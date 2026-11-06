//! HTTP / HTTPS 监听与优雅关闭。

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{anyhow, Context as _};
use axum::Router;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use tokio::sync::watch;
use tower::Service;

use crate::config::model::TlsConfig;
use crate::observability::metrics::Metrics;

/// 安装 rustls 加密提供者（进程内只能安装一次）。
pub fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// 构建服务端 TLS 配置。
pub fn build_server_tls(config: &TlsConfig) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let cert_path = config
        .cert_path
        .as_deref()
        .ok_or_else(|| anyhow!("server.tls.cert_path is required when TLS is enabled"))?;
    let key_path = config
        .key_path
        .as_deref()
        .ok_or_else(|| anyhow!("server.tls.key_path is required when TLS is enabled"))?;
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions: &[&rustls::SupportedProtocolVersion] = if config.min_version.trim() == "1.3" {
        &[&rustls::version::TLS13]
    } else {
        &[&rustls::version::TLS13, &rustls::version::TLS12]
    };
    let builder = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| anyhow!("invalid TLS protocol versions: {e}"))?;

    let builder = match &config.client_ca_path {
        Some(ca_path) => {
            let mut roots = RootCertStore::empty();
            for cert in load_certs(ca_path)? {
                roots
                    .add(cert)
                    .map_err(|e| anyhow!("invalid client CA certificate: {e}"))?;
            }
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| anyhow!("failed to build client certificate verifier: {e}"))?;
            builder.with_client_cert_verifier(verifier)
        }
        None => builder.with_no_client_auth(),
    };

    let mut server_config = builder
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("invalid server certificate / key: {e}"))?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(server_config))
}

fn load_certs(path: &str) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let data = std::fs::read(path).with_context(|| format!("cannot read `{path}`"))?;
    let mut reader = std::io::BufReader::new(std::io::Cursor::new(data));
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("invalid PEM certificates in `{path}`"))
}

fn load_private_key(path: &str) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let data = std::fs::read(path).with_context(|| format!("cannot read `{path}`"))?;
    let mut reader = std::io::BufReader::new(std::io::Cursor::new(data));
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("invalid PEM private key in `{path}`"))?
        .ok_or_else(|| anyhow!("no private key found in `{path}`"))
}

/// 监听并服务，直到收到关闭信号。
pub async fn serve(
    addr: SocketAddr,
    router: Router,
    tls: Option<Arc<rustls::ServerConfig>>,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
    graceful: Duration,
) -> anyhow::Result<()> {
    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        if shutdown.changed().await.is_ok() && *shutdown.borrow() {
            tracing::info!(%addr, "graceful shutdown initiated");
            shutdown_handle.graceful_shutdown(Some(graceful));
        }
    });

    let make_service = CountingMakeService::new(
        router.into_make_service_with_connect_info::<SocketAddr>(),
        metrics,
    );

    match tls {
        Some(config) => {
            let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(config);
            axum_server::bind_rustls(addr, rustls_config)
                .handle(handle)
                .serve(make_service)
                .await
                .with_context(|| format!("HTTPS server on {addr} failed"))?;
        }
        None => {
            axum_server::bind(addr)
                .handle(handle)
                .serve(make_service)
                .await
                .with_context(|| format!("HTTP server on {addr} failed"))?;
        }
    }
    Ok(())
}

/// 包装 MakeService，统计当前活跃连接数。
#[derive(Clone)]
pub struct CountingMakeService<M> {
    inner: M,
    metrics: Arc<Metrics>,
}

impl<M> CountingMakeService<M> {
    pub fn new(inner: M, metrics: Arc<Metrics>) -> Self {
        Self { inner, metrics }
    }
}

impl<T, M> Service<T> for CountingMakeService<M>
where
    M: Service<T>,
{
    type Response = CountingService<M::Response>;
    type Error = M::Error;
    type Future = CountingFuture<M::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: T) -> Self::Future {
        self.metrics.add_active_connections(1);
        let guard = Arc::new(ConnectionGuard {
            metrics: self.metrics.clone(),
        });
        CountingFuture {
            future: Box::pin(self.inner.call(req)),
            guard: Some(guard),
        }
    }
}

pub struct CountingFuture<F> {
    future: Pin<Box<F>>,
    guard: Option<Arc<ConnectionGuard>>,
}

impl<F, T, E> std::future::Future for CountingFuture<F>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    type Output = Result<CountingService<T>, E>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let guard = self.guard.take().expect("future polled after completion");
        match self.future.as_mut().poll(cx) {
            Poll::Ready(Ok(service)) => Poll::Ready(Ok(CountingService {
                inner: service,
                guard,
            })),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                self.guard = Some(guard);
                Poll::Pending
            }
        }
    }
}

#[derive(Clone)]
pub struct CountingService<S> {
    inner: S,
    #[allow(dead_code)]
    guard: Arc<ConnectionGuard>,
}

struct ConnectionGuard {
    metrics: Arc<Metrics>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.metrics.add_active_connections(-1);
    }
}

impl<S, ReqBody, ResBody> Service<axum::http::Request<ReqBody>> for CountingService<S>
where
    S: Service<axum::http::Request<ReqBody>, Response = axum::http::Response<ResBody>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::http::Request<ReqBody>) -> Self::Future {
        self.inner.call(req)
    }
}
