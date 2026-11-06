//! 反向代理核心。
//!
//! 使用 Hyper 1.x + hyper-util legacy Client 实现真正的流式反向代理：
//! - 请求 / 响应 Body 全程流式，不整包缓冲
//! - 连接池与连接复用
//! - HTTP/1.1、HTTP/2（含 h2c / gRPC）
//! - HTTPS 上游、可选 mTLS、可选关闭校验（仅显式配置时）
//! - WebSocket 升级与双向隧道
//! - Trailer 透传（依赖 hyper 原生的 frame 转发）
//! - 幂等重试与指数退避

use std::collections::hash_map::DefaultHasher;
use std::error::Error as StdError;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use http::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, HOST, TE, TRAILER, UPGRADE};
use http::{Method, Request, Response, StatusCode, Version};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use hyper::upgrade::OnUpgrade;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::copy_bidirectional;
use tokio::time::Sleep;

use crate::config::model::{LbStrategy, RetryConfig, UpstreamProtocol, UpstreamTlsConfig};
use crate::core::upstream::{InFlightGuard, Target, UpstreamRegistry};
use crate::error::{GatewayError, Result};
use crate::middleware::security::UpstreamGuard;
use crate::resilience::retry::{backoff_delay, is_retryable_request, should_retry_status};
use crate::resilience::timeout::EffectiveTimeouts;
use crate::utils::http::{apply_forwarding_headers, is_websocket_upgrade};

pub type BoxError = Box<dyn StdError + Send + Sync>;

/// 代理请求体。
pub enum ProxyBody {
    Empty,
    Bytes(Bytes),
    Stream(axum::body::Body),
}

impl ProxyBody {
    pub fn empty() -> Self {
        ProxyBody::Empty
    }

    pub fn bytes(bytes: Bytes) -> Self {
        ProxyBody::Bytes(bytes)
    }

    pub fn stream(body: axum::body::Body) -> Self {
        ProxyBody::Stream(body)
    }

    pub fn is_empty(&self) -> bool {
        match self {
            ProxyBody::Empty => true,
            ProxyBody::Bytes(bytes) => bytes.is_empty(),
            ProxyBody::Stream(_) => false,
        }
    }

    /// 仅当 Body 已在内存中时才能克隆（用于重试）。
    pub fn try_clone(&self) -> Option<ProxyBody> {
        match self {
            ProxyBody::Empty => Some(ProxyBody::Empty),
            ProxyBody::Bytes(bytes) => Some(ProxyBody::Bytes(bytes.clone())),
            ProxyBody::Stream(_) => None,
        }
    }

    pub fn content_length(&self) -> Option<u64> {
        match self {
            ProxyBody::Empty => Some(0),
            ProxyBody::Bytes(bytes) => Some(bytes.len() as u64),
            ProxyBody::Stream(_) => None,
        }
    }
}

impl HttpBody for ProxyBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        match self.get_mut() {
            ProxyBody::Empty => Poll::Ready(None),
            ProxyBody::Bytes(bytes) => {
                if bytes.is_empty() {
                    Poll::Ready(None)
                } else {
                    let data = std::mem::take(bytes);
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
            }
            ProxyBody::Stream(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|opt| opt.map(|res| res.map_err(|e| Box::new(e) as BoxError))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ProxyBody::Empty => true,
            ProxyBody::Bytes(bytes) => bytes.is_empty(),
            ProxyBody::Stream(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            ProxyBody::Empty => SizeHint::with_exact(0),
            ProxyBody::Bytes(bytes) => SizeHint::with_exact(bytes.len() as u64),
            ProxyBody::Stream(body) => body.size_hint(),
        }
    }
}

/// 代理请求。
pub struct ProxyRequest {
    pub method: Method,
    pub headers: HeaderMap,
    pub path: String,
    pub query: Option<String>,
    pub body: ProxyBody,
    pub client_ip: Option<IpAddr>,
    pub peer_ip: Option<IpAddr>,
    pub downstream_scheme: String,
    pub original_host: Option<String>,
    pub preserve_host: bool,
    pub upgrade: Option<OnUpgrade>,
    pub websocket: bool,
    pub grpc: bool,
}

impl ProxyRequest {
    fn can_retry(&self) -> bool {
        !self.websocket && self.upgrade.is_none() && self.body.try_clone().is_some()
    }

    fn is_websocket_candidate(&self) -> bool {
        self.websocket && (self.upgrade.is_some() || is_websocket_upgrade(&self.headers))
    }
}

/// 路由级代理选项。
#[derive(Clone)]
pub struct ProxyOptions {
    pub strategy: Option<LbStrategy>,
    pub protocol: UpstreamProtocol,
    pub tls: UpstreamTlsConfig,
    pub timeouts: EffectiveTimeouts,
    pub retry: Option<RetryConfig>,
    pub websocket: bool,
}

/// 代理结果。
pub struct ProxyResponse {
    pub response: Response<axum::body::Body>,
    pub status: StatusCode,
    pub service: Option<String>,
    pub upstream: String,
    pub attempts: u32,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct ClientKey {
    protocol: UpstreamProtocol,
    verify: bool,
    ca_cert: Option<String>,
    client_cert: Option<String>,
    client_key: Option<String>,
    connect_timeout_ms: u64,
    http2_only: bool,
}

type ProxyClient = Client<HttpsConnector<HttpConnector>, ProxyBody>;

/// 代理服务。
pub struct ProxyService {
    clients: DashMap<ClientKey, ProxyClient>,
    registry: Arc<UpstreamRegistry>,
    global_tls: UpstreamTlsConfig,
    guard: UpstreamGuard,
    pool_idle_timeout: Duration,
    pool_max_idle_per_host: usize,
}

impl ProxyService {
    pub fn new(
        registry: Arc<UpstreamRegistry>,
        global_tls: UpstreamTlsConfig,
        guard: UpstreamGuard,
        pool_idle_timeout: Duration,
        pool_max_idle_per_host: usize,
    ) -> Self {
        Self {
            clients: DashMap::new(),
            registry,
            global_tls,
            guard,
            pool_idle_timeout,
            pool_max_idle_per_host,
        }
    }

    fn client_for(&self, key: &ClientKey) -> Result<ProxyClient> {
        if let Some(client) = self.clients.get(key) {
            return Ok(client.clone());
        }
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(Duration::from_millis(key.connect_timeout_ms.max(1))));

        let connector = build_https_connector(
            key.verify,
            key.ca_cert.as_deref(),
            key.client_cert.as_deref(),
            key.client_key.as_deref(),
            key.protocol != UpstreamProtocol::Http1,
        )
        .map_err(|e| GatewayError::Config(format!("upstream TLS configuration error: {e}")))?;
        let connector = hyper_rustls::HttpsConnector::from((http, connector));

        let mut builder = Client::builder(TokioExecutor::new());
        builder
            .pool_idle_timeout(self.pool_idle_timeout)
            .pool_max_idle_per_host(self.pool_max_idle_per_host)
            .pool_timer(TokioTimer::new())
            .http1_title_case_headers(false)
            .http2_keep_alive_interval(Some(Duration::from_secs(30)))
            .http2_keep_alive_timeout(Duration::from_secs(10));
        if key.http2_only {
            builder.http2_only(true);
        }
        let client = builder.build(connector);
        self.clients.insert(key.clone(), client.clone());
        Ok(client)
    }

    fn key_for(&self, options: &ProxyOptions, http2_only: bool) -> ClientKey {
        let tls = merge_tls(&self.global_tls, &options.tls);
        ClientKey {
            protocol: options.protocol,
            verify: tls.verify,
            ca_cert: tls.ca_cert_path.clone(),
            client_cert: tls.client_cert_path.clone(),
            client_key: tls.client_key_path.clone(),
            connect_timeout_ms: options.timeouts.connect.as_millis() as u64,
            http2_only,
        }
    }

    /// 执行代理，包含幂等重试。
    pub async fn execute(
        &self,
        request: &mut ProxyRequest,
        uri: &str,
        options: &ProxyOptions,
    ) -> Result<ProxyResponse> {
        let retry = options.retry.as_ref().filter(|r| {
            r.enabled
                && is_retryable_request(&request.method, r)
                && request.can_retry()
                && !request.is_websocket_candidate()
        });
        let max_attempts = retry.map(|r| r.max_attempts.max(1)).unwrap_or(1);

        let mut last_error: Option<GatewayError> = None;
        for attempt in 1..=max_attempts {
            let target = self
                .registry
                .resolve(uri, options.strategy)
                .await
                .map_err(|e| last_error.take().unwrap_or(e))?;
            self.guard.check(&target.host, target.port).await?;

            let body = if attempt == max_attempts {
                std::mem::replace(&mut request.body, ProxyBody::Empty)
            } else {
                request
                    .body
                    .try_clone()
                    .ok_or_else(|| GatewayError::Internal("request body is not retryable".into()))?
            };

            match self
                .send_once(request, body, &target, options, attempt)
                .await
            {
                Ok(mut outcome) => {
                    let retryable_status = retry
                        .map(|r| should_retry_status(outcome.status.as_u16(), r))
                        .unwrap_or(false);
                    if retryable_status && attempt < max_attempts {
                        self.registry.record_result(&target, false);
                        let status = outcome.status.as_u16();
                        drop(outcome);
                        let delay = backoff_delay(attempt, retry.expect("retry config"));
                        tracing::debug!(
                            attempt,
                            delay_ms = delay.as_millis(),
                            status,
                            "retrying upstream request after retryable status"
                        );
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    let success = !outcome.status.is_server_error();
                    self.registry.record_result(&target, success);
                    outcome.attempts = attempt;
                    return Ok(outcome);
                }
                Err(err) => {
                    self.registry.record_result(&target, false);
                    let retryable = retry
                        .map(|r| {
                            (err.is_upstream_failure() && r.retry_on_connect_error)
                                || (matches!(err, GatewayError::Timeout) && r.retry_on_timeout)
                        })
                        .unwrap_or(false);
                    if retryable && attempt < max_attempts {
                        let delay = backoff_delay(attempt, retry.expect("retry config"));
                        tracing::debug!(
                            attempt,
                            delay_ms = delay.as_millis(),
                            error = %err,
                            "retrying upstream request after error"
                        );
                        last_error = Some(err);
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                    return Err(err);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| {
            GatewayError::Upstream("upstream request exhausted retries".to_string())
        }))
    }

    async fn send_once(
        &self,
        request: &mut ProxyRequest,
        body: ProxyBody,
        target: &Target,
        options: &ProxyOptions,
        _attempt: u32,
    ) -> Result<ProxyResponse> {
        let websocket = request.is_websocket_candidate();
        let grpc = request.grpc || is_grpc_request(&request.headers);
        let http2_only = matches!(options.protocol, UpstreamProtocol::Http2) || grpc;
        let key = self.key_for(options, http2_only);
        let client = self.client_for(&key)?;

        let path = target.join_path(&request.path);
        let query = request
            .query
            .as_ref()
            .map(|q| format!("?{q}"))
            .unwrap_or_default();
        let uri_string = format!("{}://{}{}{}", target.scheme, target.authority, path, query);
        let uri: http::Uri = uri_string
            .parse()
            .map_err(|e| GatewayError::Internal(format!("invalid upstream uri: {e}")))?;

        let mut headers = request.headers.clone();
        if websocket {
            clean_upgrade_headers(&mut headers);
        } else {
            remove_hop_by_hop(&mut headers);
        }

        // Host / :authority
        headers.remove(HOST);
        let host_value = if request.preserve_host {
            request
                .original_host
                .clone()
                .unwrap_or_else(|| target.authority.clone())
        } else {
            target.authority.clone()
        };
        if let Ok(value) = HeaderValue::from_str(&host_value) {
            headers.insert(HOST, value);
        }

        apply_forwarding_headers(
            &mut headers,
            request.client_ip,
            request.original_host.as_deref(),
            &request.downstream_scheme,
            request.peer_ip,
        );

        let version = if http2_only {
            Version::HTTP_2
        } else {
            Version::HTTP_11
        };
        let mut builder = Request::builder()
            .method(request.method.clone())
            .uri(uri)
            .version(version);
        if let Some(headers_mut) = builder.headers_mut() {
            *headers_mut = headers;
        }
        let upstream_request = builder.body(body).map_err(|e| {
            GatewayError::Internal(format!("failed to build upstream request: {e}"))
        })?;

        let guard: Option<InFlightGuard> = target.instance.as_ref().map(|i| i.acquire());

        let total = options.timeouts.total;
        let started = std::time::Instant::now();
        let mut timeout = options.timeouts.response;
        if total.as_millis() > 0 {
            timeout = timeout.min(total);
        }
        let response = tokio::time::timeout(timeout, client.request(upstream_request))
            .await
            .map_err(|_| GatewayError::Timeout)?
            .map_err(map_client_error)?;

        let status = response.status();

        // WebSocket：上游返回 101 时，建立客户端 ↔ 上游的双向隧道。
        if websocket && status == StatusCode::SWITCHING_PROTOCOLS {
            let mut response = response;
            let upstream_upgrade = hyper::upgrade::on(&mut response);
            let (parts, _incoming) = response.into_parts();
            match request.upgrade.take() {
                Some(client_upgrade) => {
                    tokio::spawn(async move {
                        match tokio::join!(client_upgrade, upstream_upgrade) {
                            (Ok(client_io), Ok(upstream_io)) => {
                                let mut client_io = TokioIo::new(client_io);
                                let mut upstream_io = TokioIo::new(upstream_io);
                                match copy_bidirectional(&mut client_io, &mut upstream_io).await {
                                    Ok((from_client, from_upstream)) => tracing::debug!(
                                        from_client,
                                        from_upstream,
                                        "websocket tunnel closed"
                                    ),
                                    Err(err) => {
                                        tracing::debug!(error = %err, "websocket tunnel error")
                                    }
                                }
                            }
                            _ => tracing::warn!("websocket upgrade did not complete"),
                        }
                        drop(guard);
                    });
                }
                None => {
                    tracing::warn!("upstream returned 101 but client upgrade handle is missing");
                    drop(guard);
                }
            }
            return Ok(ProxyResponse {
                status,
                response: Response::from_parts(parts, axum::body::Body::empty()),
                service: target.service.clone(),
                upstream: target.authority.clone(),
                attempts: 1,
            });
        }

        let (mut parts, incoming) = response.into_parts();
        parts.headers = sanitize_response_headers(parts.headers);

        let remaining = total.saturating_sub(started.elapsed());
        let deadline = if !request.websocket && total.as_millis() > 0 {
            Some(Box::pin(tokio::time::sleep(remaining)))
        } else {
            None
        };

        let timed = TimedResponseBody::new(axum::body::Body::new(incoming), deadline, guard);
        let response = Response::from_parts(parts, axum::body::Body::new(timed));

        Ok(ProxyResponse {
            status,
            response,
            service: target.service.clone(),
            upstream: target.authority.clone(),
            attempts: 1,
        })
    }
}

fn map_client_error(err: hyper_util::client::legacy::Error) -> GatewayError {
    let text = err.to_string();
    if text.contains("length limit") || text.contains("payload") {
        return GatewayError::PayloadTooLarge;
    }
    if err.is_connect() {
        GatewayError::UpstreamConnect(format!("failed to connect upstream: {err}"))
    } else {
        GatewayError::Upstream(format!("upstream request failed: {err}"))
    }
}

fn is_grpc_request(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("application/grpc"))
        .unwrap_or(false)
}

fn merge_tls(global: &UpstreamTlsConfig, route: &UpstreamTlsConfig) -> UpstreamTlsConfig {
    UpstreamTlsConfig {
        verify: route.verify && global.verify,
        ca_cert_path: route
            .ca_cert_path
            .clone()
            .or_else(|| global.ca_cert_path.clone()),
        client_cert_path: route
            .client_cert_path
            .clone()
            .or_else(|| global.client_cert_path.clone()),
        client_key_path: route
            .client_key_path
            .clone()
            .or_else(|| global.client_key_path.clone()),
        server_name: route
            .server_name
            .clone()
            .or_else(|| global.server_name.clone()),
    }
}

fn remove_hop_by_hop(headers: &mut HeaderMap) {
    crate::utils::http::remove_hop_by_hop(headers);
}

fn clean_upgrade_headers(headers: &mut HeaderMap) {
    let extra: Vec<HeaderName> = headers
        .get(CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .filter_map(|token| HeaderName::from_bytes(token.trim().as_bytes()).ok())
                .filter(|name| name != UPGRADE)
                .collect()
        })
        .unwrap_or_default();
    for name in extra {
        if !is_upgrade_header(&name) {
            headers.remove(&name);
        }
    }
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
    headers.remove("proxy-authorization");
    headers.remove("proxy-authenticate");
    headers.remove(TE);
    headers.remove(TRAILER);
    headers.remove("transfer-encoding");
}

fn is_upgrade_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "upgrade"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "sec-websocket-protocol"
            | "sec-websocket-extensions"
    )
}

fn sanitize_response_headers(mut headers: HeaderMap) -> HeaderMap {
    crate::utils::http::remove_hop_by_hop(&mut headers);
    headers
}

/// 带总超时与在途守卫的响应 Body。
pub struct TimedResponseBody {
    inner: axum::body::Body,
    deadline: Option<Pin<Box<Sleep>>>,
    guard: Option<InFlightGuard>,
}

impl TimedResponseBody {
    pub fn new(
        inner: axum::body::Body,
        deadline: Option<Pin<Box<Sleep>>>,
        guard: Option<InFlightGuard>,
    ) -> Self {
        Self {
            inner,
            deadline,
            guard,
        }
    }
}

impl HttpBody for TimedResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, BoxError>>> {
        if let Some(deadline) = self.deadline.as_mut() {
            if deadline.as_mut().poll(cx).is_ready() {
                self.deadline = None;
                return Poll::Ready(Some(Err(Box::new(ResponseTimeout))));
            }
        }
        Pin::new(&mut self.inner)
            .poll_frame(cx)
            .map(|opt| opt.map(|res| res.map_err(|e| Box::new(e) as BoxError)))
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for TimedResponseBody {
    fn drop(&mut self) {
        // guard 在此释放，确保流式响应结束后在途计数正确。
        let _ = self.guard.take();
    }
}

#[derive(Debug)]
struct ResponseTimeout;

impl std::fmt::Display for ResponseTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "upstream response exceeded total timeout")
    }
}

impl StdError for ResponseTimeout {}

fn load_certs(
    path: &str,
) -> std::result::Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read `{path}`: {e}"))?;
    let mut reader = std::io::BufReader::new(std::io::Cursor::new(data));
    rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| format!("invalid PEM certificates in `{path}`: {e}"))
}

fn load_private_key(
    path: &str,
) -> std::result::Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    let data = std::fs::read(path).map_err(|e| format!("cannot read `{path}`: {e}"))?;
    let mut reader = std::io::BufReader::new(std::io::Cursor::new(data));
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("invalid PEM private key in `{path}`: {e}"))?
        .ok_or_else(|| format!("no private key found in `{path}`"))
}

fn build_https_connector(
    verify: bool,
    ca_cert: Option<&str>,
    client_cert: Option<&str>,
    client_key: Option<&str>,
    alpn_h2: bool,
) -> std::result::Result<rustls::ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS protocol version configuration failed: {e}"))?;

    let builder = if verify {
        let mut roots = RootCertStore::empty();
        match ca_cert {
            Some(path) => {
                let certs = load_certs(path)?;
                let (added, ignored) = roots.add_parsable_certificates(certs);
                if added == 0 {
                    return Err(format!(
                        "no valid CA certificate loaded from `{path}` (ignored: {ignored})"
                    ));
                }
            }
            None => {
                let result = rustls_native_certs::load_native_certs();
                for cert in result.certs {
                    let _ = roots.add(cert);
                }
            }
        }
        builder.with_root_certificates(roots)
    } else {
        tracing::warn!("upstream TLS certificate verification is disabled");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification(provider)))
    };

    let mut config = match (client_cert, client_key) {
        (Some(cert), Some(key)) => {
            let certs = load_certs(cert)?;
            let key = load_private_key(key)?;
            builder
                .with_client_auth_cert(certs, key)
                .map_err(|e| format!("invalid upstream client certificate: {e}"))?
        }
        _ => builder.with_no_client_auth(),
    };
    config.alpn_protocols = if alpn_h2 {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    } else {
        vec![b"http/1.1".to_vec()]
    };
    Ok(config)
}

#[derive(Debug)]
struct NoCertificateVerification(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// 计算一个稳定的短哈希（供调试 / 指纹使用）。
pub fn fingerprint<T: Hash>(value: &T) -> String {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// 拼接上游路径，供测试复用。
pub fn join_uri(scheme: &str, authority: &str, path: &str, query: Option<&str>) -> String {
    match query {
        Some(query) if !query.is_empty() => format!("{scheme}://{authority}{path}?{query}"),
        _ => format!("{scheme}://{authority}{path}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::http::host_without_port;

    #[test]
    fn hop_by_hop_is_removed_from_upstream_request() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "keep-alive".parse().unwrap());
        headers.insert("proxy-connection", "keep-alive".parse().unwrap());
        headers.insert("x-keep", "1".parse().unwrap());
        remove_hop_by_hop(&mut headers);
        assert!(!headers.contains_key(CONNECTION));
        assert!(headers.contains_key("x-keep"));
    }

    #[test]
    fn websocket_upgrade_headers_are_preserved() {
        let mut headers = HeaderMap::new();
        headers.insert(CONNECTION, "Upgrade".parse().unwrap());
        headers.insert(UPGRADE, "websocket".parse().unwrap());
        headers.insert("sec-websocket-key", "abc".parse().unwrap());
        headers.insert("keep-alive", "timeout=5".parse().unwrap());
        clean_upgrade_headers(&mut headers);
        assert!(headers.contains_key(UPGRADE));
        assert!(headers.contains_key("sec-websocket-key"));
        assert!(!headers.contains_key("keep-alive"));
    }

    #[test]
    fn host_without_port_helper() {
        assert_eq!(host_without_port("example.com:8080"), "example.com");
    }

    #[test]
    fn grpc_detection() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::CONTENT_TYPE,
            "application/grpc+proto".parse().unwrap(),
        );
        assert!(is_grpc_request(&headers));
    }
}
