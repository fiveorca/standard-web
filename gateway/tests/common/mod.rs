//! 集成测试公共设施：真实上游服务 + 进程内网关。

#![allow(dead_code)]

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use gateway::config::model::GatewayConfig;
use gateway::core::gateway::{Gateway, GatewayOptions};
use gateway::observability::metrics::Metrics;
use gateway::observability::tracing::TracingState;
use gateway::resilience::health_check::HealthRegistry;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

/// 上游统计。
#[derive(Default)]
pub struct UpstreamStats {
    pub requests: AtomicUsize,
    pub flaky_calls: AtomicUsize,
    pub paths: std::sync::Mutex<Vec<String>>,
}

pub struct EchoUpstream {
    pub addr: SocketAddr,
    pub stats: Arc<UpstreamStats>,
}

/// 启动一个真实的 HTTP/1.1 上游服务，支持：
/// - JSON 回显请求信息
/// - `/flaky` 前两次返回 503
/// - `/slow?ms=...` 延迟响应
/// - `/ws` WebSocket 回显
pub async fn start_echo_upstream() -> EchoUpstream {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let addr = listener.local_addr().unwrap();
    let stats = Arc::new(UpstreamStats::default());
    let stats_for_task = stats.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                break;
            };
            let stats = stats_for_task.clone();
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let service = service_fn(move |req| handle_upstream(req, stats.clone()));
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, service)
                    .with_upgrades()
                    .await;
            });
        }
    });

    EchoUpstream { addr, stats }
}

async fn handle_upstream(
    mut req: Request<Incoming>,
    stats: Arc<UpstreamStats>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    stats.requests.fetch_add(1, Ordering::SeqCst);
    let path = req.uri().path().to_string();
    stats.paths.lock().unwrap().push(path.clone());

    if path == "/flaky" {
        let call = stats.flaky_calls.fetch_add(1, Ordering::SeqCst);
        if call < 2 {
            return Ok(text_response(StatusCode::SERVICE_UNAVAILABLE, "try again"));
        }
        return Ok(json_response(StatusCode::OK, "{\"ok\":true}"));
    }

    if path == "/slow" {
        let ms = req
            .uri()
            .query()
            .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("ms=")))
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(500);
        tokio::time::sleep(Duration::from_millis(ms)).await;
        return Ok(text_response(StatusCode::OK, "slow done"));
    }

    let is_upgrade = req
        .headers()
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

    if is_upgrade {
        let key = req
            .headers()
            .get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let on_upgrade = hyper::upgrade::on(&mut req);
        tokio::spawn(async move {
            let Ok(upgraded) = on_upgrade.await else {
                return;
            };
            let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                TokioIo::new(upgraded),
                tokio_tungstenite::tungstenite::protocol::Role::Server,
                None,
            )
            .await;
            use futures::{SinkExt, StreamExt};
            while let Some(Ok(message)) = ws.next().await {
                let echo = match message {
                    tokio_tungstenite::tungstenite::Message::Text(text) => {
                        tokio_tungstenite::tungstenite::Message::Text(format!("echo:{text}"))
                    }
                    other => other,
                };
                if ws.send(echo).await.is_err() {
                    break;
                }
            }
        });

        let accept = tokio_tungstenite::tungstenite::handshake::derive_accept_key(key.as_bytes());
        return Ok(Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header(http::header::CONNECTION, "upgrade")
            .header(http::header::UPGRADE, "websocket")
            .header("sec-websocket-accept", accept)
            .body(Full::new(Bytes::new()))
            .unwrap());
    }

    let headers: HashMap<String, String> = req
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    let query = req.uri().query().unwrap_or_default().to_string();
    let body = req
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes())
        .unwrap_or_default();
    let payload = serde_json::json!({
        "method": "echo",
        "path": path,
        "query": query,
        "headers": headers,
        "body_len": body.len(),
        "body": String::from_utf8_lossy(&body[..body.len().min(256)]),
    });
    Ok(json_response(StatusCode::OK, &payload.to_string()))
}

fn json_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn text_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(http::header::CONTENT_TYPE, "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// 进程内网关。
pub struct TestGateway {
    pub addr: SocketAddr,
    pub gateway: Arc<Gateway>,
    pub client: reqwest::Client,
}

impl TestGateway {
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .send()
            .await
            .expect("request")
    }
}

/// 用 YAML 配置启动网关。
pub async fn start_gateway(yaml: &str) -> TestGateway {
    let config: GatewayConfig = serde_yaml::from_str(yaml).expect("parse test config");
    let metrics = Metrics::new().expect("metrics");
    let health = Arc::new(HealthRegistry::new(Vec::new()));
    let (tracing, _provider) = TracingState::init(&config.gateway.tracing);
    let gateway = Arc::new(
        Gateway::build(
            config,
            GatewayOptions::new(metrics, health, Arc::new(tracing), "test".to_string()),
        )
        .await
        .expect("build gateway"),
    );
    let router = gateway.router();
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().unwrap();
    let app = router.into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    TestGateway {
        addr,
        gateway,
        client: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap(),
    }
}

/// 生成一条最简路由配置。
pub fn route_yaml(id: &str, upstream: SocketAddr, path: &str, extra: &str) -> String {
    format!(
        r#"
routes:
  - id: {id}
    uri: http://{upstream}
    predicates:
      - Path={path}
{extra}
"#
    )
}

/// 轮询直到条件成立。
pub async fn wait_until<F>(mut check: F, timeout: Duration) -> bool
where
    F: FnMut() -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}
