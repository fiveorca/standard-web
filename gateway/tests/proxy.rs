//! 代理行为集成测试：限流、缓存、重试、超时、大请求体、WebSocket、TLS。

mod common;

use std::time::Duration;

use axum::routing::get;
use axum::Router;
use common::{start_echo_upstream, start_gateway};
use futures::{SinkExt, StreamExt};
use gateway::observability::metrics::Metrics;
use gateway::transport::{build_server_tls, install_crypto_provider, serve};
use serde_json::Value;
use tokio::sync::watch;

#[tokio::test]
async fn rate_limit_returns_429_with_headers() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
routes:
  - id: limited
    uri: http://{}
    predicates:
      - Path=/limited
    rate_limit:
      enabled: true
      key_type: ip
      quota:
        requests_per_second: 1
        burst_capacity: 2
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;

    assert_eq!(gw.get("/limited").await.status(), 200);
    assert_eq!(gw.get("/limited").await.status(), 200);
    let third = gw.get("/limited").await;
    assert_eq!(third.status(), 429);
    assert!(third.headers().get("retry-after").is_some());
    assert_eq!(third.headers().get("x-ratelimit-limit").unwrap(), "2");
    let body: Value = third.json().await.unwrap();
    assert_eq!(body["error"]["code"], "RATE_LIMITED");
}

#[tokio::test]
async fn response_cache_serves_second_request_from_cache() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
routes:
  - id: cached
    uri: http://{}
    predicates:
      - Path=/cache
    cache:
      enabled: true
      ttl: 60s
      cacheable_status: [200]
      respect_cache_control: false
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;

    let first = gw.get("/cache").await;
    assert_eq!(first.status(), 200);
    let second = gw.get("/cache").await;
    assert_eq!(second.status(), 200);
    assert_eq!(second.headers().get("x-cache").unwrap(), "HIT");
    assert!(second.headers().get("age").is_some());
    assert_eq!(
        upstream
            .stats
            .requests
            .load(std::sync::atomic::Ordering::SeqCst),
        1
    );
}

#[tokio::test]
async fn retries_on_retryable_status() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
routes:
  - id: flaky
    uri: http://{}
    predicates:
      - Path=/flaky
    retry:
      enabled: true
      max_attempts: 3
      retry_on_connect_error: true
      retry_statuses: [503]
      backoff_initial: 10ms
      backoff_max: 50ms
      backoff_multiplier: 2.0
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;
    let response = gw.get("/flaky").await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        upstream
            .stats
            .flaky_calls
            .load(std::sync::atomic::Ordering::SeqCst),
        3
    );
}

#[tokio::test]
async fn total_timeout_returns_gateway_timeout() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
routes:
  - id: slow
    uri: http://{}
    predicates:
      - Path=/slow
    timeout:
      total: 100ms
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;
    let response = gw.get("/slow?ms=1000").await;
    assert_eq!(response.status(), 504);
}

#[tokio::test]
async fn large_request_body_is_streamed() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
  server:
    limits:
      max_body_size: 16777216
routes:
  - id: upload
    uri: http://{}
    predicates:
      - Path=/upload
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;
    let payload = vec![b'x'; 2 * 1024 * 1024];
    let response = gw
        .client
        .post(gw.url("/upload"))
        .body(payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["body_len"], 2 * 1024 * 1024);
}

#[tokio::test]
async fn websocket_is_tunnelled_both_directions() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
routes:
  - id: ws
    uri: http://{}
    predicates:
      - Path=/ws/**
    filters:
      - StripPrefix=1
    upstream:
      websocket: true
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;
    let (mut socket, response) =
        tokio_tungstenite::connect_async(format!("ws://{}/ws/echo", gw.addr))
            .await
            .expect("websocket handshake");
    assert_eq!(response.status(), 101);
    socket
        .send(tokio_tungstenite::tungstenite::Message::Text(
            "hello".into(),
        ))
        .await
        .unwrap();
    let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("websocket message timeout")
        .expect("stream ended")
        .expect("websocket error");
    assert_eq!(message.into_text().unwrap(), "echo:hello");
    let _ = socket.close(None).await;
}

#[tokio::test]
async fn https_listener_serves_requests() {
    install_crypto_provider();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let dir = std::env::temp_dir().join(format!("gateway-tls-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("tls.crt");
    let key_path = dir.join("tls.key");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let tls = gateway::config::model::TlsConfig {
        enabled: true,
        cert_path: Some(cert_path.to_string_lossy().to_string()),
        key_path: Some(key_path.to_string_lossy().to_string()),
        client_ca_path: None,
        min_version: "1.2".to_string(),
    };
    let server_config = build_server_tls(&tls).expect("server tls");

    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = probe.local_addr().unwrap();
    drop(probe);

    let metrics = Metrics::new().unwrap();
    let (_tx, rx) = watch::channel(false);
    let router = Router::new().route("/", get(|| async { "secure" }));
    tokio::spawn(serve(
        addr,
        router,
        Some(server_config),
        metrics,
        rx,
        Duration::from_secs(5),
    ));
    tokio::time::sleep(Duration::from_millis(150)).await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let response = client
        .get(format!("https://localhost:{}/", addr.port()))
        .send()
        .await
        .expect("https request");
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "secure");
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn metrics_endpoint_exposes_prometheus_text() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics:
    enabled: true
    path: /metrics
routes:
  - id: m
    uri: http://{}
    predicates:
      - Path=/m
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;
    gw.get("/m").await;
    let response = gw.get("/metrics").await;
    assert_eq!(response.status(), 200);
    let text = response.text().await.unwrap();
    assert!(text.contains("gateway_requests_total"));
}
