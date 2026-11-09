//! 管理 API 集成测试。

mod common;

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::Router;
use common::{start_echo_upstream, start_gateway, TestGateway};
use serde_json::{json, Value};

async fn start_admin(gw: &TestGateway) -> (SocketAddr, reqwest::Client) {
    let root = std::env::temp_dir().join(format!("gateway-admin-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let state = gateway::admin::AdminState::new(
        gw.gateway.state.clone(),
        gw.gateway.route_table.clone(),
        gw.gateway.upstreams.clone(),
        PathBuf::from(&root),
        Some("test".to_string()),
        None,
        "test-node".to_string(),
    );
    let router: Router = gateway::admin::router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = router.into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, reqwest::Client::new())
}

fn config(upstream: SocketAddr) -> String {
    format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
  admin:
    enabled: true
    auth:
      mode: none
    persistence:
      enabled: true
routes:
  - id: alpha
    uri: http://{}
    predicates:
      - Path=/alpha
  - id: beta
    uri: http://{}
    predicates:
      - Path=/beta
"#,
        upstream, upstream
    )
}

#[tokio::test]
async fn admin_lists_and_toggles_routes() {
    let upstream = start_echo_upstream().await;
    let gw = start_gateway(&config(upstream.addr)).await;
    let (admin, client) = start_admin(&gw).await;

    let response = client
        .get(format!("http://{admin}/admin/v1/routes"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["total"], 2);
    assert_eq!(body["data"]["routes"].as_array().unwrap().len(), 2);

    let disabled = client
        .post(format!("http://{admin}/admin/v1/routes/alpha/disable"))
        .send()
        .await
        .unwrap();
    assert_eq!(disabled.status(), 200);

    assert_eq!(gw.get("/alpha").await.status(), 404);
    assert_eq!(gw.get("/beta").await.status(), 200);

    let enabled = client
        .post(format!("http://{admin}/admin/v1/routes/alpha/enable"))
        .send()
        .await
        .unwrap();
    assert_eq!(enabled.status(), 200);
    assert_eq!(gw.get("/alpha").await.status(), 200);
}

#[tokio::test]
async fn admin_creates_route_atomically() {
    let upstream = start_echo_upstream().await;
    let gw = start_gateway(&config(upstream.addr)).await;
    let (admin, client) = start_admin(&gw).await;

    let response = client
        .post(format!("http://{admin}/admin/v1/routes"))
        .json(&json!({
            "id": "gamma",
            "uri": format!("http://{}", upstream.addr),
            "predicates": ["Path=/gamma"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["data"]["version"], 1);

    assert_eq!(gw.get("/gamma").await.status(), 200);

    let duplicate = client
        .post(format!("http://{admin}/admin/v1/routes"))
        .json(&json!({
            "id": "gamma",
            "uri": format!("http://{}", upstream.addr),
            "predicates": ["Path=/gamma"]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), 409);
}

#[tokio::test]
async fn admin_config_status_and_summaries() {
    let upstream = start_echo_upstream().await;
    let gw = start_gateway(&config(upstream.addr)).await;
    let (admin, client) = start_admin(&gw).await;

    let status: Value = client
        .get(format!("http://{admin}/admin/v1/config/status"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(status["data"]["routes"], 2);
    assert_eq!(status["data"]["node_id"], "test-node");

    let summary: Value = client
        .get(format!("http://{admin}/admin/v1/metrics/summary"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(summary["success"], true);

    let services: Value = client
        .get(format!("http://{admin}/admin/v1/services"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(services["success"], true);

    let health = client
        .get(format!("http://{admin}/health/live"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status(), 200);
}

#[tokio::test]
async fn admin_requires_api_key_when_configured() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
  admin:
    enabled: true
    auth:
      mode: api_key
      header: x-admin-key
      api_keys: [secret-key]
routes:
  - id: alpha
    uri: http://{}
    predicates:
      - Path=/alpha
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;
    let (admin, client) = start_admin(&gw).await;

    let denied = client
        .get(format!("http://{admin}/admin/v1/routes"))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);

    let allowed = client
        .get(format!("http://{admin}/admin/v1/routes"))
        .header("x-admin-key", "secret-key")
        .send()
        .await
        .unwrap();
    assert_eq!(allowed.status(), 200);
}
