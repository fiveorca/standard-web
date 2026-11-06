//! 认证与授权集成测试。

mod common;

use std::time::{SystemTime, UNIX_EPOCH};

use common::{start_echo_upstream, start_gateway};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::Value;

fn token(secret: &str, claims: Value) -> String {
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn exp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600
}

async fn setup() -> (common::TestGateway, String) {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
  authentication:
    jwt:
      algorithms: [HS256]
      secret: test-secret
      require_exp: true
    api_keys:
      - id: key-1
        key: plain-test-key
        subject: api-client
        scopes: [read]
        roles: [service]
routes:
  - id: secure
    uri: http://{}
    predicates:
      - Path=/secure/**
    authentication:
      mode: authenticated
    authorization:
      scopes: [read]
  - id: api
    uri: http://{}
    predicates:
      - Path=/api-key
    authentication:
      mode: api_key
"#,
        upstream.addr, upstream.addr
    );
    (start_gateway(&yaml).await, "test-secret".to_string())
}

#[tokio::test]
async fn missing_token_is_rejected() {
    let (gw, _) = setup().await;
    let response = gw.get("/secure/me").await;
    assert_eq!(response.status(), 401);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "UNAUTHORIZED");
}

#[tokio::test]
async fn valid_token_passes_and_injects_identity_headers() {
    let (gw, secret) = setup().await;
    let jwt = token(
        &secret,
        serde_json::json!({
            "sub": "alice",
            "exp": exp(),
            "scope": "read write",
            "roles": ["user"],
            "tenant": "acme"
        }),
    );
    let response = gw
        .client
        .get(gw.url("/secure/me"))
        .bearer_auth(jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["headers"]["x-user-id"], "alice");
    assert_eq!(body["headers"]["x-tenant-id"], "acme");
    assert_eq!(body["headers"]["x-auth-type"], "jwt");
    assert!(body["headers"]["x-user-scopes"]
        .as_str()
        .unwrap()
        .contains("read"));
}

#[tokio::test]
async fn insufficient_scope_is_forbidden() {
    let (gw, secret) = setup().await;
    let jwt = token(
        &secret,
        serde_json::json!({ "sub": "bob", "exp": exp(), "scope": "write" }),
    );
    let response = gw
        .client
        .get(gw.url("/secure/me"))
        .bearer_auth(jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
}

#[tokio::test]
async fn expired_token_is_rejected() {
    let (gw, secret) = setup().await;
    let jwt = token(
        &secret,
        serde_json::json!({ "sub": "bob", "exp": exp() - 7200, "scope": "read" }),
    );
    let response = gw
        .client
        .get(gw.url("/secure/me"))
        .bearer_auth(jwt)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn api_key_authentication() {
    let (gw, _) = setup().await;
    let ok = gw
        .client
        .get(gw.url("/api-key"))
        .header("x-api-key", "plain-test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);
    let body: Value = ok.json().await.unwrap();
    assert_eq!(body["headers"]["x-user-id"], "api-client");
    assert_eq!(body["headers"]["x-auth-type"], "api_key");

    let denied = gw
        .client
        .get(gw.url("/api-key"))
        .header("x-api-key", "wrong")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 401);
}

#[tokio::test]
async fn spoofed_identity_headers_are_replaced() {
    let (gw, secret) = setup().await;
    let jwt = token(
        &secret,
        serde_json::json!({ "sub": "alice", "exp": exp(), "scope": "read" }),
    );
    let response = gw
        .client
        .get(gw.url("/secure/me"))
        .bearer_auth(jwt)
        .header("x-user-id", "attacker")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["headers"]["x-user-id"], "alice");
}
