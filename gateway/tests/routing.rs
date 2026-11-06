//! 路由、谓词与过滤器集成测试。

mod common;

use common::{route_yaml, start_echo_upstream, start_gateway};
use serde_json::Value;

#[tokio::test]
async fn path_rewrite_and_forwarded_headers() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
routes:
  - id: echo
    uri: http://{}
    predicates:
      - Path=/api/**
      - Method=GET,POST
    filters:
      - StripPrefix=1
      - AddRequestHeader=X-Gateway-Route,echo
      - AddResponseHeader=X-Served-By,gateway
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;

    let response = gw
        .client
        .get(gw.url("/api/users/42?a=1&b=2"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get("x-served-by").unwrap(), "gateway");
    assert!(response.headers().get("x-request-id").is_some());

    let body: Value = response.json().await.unwrap();
    assert_eq!(body["path"], "/users/42");
    assert_eq!(body["query"], "a=1&b=2");
    assert_eq!(body["headers"]["x-gateway-route"], "echo");
    assert_eq!(body["headers"]["x-forwarded-proto"], "http");
    assert!(body["headers"]["x-forwarded-for"].is_string());
    assert!(body["headers"]["x-request-id"].is_string());
    // 未配置 PreserveHostHeader 时，Host 使用上游地址。
    assert_eq!(body["headers"]["host"], format!("{}", upstream.addr));
}

#[tokio::test]
async fn unmatched_route_returns_404() {
    let upstream = start_echo_upstream().await;
    let gw = start_gateway(&route_yaml("only", upstream.addr, "/only/**", "")).await;
    let response = gw.get("/nope").await;
    assert_eq!(response.status(), 404);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["success"], false);
    assert_eq!(body["error"]["code"], "ROUTE_NOT_FOUND");
}

#[tokio::test]
async fn method_predicate_is_enforced() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
routes:
  - id: get-only
    uri: http://{}
    predicates:
      - Path=/read
      - Method=GET
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;
    assert_eq!(gw.get("/read").await.status(), 200);
    assert_eq!(
        gw.client
            .post(gw.url("/read"))
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
}

#[tokio::test]
async fn host_and_header_predicates() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
routes:
  - id: headers
    uri: http://{}
    predicates:
      - Path=/h
      - Header=X-Tenant,acme*
      - Query=debug,true
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;
    let ok = gw
        .client
        .get(gw.url("/h?debug=true"))
        .header("x-tenant", "acme-eu")
        .send()
        .await
        .unwrap();
    assert_eq!(ok.status(), 200);

    let denied = gw
        .client
        .get(gw.url("/h?debug=true"))
        .header("x-tenant", "other")
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 404);
}

#[tokio::test]
async fn response_filters_modify_headers() {
    let upstream = start_echo_upstream().await;
    let yaml = format!(
        r#"
gateway:
  metrics: {{ enabled: false }}
routes:
  - id: resp
    uri: http://{}
    predicates:
      - Path=/r
    filters:
      - AddResponseHeader=X-Test,one
      - SetResponseHeader=X-Test2,two
      - RemoveResponseHeader=Content-Type
"#,
        upstream.addr
    );
    let gw = start_gateway(&yaml).await;
    let response = gw.get("/r").await;
    assert_eq!(response.headers().get("x-test").unwrap(), "one");
    assert_eq!(response.headers().get("x-test2").unwrap(), "two");
    assert!(response.headers().get("content-type").is_none());
}
