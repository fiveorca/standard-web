//! Admin API 集成测试（Tower `oneshot`，不启动真实端口）。
//!
//! 覆盖：
//!   1. 未认证 → 401；viewer 写操作 → 403
//!   2. 资源 CRUD 正常路径与 404
//!   3. 发布失败返回 400 且不产生版本
//!   4. 发布成功后版本 / 审计可查询
//!   5. 未知资源类型 → 404

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use gateway_control_service::ConfigService;
use gateway_storage::MemoryRepository;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use tower::ServiceExt;

use crate::auth::{AdminAuth, Role};
use crate::router::build_admin_router;
use crate::state::AdminState;

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

fn build_app() -> axum::Router {
    let service = ConfigService::new(Arc::new(MemoryRepository::new()));
    let mut auth = AdminAuth::empty();
    auth.add_token("admin-token", "alice", Role::Admin);
    auth.add_token("viewer-token", "bob", Role::Viewer);
    build_admin_router(AdminState::new(service, auth))
}

fn request(method: Method, uri: &str, token: Option<&str>, body: Option<Value>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    match body {
        Some(value) => builder
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&value).expect("serialize request body")))
            .expect("build request"),
        None => builder.body(Body::empty()).expect("build request"),
    }
}

async fn send(app: &axum::Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = app.clone().oneshot(request).await.expect("send request");
    let status = response.status();
    let bytes = response.into_body().collect().await.expect("collect body").to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

fn upstream_uri() -> &'static str {
    "/api/admin/v1/resources/upstreams"
}

fn resource_uri(kind: &str, id: &str) -> String {
    format!("/api/admin/v1/resources/{kind}/{id}")
}

/// 创建一条最小可用配置（upstream → service → route）。
async fn seed(app: &axum::Router) {
    let (status, body) = send(
        app,
        request(
            Method::POST,
            upstream_uri(),
            Some("admin-token"),
            Some(json!({
                "id": "up-1",
                "payload": {
                    "id": "up-1",
                    "algorithm": "round_robin",
                    "endpoints": [{ "host": "127.0.0.1", "port": 9000 }]
                }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "upstream: {body}");

    let (status, body) = send(
        app,
        request(
            Method::POST,
            "/api/admin/v1/resources/services",
            Some("admin-token"),
            Some(json!({
                "id": "svc-1",
                "payload": { "id": "svc-1", "upstream_id": "up-1" }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "service: {body}");

    let (status, body) = send(
        app,
        request(
            Method::POST,
            "/api/admin/v1/resources/routes",
            Some("admin-token"),
            Some(json!({
                "id": "r-1",
                "payload": {
                    "id": "r-1",
                    "path_type": "prefix",
                    "path_value": "/api",
                    "service_id": "svc-1"
                }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "route: {body}");
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[tokio::test]
async fn health_is_public() {
    let app = build_app();
    let (status, body) = send(&app, request(Method::GET, "/api/admin/v1/health", None, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn missing_token_is_unauthorized() {
    let app = build_app();
    let (status, body) =
        send(&app, request(Method::GET, "/api/admin/v1/resources/routes", None, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "ADMIN_UNAUTHORIZED");
    assert!(!body["request_id"].as_str().unwrap_or_default().is_empty());
}

#[tokio::test]
async fn viewer_cannot_write() {
    let app = build_app();
    let (status, body) = send(
        &app,
        request(
            Method::POST,
            "/api/admin/v1/resources/routes",
            Some("viewer-token"),
            Some(json!({ "id": "r-1", "payload": { "id": "r-1" } })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "ADMIN_FORBIDDEN");
}

#[tokio::test]
async fn resource_crud_and_not_found() {
    let app = build_app();
    seed(&app).await;

    // 列表（viewer 可读）
    let (status, body) = send(
        &app,
        request(
            Method::GET,
            "/api/admin/v1/resources/routes?limit=10&offset=0",
            Some("viewer-token"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 1);
    assert_eq!(body["items"][0]["id"], "r-1");

    // 单条
    let (status, body) = send(
        &app,
        request(Method::GET, &resource_uri("routes", "r-1"), Some("viewer-token"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["payload"]["path_value"], "/api");

    // 不存在
    let (status, body) = send(
        &app,
        request(Method::GET, &resource_uri("routes", "missing"), Some("viewer-token"), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "RESOURCE_NOT_FOUND");

    // 未知资源类型
    let (status, body) = send(
        &app,
        request(Method::GET, "/api/admin/v1/resources/unknown-kind", Some("viewer-token"), None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["message"].as_str().unwrap_or_default().contains("unknown resource kind"));
}

#[tokio::test]
async fn publish_invalid_config_returns_400_without_version() {
    let app = build_app();
    // 直接创建一条引用不存在 service 的路由
    let (status, _) = send(
        &app,
        request(
            Method::POST,
            "/api/admin/v1/resources/routes",
            Some("admin-token"),
            Some(json!({
                "id": "r-1",
                "payload": {
                    "id": "r-1",
                    "path_value": "/api",
                    "service_id": "missing-svc"
                }
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = send(
        &app,
        request(
            Method::POST,
            "/api/admin/v1/config/publish",
            Some("admin-token"),
            Some(json!({})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "CONFIG_VALIDATION_FAILED");

    // 没有版本被创建
    let (status, body) = send(
        &app,
        request(Method::GET, "/api/admin/v1/config/versions/latest", Some("viewer-token"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, Value::Null);
}

#[tokio::test]
async fn publish_success_exposes_version_and_audit() {
    let app = build_app();
    seed(&app).await;

    // dry-run 校验（POST /config/validate，与设计文档第八章一致）
    let (status, body) = send(
        &app,
        request(Method::POST, "/api/admin/v1/config/validate", Some("viewer-token"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["valid"], true);

    // 发布
    let (status, body) = send(
        &app,
        request(
            Method::POST,
            "/api/admin/v1/config/publish",
            Some("admin-token"),
            Some(json!({ "note": "first publish" })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 1);
    assert_eq!(body["applied"], false); // 独立控制面没有注入 applier
    assert_eq!(body["note"], "first publish");

    // 状态
    let (status, body) =
        send(&app, request(Method::GET, "/api/admin/v1/status", Some("viewer-token"), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["published_version"], 1);
    assert_eq!(body["has_configuration"], true);

    // 审计日志：3 次 create + 1 次 publish
    let (status, body) = send(
        &app,
        request(Method::GET, "/api/admin/v1/audit-logs?limit=10", Some("viewer-token"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["action"], "publish");
    assert_eq!(body["items"][0]["version"], 1);

    // 版本列表
    let (status, body) = send(
        &app,
        request(Method::GET, "/api/admin/v1/config/versions", Some("viewer-token"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"][0]["version"], 1);
}

#[tokio::test]
async fn viewer_reads_are_allowed() {
    let app = build_app();
    let (status, _) = send(
        &app,
        request(Method::GET, "/api/admin/v1/publish-records", Some("viewer-token"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn update_and_delete_use_optimistic_lock() {
    let app = build_app();
    seed(&app).await;

    // 正确的期望版本
    let (status, body) = send(
        &app,
        request(
            Method::PUT,
            &resource_uri("routes", "r-1"),
            Some("admin-token"),
            Some(json!({ "enabled": false, "expected_version": 1 })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 2);
    assert_eq!(body["enabled"], false);

    // 过期的期望版本 → 409
    let (status, body) = send(
        &app,
        request(
            Method::DELETE,
            &format!("{}?expected_version=1", resource_uri("routes", "r-1")),
            Some("admin-token"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "VERSION_CONFLICT");

    // 使用正确版本删除 → 204
    let (status, _) = send(
        &app,
        request(
            Method::DELETE,
            &format!("{}?expected_version=2", resource_uri("routes", "r-1")),
            Some("admin-token"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn config_endpoints_expose_current_compile_and_rollback() {
    let app = build_app();

    // 尚未发布时 GET /config → 404
    let (status, body) =
        send(&app, request(Method::GET, "/api/admin/v1/config", Some("viewer-token"), None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "RESOURCE_NOT_FOUND");

    seed(&app).await;

    // 编译预览：不写版本，返回预计版本号与快照
    let (status, body) = send(
        &app,
        request(Method::POST, "/api/admin/v1/config/compile", Some("viewer-token"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 1);
    assert!(body["checksum"].is_string());
    assert_eq!(body["snapshot"]["config_version"], 1);
    assert_eq!(body["snapshot"]["bundle"]["routes"][0]["id"], "r-1");

    // 发布
    let (status, body) = send(
        &app,
        request(
            Method::POST,
            "/api/admin/v1/config/publish",
            Some("admin-token"),
            Some(json!({ "note": "v1" })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 1);

    // GET /config 返回当前版本与资源集合
    let (status, body) =
        send(&app, request(Method::GET, "/api/admin/v1/config", Some("viewer-token"), None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 1);
    assert_eq!(body["resources"]["routes"][0]["id"], "r-1");

    // 回滚到 v1（路径携带版本号，body 可省略）→ 版本号继续递增到 2
    let (status, body) = send(
        &app,
        request(
            Method::POST,
            "/api/admin/v1/config/versions/1/rollback",
            Some("admin-token"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["version"], 2);
    assert!(body["note"].as_str().unwrap_or_default().contains("rollback"));

    // viewer 不能回滚
    let (status, body) = send(
        &app,
        request(
            Method::POST,
            "/api/admin/v1/config/versions/1/rollback",
            Some("viewer-token"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "ADMIN_FORBIDDEN");
}
