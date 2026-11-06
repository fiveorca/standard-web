//! Admin API 路由。
//!
//! 所有路径前缀为 `/api/admin/v1`（需求文档第八章）。
//! 静态路径（`/config/versions/latest`）与动态路径（`/config/versions/{version}`）
//! 同时存在时，Axum 的静态匹配优先。

use axum::routing::{delete, get, post};
use axum::Router;

use crate::handlers;
use crate::state::AdminState;

/// Admin API 路径前缀。
pub const ADMIN_API_PREFIX: &str = "/api/admin/v1";

/// 构建控制面 Router（`/api/admin/v1`）。
///
/// 返回的 Router 已经绑定状态，可直接 `merge`/`nest` 到其他 Router，
/// 或交给 `axum::serve`。
pub fn build_router(state: AdminState) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/status", get(handlers::status))
        // 通用资源 CRUD（按 kind 动态解析）
        .route(
            "/resources/{kind}",
            get(handlers::list_resources).post(handlers::create_resource),
        )
        .route(
            "/resources/{kind}/{id}",
            get(handlers::get_resource)
                .put(handlers::update_resource)
                .delete(handlers::delete_resource),
        )
        // consumers 别名路由（设计文档 8.5）
        .route("/consumers", get(handlers::list_consumers).post(handlers::create_consumer))
        .route(
            "/consumers/{id}",
            get(handlers::get_consumer)
                .put(handlers::update_consumer)
                .delete(handlers::delete_consumer),
        )
        // Consumer 嵌套凭据（设计文档 8.6）
        .route("/consumers/{id}/credentials", post(handlers::create_credential))
        .route(
            "/consumers/{consumer_id}/credentials/{credential_id}",
            delete(handlers::delete_credential),
        )
        // plugins 别名路由（设计文档 8.7）
        .route("/plugins", get(handlers::list_plugins).post(handlers::create_plugin))
        .route(
            "/plugins/{id}",
            get(handlers::get_plugin)
                .put(handlers::update_plugin)
                .delete(handlers::delete_plugin),
        )
        .route("/plugins/{id}/enable", post(handlers::enable_plugin))
        .route("/plugins/{id}/disable", post(handlers::disable_plugin))
        // 配置查询 / 校验 / 编译 / 发布 / 回滚
        .route("/config", get(handlers::current_config))
        .route("/config/validate", post(handlers::validate_config))
        .route("/config/compile", post(handlers::compile_config))
        .route("/config/publish", post(handlers::publish))
        // 版本
        .route("/config/versions", get(handlers::list_versions))
        .route("/config/versions/latest", get(handlers::latest_version))
        .route("/config/versions/{version}", get(handlers::get_version))
        .route("/config/versions/{version}/rollback", post(handlers::rollback))
        // 审计与应用记录
        .route("/audit-logs", get(handlers::list_audit_logs))
        .route("/publish-records", get(handlers::list_publish_records))
        .with_state(state)
}

/// 构建完整 Admin API Router（自动带上 `/api/admin/v1` 前缀）。
pub fn build_admin_router(state: AdminState) -> Router {
    Router::new().nest(ADMIN_API_PREFIX, build_router(state))
}
