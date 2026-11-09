//! HTTP API 路由装配与公共辅助。

pub mod admin;
pub mod auth;
pub mod authz;
pub mod federation;
pub mod internal;
pub mod oauth;
pub mod openapi;
pub mod saml;

use std::sync::Arc;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use serde_json::json;
use uuid::Uuid;

use crate::bootstrap::AppState;
use crate::middleware::auth::client_ip;
use crate::middleware::permission::{permission_middleware, PermissionGuard};
use crate::shared::util::DEFAULT_TENANT_ID;
use crate::shared::{AppError, AppResult};

/// 构造完整应用路由。
pub fn router(state: Arc<AppState>) -> Router {
    let admin = admin_routes();
    let admin = admin.route_layer(middleware::from_fn_with_state(
        PermissionGuard::new(state.clone(), "admin:access"),
        permission_middleware,
    ));

    let authz = Router::new()
        .route("/api/v1/authz/check", post(authz::check))
        .route("/api/v1/authz/batch-check", post(authz::batch_check))
        .route("/api/v1/authz/me", get(authz::me))
        .route("/api/v1/authz/me/permissions", get(authz::my_permissions))
        .route("/api/v1/authz/me/menus", get(authz::my_menus))
        .route("/api/v1/authz/me/buttons", get(authz::my_buttons))
        .route("/api/v1/authz/me/apis", get(authz::my_apis))
        .route("/api/v1/authz/me/data-scope", get(authz::my_data_scope))
        .route_layer(middleware::from_fn_with_state(
            PermissionGuard::new(state.clone(), "authz:check"),
            permission_middleware,
        ));

    Router::new()
        // 健康检查
        .route("/health", get(health))
        .route("/health/live", get(health))
        .route("/health/ready", get(ready))
        .route("/ready", get(ready))
        // OpenAPI / Swagger
        .route("/openapi.json", get(openapi::document))
        .route("/docs", get(openapi::swagger_ui))
        // 认证
        .merge(auth::routes())
        // 授权
        .merge(authz)
        // 管理端
        .merge(admin)
        // 内部服务
        .merge(internal::routes())
        // OAuth2 / OIDC
        .merge(oauth::routes())
        // SAML
        .merge(saml::routes())
        // 身份联邦
        .merge(federation::routes())
        .fallback(not_found)
        .with_state(state)
}

fn admin_routes() -> Router<Arc<AppState>> {
    Router::new()
        // 身份
        .route(
            "/api/v1/admin/identities",
            get(admin::list_identities).post(admin::create_identity),
        )
        .route(
            "/api/v1/admin/identities/{id}",
            get(admin::get_identity).patch(admin::update_identity),
        )
        .route(
            "/api/v1/admin/identities/{id}/status",
            put(admin::set_identity_status),
        )
        .route(
            "/api/v1/admin/identities/{id}/roles",
            get(admin::list_user_roles).post(admin::assign_role),
        )
        .route(
            "/api/v1/admin/identities/{id}/roles/{role_id}",
            delete(admin::revoke_role),
        )
        .route(
            "/api/v1/admin/identities/{id}/permissions",
            post(admin::grant_user_permission),
        )
        .route(
            "/api/v1/admin/identities/{id}/permissions/{permission_id}",
            delete(admin::revoke_user_permission),
        )
        .route(
            "/api/v1/admin/identities/{id}/mfa/reset",
            post(admin::reset_mfa),
        )
        // 角色
        .route(
            "/api/v1/admin/roles",
            get(admin::list_roles).post(admin::create_role),
        )
        .route(
            "/api/v1/admin/roles/{id}",
            get(admin::get_role)
                .patch(admin::update_role)
                .delete(admin::delete_role),
        )
        .route(
            "/api/v1/admin/roles/{id}/permissions",
            get(admin::list_role_permissions).put(admin::set_role_permissions),
        )
        .route(
            "/api/v1/admin/roles/{id}/members",
            get(admin::list_role_members),
        )
        .route(
            "/api/v1/admin/roles/{id}/assign",
            post(admin::batch_assign_roles),
        )
        // 权限
        .route(
            "/api/v1/admin/permissions",
            get(admin::list_permissions).post(admin::create_permission),
        )
        .route(
            "/api/v1/admin/permissions/tree",
            get(admin::permission_tree),
        )
        .route(
            "/api/v1/admin/permissions/{id}",
            get(admin::get_permission)
                .patch(admin::update_permission)
                .delete(admin::delete_permission),
        )
        // API / 菜单 / 按钮 / 数据权限
        .route(
            "/api/v1/admin/api-resources",
            get(admin::list_api_resources).post(admin::create_api_resource),
        )
        .route(
            "/api/v1/admin/api-resources/{id}",
            patch(admin::update_api_resource).delete(admin::delete_api_resource),
        )
        .route(
            "/api/v1/admin/menus",
            get(admin::list_menus).post(admin::create_menu),
        )
        .route(
            "/api/v1/admin/menus/{id}",
            patch(admin::update_menu).delete(admin::delete_menu),
        )
        .route(
            "/api/v1/admin/buttons",
            get(admin::list_buttons).post(admin::create_button),
        )
        .route("/api/v1/admin/buttons/{id}", delete(admin::delete_button))
        .route(
            "/api/v1/admin/data-permissions",
            get(admin::list_data_permissions).post(admin::create_data_permission),
        )
        .route(
            "/api/v1/admin/data-permissions/{id}",
            delete(admin::delete_data_permission),
        )
        // 策略与资源关系
        .route(
            "/api/v1/admin/policies",
            get(admin::list_policies).post(admin::create_policy),
        )
        .route("/api/v1/admin/policies/{id}", delete(admin::delete_policy))
        .route(
            "/api/v1/admin/resource-relations",
            get(admin::list_resource_relations).post(admin::add_resource_relation),
        )
        .route(
            "/api/v1/admin/resource-relations/{id}",
            delete(admin::remove_resource_relation),
        )
        // 租户
        .route(
            "/api/v1/admin/tenants",
            get(admin::list_tenants).post(admin::create_tenant),
        )
        .route(
            "/api/v1/admin/tenants/{id}/status",
            put(admin::set_tenant_status),
        )
        // OAuth 客户端与 scope
        .route(
            "/api/v1/admin/oauth/clients",
            get(admin::list_oauth_clients).post(admin::create_oauth_client),
        )
        .route(
            "/api/v1/admin/oauth/clients/{client_id}/secret",
            post(admin::rotate_client_secret),
        )
        .route(
            "/api/v1/admin/oauth/clients/{client_id}/status",
            put(admin::set_client_status),
        )
        .route(
            "/api/v1/admin/oauth/scopes",
            get(admin::list_oauth_scopes).post(admin::create_oauth_scope),
        )
        // 审计与密钥
        .route("/api/v1/admin/audit-logs", get(admin::list_audit_logs))
        .route(
            "/api/v1/admin/signing-keys",
            get(admin::list_signing_keys).post(admin::rotate_signing_key),
        )
        // SAML
        .route(
            "/api/v1/admin/saml/idp",
            get(admin::get_saml_idp).put(admin::update_saml_idp),
        )
        .route(
            "/api/v1/admin/saml/idp/rotate-certificate",
            post(admin::rotate_saml_certificate),
        )
        .route(
            "/api/v1/admin/saml/sps",
            get(admin::list_saml_sps).post(admin::upsert_saml_sp),
        )
        .route(
            "/api/v1/admin/saml/sps/{code}",
            get(admin::get_saml_sp).delete(admin::delete_saml_sp),
        )
        // 身份提供商
        .route(
            "/api/v1/admin/identity-providers",
            get(admin::list_identity_providers).post(admin::upsert_identity_provider),
        )
        .route(
            "/api/v1/admin/identity-providers/{code}",
            get(admin::get_identity_provider).delete(admin::delete_identity_provider),
        )
}

async fn health() -> impl IntoResponse {
    Json(json!({ "code": "ok", "data": { "status": "ok" } }))
}

async fn ready(axum::extract::State(state): axum::extract::State<Arc<AppState>>) -> Response {
    let (db_ok, redis_ok) = state.readiness().await;
    let ready = db_ok && (!state.config.redis.required || redis_ok);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "code": if ready { "ok" } else { "unavailable" },
            "data": { "database": db_ok, "redis": redis_ok }
        })),
    )
        .into_response()
}

async fn not_found() -> AppError {
    AppError::not_found("接口不存在")
}

/// 解析租户：未提供时使用默认租户。
pub async fn resolve_tenant(state: &AppState, value: Option<&str>) -> AppResult<Uuid> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(DEFAULT_TENANT_ID);
    };
    if let Ok(id) = Uuid::parse_str(value) {
        return Ok(id);
    }
    let row: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM tenants WHERE lower(code) = lower($1) AND deleted_at IS NULL",
    )
    .bind(value)
    .fetch_optional(&state.pool)
    .await?;
    row.map(|row| row.0)
        .ok_or_else(|| AppError::not_found("租户不存在"))
}

/// 从请求头构建审计上下文。
pub fn request_meta(state: &AppState, headers: &HeaderMap) -> crate::application::RequestMeta {
    let trace_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    crate::application::RequestMeta::new(
        client_ip(headers, state.config.server.trust_proxy_headers),
        headers
            .get(header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(|value| value.chars().take(512).collect::<String>()),
        trace_id,
    )
}

/// 构建带认证 Cookie 与 CSRF Cookie 的响应。
pub fn token_response(
    state: &AppState,
    tokens: crate::application::session::TokenBundle,
) -> Response {
    let csrf = crate::shared::util::random_token(32);
    let mut response = Json(json!({
        "code": "ok",
        "data": {
            "access_token": tokens.access_token,
            "token_type": tokens.token_type,
            "expires_in": tokens.expires_in,
            "refresh_token": tokens.refresh_token,
            "id_token": tokens.id_token,
            "scope": tokens.scope,
            "session_id": tokens.session_id,
            "csrf_token": csrf,
        }
    }))
    .into_response();
    let headers = response.headers_mut();
    append_cookie(
        headers,
        crate::security::cookie::session_cookie(&state.config, &tokens.access_token),
    );
    append_cookie(
        headers,
        crate::security::cookie::csrf_cookie(&state.config, &csrf),
    );
    response
}

pub fn append_cookie(headers: &mut HeaderMap, cookie: String) {
    if let Ok(value) = HeaderValue::from_str(&cookie) {
        headers.append(header::SET_COOKIE, value);
    }
}

pub fn clear_auth_cookies(state: &AppState, headers: &mut HeaderMap) {
    append_cookie(
        headers,
        crate::security::cookie::clear_session_cookie(&state.config),
    );
    append_cookie(
        headers,
        crate::security::cookie::clear_csrf_cookie(&state.config),
    );
}

/// 校验内部服务令牌。
pub fn require_internal_token(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let provided = headers
        .get("x-internal-token")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !crate::shared::util::constant_time_eq(
        provided.as_bytes(),
        state.config.security.internal_token.as_bytes(),
    ) {
        return Err(AppError::unauthorized("内部令牌无效"));
    }
    Ok(())
}

/// 用于客户端凭据与管理端点解析分页。
pub fn page_query(query: &crate::shared::PageQuery) -> (&crate::shared::PageQuery,) {
    (query,)
}

/// 统一返回 UUID 路径参数错误。
pub fn parse_uuid(value: &str, field: &str) -> AppResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| AppError::validation(field, "ID 格式不合法"))
}
