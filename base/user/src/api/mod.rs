//! HTTP API 装配层。

pub mod admin;
pub mod internal;
pub mod openapi;
pub mod user;

use std::sync::Arc;
use std::time::Duration;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::json;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

use crate::auth_client::AuthContext;
use crate::bootstrap::AppState;
use crate::shared::{constant_time_eq, AppError, AppResult, RequestMeta};

/// 从 `Authorization: Bearer` 解析并离线校验访问令牌。
#[derive(Debug, Clone)]
pub struct Auth(pub AuthContext);

impl FromRequestParts<Arc<AppState>> for Auth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| AppError::unauthorized("缺少访问令牌"))?;
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .ok_or_else(|| AppError::unauthorized("访问令牌格式应为 Bearer"))?;
        let ctx = state.auth.verify_access_token(token.trim()).await?;
        Ok(Auth(ctx))
    }
}

pub fn request_meta(headers: &HeaderMap, trust_proxy: bool) -> RequestMeta {
    let ip = if trust_proxy {
        headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| {
                headers
                    .get("x-real-ip")
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_string)
            })
    } else {
        None
    };
    RequestMeta {
        ip,
        user_agent: headers
            .get(axum::http::header::USER_AGENT)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
        trace_id: headers
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string),
    }
}

pub fn parse_uuid(value: &str, field: &str) -> AppResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| AppError::validation(field, "ID 格式不合法"))
}

pub fn require_internal_token(state: &AppState, headers: &HeaderMap) -> AppResult<()> {
    let provided = headers
        .get("x-internal-token")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("缺少内部服务令牌"))?;
    if constant_time_eq(
        provided.as_bytes(),
        state.config.auth.internal_token.as_bytes(),
    ) {
        Ok(())
    } else {
        Err(AppError::unauthorized("内部服务令牌无效"))
    }
}

/// 管理端只允许操作令牌所属租户，避免通过参数越权。
pub fn resolve_tenant(ctx: &AuthContext, requested: Option<Uuid>) -> AppResult<Uuid> {
    match requested {
        Some(tenant_id) if tenant_id != ctx.tenant_id => {
            Err(AppError::forbidden("不能访问其他租户的数据"))
        }
        _ => Ok(ctx.tenant_id),
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    let cors = if state.config.server.cors_allowed_origins.is_empty() {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers(Any)
            .max_age(Duration::from_secs(600))
    } else {
        let origins = state
            .config
            .server
            .cors_allowed_origins
            .iter()
            .filter_map(|origin| HeaderValue::from_str(origin).ok())
            .collect::<Vec<_>>();
        CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::PATCH,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers(Any)
            .max_age(Duration::from_secs(600))
    };
    let timeout = Duration::from_secs(state.config.server.request_timeout_secs.max(1));
    let body_limit = state.config.server.max_body_bytes.max(1024) as usize;

    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/openapi.json", get(openapi::document))
        .route("/docs", get(openapi::swagger_ui))
        .merge(user::routes())
        .merge(admin::routes())
        .merge(internal::routes())
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            timeout,
        ))
        .layer(RequestBodyLimitLayer::new(body_limit))
        .layer(middleware::from_fn(security_headers))
        .layer(cors)
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok", "service": "user-center" }))
}

async fn ready(State(state): State<Arc<AppState>>) -> Response {
    let (db_ok, redis_ok) = state.readiness().await;
    let auth_ok = state.auth.health().await;
    let status = if db_ok && (redis_ok || !state.config.redis.required) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(json!({
            "status": if status == StatusCode::OK { "ready" } else { "degraded" },
            "database": db_ok,
            "redis": redis_ok,
            "auth_center": auth_ok,
        })),
    )
        .into_response()
}

async fn security_headers(mut request: Request, next: Next) -> Response {
    let trace_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    if let Ok(value) = HeaderValue::from_str(&trace_id) {
        request.headers_mut().insert("x-request-id", value);
    }
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        "x-request-id",
        HeaderValue::from_str(&trace_id).unwrap_or_else(|_| HeaderValue::from_static("invalid")),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert("x-frame-options", HeaderValue::from_static("DENY"));
    headers.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    headers.insert(
        "content-security-policy",
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("geolocation=(), microphone=(), camera=()"),
    );
    response
}
