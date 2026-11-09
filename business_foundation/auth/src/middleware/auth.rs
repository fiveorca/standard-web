//! 认证中间件与 AuthContext 提取器。

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::{HeaderMap, HeaderValue};
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::bootstrap::AppState;
use crate::domain::TokenClaims;
use crate::security::cookie::{bearer_from_headers, cookie_from_headers, CSRF_COOKIE};
use crate::shared::{AppError, AppResult};

/// 请求追踪 ID。
#[derive(Debug, Clone)]
pub struct TraceId(pub String);

/// 从请求中解析并验证会话。
pub async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> AppResult<crate::domain::AuthContext> {
    let bearer = bearer_from_headers(headers);
    let cookie_token = cookie_from_headers(headers, &state.config.security.cookie_name);
    let (token, via_cookie) = match (bearer, cookie_token) {
        (Some(token), _) => (token, false),
        (None, Some(token)) => (token, true),
        (None, None) => return Err(AppError::unauthorized("缺少认证凭据")),
    };

    let claims: TokenClaims = state
        .keys
        .verify(&token, Some(state.access_audience()))
        .await?;
    if claims.typ != "access" {
        return Err(AppError::unauthorized("Token 类型不正确"));
    }
    let identity_id = Uuid::parse_str(&claims.sub)
        .map_err(|_| AppError::unauthorized("Token 的 subject 非法"))?;
    let tenant_id = Uuid::parse_str(&claims.tenant_id)
        .map_err(|_| AppError::unauthorized("Token 的 tenant_id 非法"))?;
    let session_id =
        Uuid::parse_str(&claims.sid).map_err(|_| AppError::unauthorized("Token 的会话 ID 非法"))?;

    if let Some(redis) = &state.redis {
        if crate::infrastructure::redis::get(redis, &state.access_blacklist_key(&claims.jti))
            .await?
            .is_some()
        {
            return Err(AppError::unauthorized("Token 已被撤销"));
        }
        let session =
            crate::infrastructure::redis::get(redis, &state.session_key(session_id)).await?;
        if session.as_deref() != Some("active") {
            return Err(AppError::unauthorized("会话已失效"));
        }
    } else {
        let status: Option<(String,)> =
            sqlx::query_as("SELECT status FROM auth_sessions WHERE id = $1 AND expires_at > now()")
                .bind(session_id)
                .fetch_optional(&state.pool)
                .await?;
        if status.as_ref().map(|row| row.0.as_str()) != Some("active") {
            return Err(AppError::unauthorized("会话已失效"));
        }
    }

    let identity: Option<(String, Uuid, Option<chrono::DateTime<chrono::Utc>>)> =
        sqlx::query_as("SELECT status, tenant_id, deleted_at FROM identities WHERE id = $1")
            .bind(identity_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((status, identity_tenant, deleted_at)) = identity else {
        return Err(AppError::unauthorized("身份不存在"));
    };
    if deleted_at.is_some() || !matches!(status.as_str(), "active" | "pending") {
        return Err(AppError::unauthorized("身份已被禁用或删除"));
    }
    if identity_tenant != tenant_id {
        return Err(AppError::unauthorized("Token 租户与身份租户不一致"));
    }

    let ip = client_ip(headers, state.config.server.trust_proxy_headers);
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.chars().take(512).collect::<String>());
    let trace_id = headers
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);

    Ok(crate::domain::AuthContext {
        identity_id,
        tenant_id,
        client_id: Some(claims.client_id.clone()),
        session_id: Some(session_id),
        scopes: claims
            .scope
            .split_whitespace()
            .map(str::to_string)
            .collect(),
        amr: claims.amr.clone(),
        acr: claims.acr.clone(),
        claims,
        via_cookie,
        ip,
        user_agent,
        trace_id,
    })
}

pub fn client_ip(headers: &HeaderMap, trust_proxy: bool) -> Option<String> {
    if trust_proxy {
        if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = value.split(',').next() {
                let candidate = first.trim();
                if candidate.parse::<IpAddr>().is_ok() {
                    return Some(candidate.to_string());
                }
            }
        }
        if let Some(value) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if value.trim().parse::<IpAddr>().is_ok() {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

fn credentials_present(headers: &HeaderMap, cookie_name: &str) -> bool {
    bearer_from_headers(headers).is_some() || cookie_from_headers(headers, cookie_name).is_some()
}

fn csrf_needed(method: &axum::http::Method, path: &str) -> bool {
    if matches!(
        *method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    ) {
        return false;
    }
    if path.starts_with("/api/v1/admin") {
        return true;
    }
    if !path.starts_with("/api/v1/auth") {
        return false;
    }
    const EXEMPT: &[&str] = &[
        "/api/v1/auth/login",
        "/api/v1/auth/register",
        "/api/v1/auth/password/forgot",
        "/api/v1/auth/password/reset",
        "/api/v1/auth/login/otp/request",
        "/api/v1/auth/login/otp",
        "/api/v1/auth/mfa/verify",
        "/api/v1/auth/email/verify",
        "/api/v1/auth/phone/verify",
    ];
    !EXEMPT
        .iter()
        .any(|item| path == *item || path.starts_with(&format!("{item}/")))
        && !(path.starts_with("/api/v1/auth/federated/") && path.ends_with("/callback"))
}

/// 全局认证中间件：有凭据则认证，无凭据则匿名继续。
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let method = request.method().clone();
    let has_credentials =
        credentials_present(request.headers(), &state.config.security.cookie_name);

    if !has_credentials {
        request
            .extensions_mut()
            .insert(None::<crate::domain::AuthContext>);
        return next.run(request).await;
    }

    match authenticate(&state, request.headers()).await {
        Ok(context) => {
            if context.via_cookie
                && state.config.security.enforce_csrf_for_cookie_auth
                && csrf_needed(&method, &path)
            {
                let cookie =
                    cookie_from_headers(request.headers(), CSRF_COOKIE).unwrap_or_default();
                let header = request
                    .headers()
                    .get("x-csrf-token")
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default();
                if cookie.is_empty()
                    || !crate::shared::util::constant_time_eq(cookie.as_bytes(), header.as_bytes())
                {
                    return AppError::forbidden("CSRF 校验失败").into_response();
                }
            }
            request.extensions_mut().insert(Some(context));
            next.run(request).await
        }
        Err(error) => error.into_response(),
    }
}

impl FromRequestParts<Arc<AppState>> for crate::domain::AuthContext {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if let Some(cached) = parts.extensions.get::<Option<crate::domain::AuthContext>>() {
            return cached
                .clone()
                .ok_or_else(|| AppError::unauthorized("缺少认证凭据"));
        }
        authenticate(state, &parts.headers).await
    }
}

/// 可选认证提取器。
#[derive(Debug, Clone)]
pub struct OptionalAuth(pub Option<crate::domain::AuthContext>);

impl FromRequestParts<Arc<AppState>> for OptionalAuth {
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if let Some(cached) = parts.extensions.get::<Option<crate::domain::AuthContext>>() {
            return Ok(Self(cached.clone()));
        }
        let token_present = credentials_present(&parts.headers, &state.config.security.cookie_name);
        if !token_present {
            return Ok(Self(None));
        }
        match authenticate(state, &parts.headers).await {
            Ok(context) => Ok(Self(Some(context))),
            Err(_) => Ok(Self(None)),
        }
    }
}

/// 为响应附加请求 ID。
pub async fn request_context(mut request: Request, next: Next) -> Response {
    let trace_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| value.len() <= 128 && !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| Uuid::now_v7().to_string());
    request.extensions_mut().insert(TraceId(trace_id.clone()));
    let mut response = next.run(request).await;
    if let Ok(value) = HeaderValue::from_str(&trace_id) {
        response.headers_mut().insert("x-request-id", value);
    }
    response
}
