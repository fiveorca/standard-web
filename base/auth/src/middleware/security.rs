//! 安全响应头、限流辅助。

use axum::extract::Request;
use axum::http::header::{HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;

use crate::bootstrap::AppState;
use crate::config::RateLimitRule;
use crate::shared::{sha256_hex, AppError, AppResult};

pub async fn security_headers(request: Request, next: Next) -> Response {
    let path = request.uri().path().to_string();
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "default-src 'none'; script-src 'self' https://unpkg.com; style-src 'self' 'unsafe-inline' https://unpkg.com; img-src 'self' data:; connect-src 'self'; font-src 'self' https://unpkg.com; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        ),
    );
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    if path.starts_with("/api/") || path.starts_with("/oauth/") || path.starts_with("/saml/") {
        headers.insert(
            HeaderName::from_static("cache-control"),
            HeaderValue::from_static("no-store"),
        );
        headers.insert(
            HeaderName::from_static("pragma"),
            HeaderValue::from_static("no-cache"),
        );
    }
    response
}

/// 固定窗口限流；Redis 不可用时降级放行（可用性优先，同时记录告警）。
pub async fn enforce_rate_limit(
    state: &AppState,
    scope: &str,
    identifier: &str,
    rule: &RateLimitRule,
) -> AppResult<()> {
    let Some(redis) = &state.redis else {
        return Ok(());
    };
    let digest = sha256_hex(format!("{scope}|{identifier}"));
    let key = state.rate_key(scope, &digest[..32]);
    if let Some(retry_after) =
        crate::infrastructure::redis::rate_limit(redis, &key, rule.max_attempts, rule.window_secs)
            .await?
    {
        return Err(AppError::too_many_requests(
            "请求过于频繁，请稍后再试",
            Some(retry_after),
        ));
    }
    Ok(())
}
