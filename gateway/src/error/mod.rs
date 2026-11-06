//! 统一错误模型。
//!
//! 网关内部所有可预期的失败都通过 [`GatewayError`] 表达，
//! 由 [`GatewayError::into_response`] 转换为统一的 JSON 错误响应。

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use http::header::CONTENT_TYPE;
use http::StatusCode;
use serde::Serialize;

/// 网关错误类型。
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("no route matched the request")]
    RouteNotFound,

    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("rate limit exceeded")]
    RateLimited { retry_after_secs: Option<u64> },

    #[error("request body too large")]
    PayloadTooLarge,

    #[error("request headers too large")]
    HeadersTooLarge,

    #[error("upstream request failed: {0}")]
    Upstream(String),

    #[error("upstream connect failed: {0}")]
    UpstreamConnect(String),

    #[error("upstream request timed out")]
    Timeout,

    #[error("circuit breaker is open for {0}")]
    CircuitOpen(String),

    #[error("service unavailable: {0}")]
    ServiceUnavailable(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("internal error: {0}")]
    Internal(String),
}

impl GatewayError {
    /// 映射到 HTTP 状态码。
    pub fn status_code(&self) -> StatusCode {
        match self {
            GatewayError::RouteNotFound => StatusCode::NOT_FOUND,
            GatewayError::BadRequest(_) => StatusCode::BAD_REQUEST,
            GatewayError::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            GatewayError::Forbidden(_) => StatusCode::FORBIDDEN,
            GatewayError::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            GatewayError::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            GatewayError::HeadersTooLarge => StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            GatewayError::Upstream(_) | GatewayError::UpstreamConnect(_) => StatusCode::BAD_GATEWAY,
            GatewayError::Timeout => StatusCode::GATEWAY_TIMEOUT,
            GatewayError::CircuitOpen(_) => StatusCode::SERVICE_UNAVAILABLE,
            GatewayError::ServiceUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            GatewayError::Config(_) | GatewayError::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }

    /// 稳定的错误码，供客户端程序判断。
    pub fn code(&self) -> &'static str {
        match self {
            GatewayError::RouteNotFound => "ROUTE_NOT_FOUND",
            GatewayError::BadRequest(_) => "BAD_REQUEST",
            GatewayError::Unauthorized(_) => "UNAUTHORIZED",
            GatewayError::Forbidden(_) => "FORBIDDEN",
            GatewayError::RateLimited { .. } => "RATE_LIMITED",
            GatewayError::PayloadTooLarge => "PAYLOAD_TOO_LARGE",
            GatewayError::HeadersTooLarge => "HEADERS_TOO_LARGE",
            GatewayError::Upstream(_) => "UPSTREAM_ERROR",
            GatewayError::UpstreamConnect(_) => "UPSTREAM_CONNECT_ERROR",
            GatewayError::Timeout => "UPSTREAM_TIMEOUT",
            GatewayError::CircuitOpen(_) => "CIRCUIT_OPEN",
            GatewayError::ServiceUnavailable(_) => "SERVICE_UNAVAILABLE",
            GatewayError::Config(_) => "CONFIG_ERROR",
            GatewayError::Internal(_) => "INTERNAL_ERROR",
        }
    }

    /// 该错误是否属于上游（服务端）错误，用于熔断统计与指标分类。
    pub fn is_upstream_failure(&self) -> bool {
        matches!(
            self,
            GatewayError::Upstream(_)
                | GatewayError::UpstreamConnect(_)
                | GatewayError::Timeout
                | GatewayError::ServiceUnavailable(_)
        )
    }
}

/// 统一错误响应体。
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub success: bool,
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: &'static str,
    pub message: String,
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let retry_after = match &self {
            GatewayError::RateLimited { retry_after_secs } => *retry_after_secs,
            _ => None,
        };

        let body = ErrorResponse {
            success: false,
            error: ErrorDetail {
                code: self.code(),
                message: self.to_string(),
            },
        };
        let payload = serde_json::to_vec(&body).unwrap_or_else(|_| {
            br#"{"success":false,"error":{"code":"INTERNAL_ERROR","message":"serialization failure"}}"#
                .to_vec()
        });

        let mut response = Response::new(Body::from(payload));
        *response.status_mut() = status;
        response.headers_mut().insert(
            CONTENT_TYPE,
            http::HeaderValue::from_static("application/json; charset=utf-8"),
        );
        if let Some(secs) = retry_after {
            if let Ok(v) = http::HeaderValue::from_str(&secs.to_string()) {
                response.headers_mut().insert(http::header::RETRY_AFTER, v);
            }
        }
        response
    }
}

/// 常用 Result 别名。
pub type Result<T> = std::result::Result<T, GatewayError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_is_stable() {
        assert_eq!(
            GatewayError::RouteNotFound.status_code(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            GatewayError::RateLimited {
                retry_after_secs: Some(1)
            }
            .status_code(),
            StatusCode::TOO_MANY_REQUESTS
        );
    }
}
