//! 统一错误类型与 HTTP 错误响应。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;
use serde_json::{json, Value};

pub type AppResult<T> = Result<T, AppError>;

/// 应用错误。所有可预期失败都通过该类型表达。
#[derive(Debug, Clone)]
pub struct AppError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<Value>,
}

impl AppError {
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            details: None,
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }

    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "validation_failed".into(),
            message: "请求参数校验失败".into(),
            details: Some(json!({ "field": field.into(), "reason": message.into() })),
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", message)
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "conflict", message)
    }

    pub fn too_many_requests(message: impl Into<String>, retry_after: Option<u64>) -> Self {
        let mut err = Self::new(StatusCode::TOO_MANY_REQUESTS, "rate_limited", message);
        if let Some(seconds) = retry_after {
            err.details = Some(json!({ "retry_after_secs": seconds }));
        }
        err
    }

    pub fn invalid_grant(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_grant", message)
    }

    pub fn invalid_client(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "invalid_client", message)
    }

    pub fn invalid_scope(message: impl Into<String>) -> Self {
        Self::new(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_scope",
            message,
        )
    }

    pub fn unsupported_grant_type(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "unsupported_grant_type", message)
    }

    pub fn server_error(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }

    pub fn unavailable(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service_unavailable",
            message,
        )
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AppError {}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = self.status;
        let body = ErrorBody {
            code: self.code.clone(),
            message: self.message.clone(),
            details: self.details.clone(),
        };
        if status.is_server_error() {
            tracing::error!(status = status.as_u16(), code = %self.code, message = %self.message, "request failed");
        } else {
            tracing::debug!(status = status.as_u16(), code = %self.code, message = %self.message, "request rejected");
        }
        (status, Json(body)).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        if let sqlx::Error::Database(db) = &error {
            if db.code().as_deref() == Some("23505") {
                return Self::conflict("数据已存在，违反唯一约束");
            }
            if db.code().as_deref() == Some("23503") {
                return Self::conflict("关联的数据不存在或仍被引用");
            }
        }
        tracing::error!(error = %error, "database error");
        Self::server_error("数据库操作失败")
    }
}

impl From<redis::RedisError> for AppError {
    fn from(error: redis::RedisError) -> Self {
        tracing::error!(error = %error, "redis error");
        Self::unavailable("缓存服务暂不可用")
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        tracing::error!(error = %error, "unexpected error");
        Self::server_error("服务内部错误")
    }
}

impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        tracing::warn!(error = %error, "json error");
        Self::bad_request("JSON 数据格式错误")
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(error: jsonwebtoken::errors::Error) -> Self {
        tracing::debug!(error = %error, "jwt error");
        Self::unauthorized("Token 无效或已过期")
    }
}

impl From<uuid::Error> for AppError {
    fn from(_: uuid::Error) -> Self {
        Self::bad_request("UUID 格式错误")
    }
}

impl From<url::ParseError> for AppError {
    fn from(error: url::ParseError) -> Self {
        Self::bad_request(format!("URL 格式错误: {error}"))
    }
}
