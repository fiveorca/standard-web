//! 统一错误响应。
//!
//! 所有 Admin API 错误都返回同一结构：
//!
//! ```json
//! {
//!   "code": "RESOURCE_NOT_FOUND",
//!   "message": "resource not found: routes/r-1",
//!   "request_id": "...",
//!   "trace_id": "..."
//! }
//! ```
//!
//! # 约束
//!
//! - 生产环境不得返回堆栈、SQL 语句、连接串、密钥
//! - 存储层内部错误统一映射为 `INTERNAL_ERROR` + 通用文案
//! - `request_id` 与 `trace_id` 在 Phase 3 由服务端生成；Phase 5 接入
//!   链路追踪后改为从上游上下文读取

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use gateway_control_service::{format_validation_errors, ControlError};
use gateway_storage::StorageError;
use serde_json::json;
use uuid::Uuid;

/// Admin API 错误。
#[derive(Debug, Clone)]
pub struct ApiError {
    /// HTTP 状态码
    pub status: StatusCode,
    /// 稳定错误码（供客户端程序判断）
    pub code: &'static str,
    /// 人类可读描述
    pub message: String,
}

impl ApiError {
    /// 401：缺少或无效的 Bearer Token。
    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "ADMIN_UNAUTHORIZED",
            message: message.into(),
        }
    }

    /// 403：角色不足。
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "ADMIN_FORBIDDEN",
            message: message.into(),
        }
    }

    /// 404：未知资源类型 / 接口。
    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "RESOURCE_NOT_FOUND",
            message: message.into(),
        }
    }

    /// 400：请求参数错误。
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "INVALID_REQUEST",
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Phase 3：由服务端生成 request_id/trace_id。两者当前相同，
        // 后续接入分布式追踪后 trace_id 可来自上游 Header。
        let request_id = Uuid::new_v4().to_string();
        let body = json!({
            "code": self.code,
            "message": self.message,
            "request_id": request_id,
            "trace_id": request_id,
        });
        (self.status, Json(body)).into_response()
    }
}

impl From<ControlError> for ApiError {
    fn from(err: ControlError) -> Self {
        match err {
            ControlError::NotFound { resource, id } => Self {
                status: StatusCode::NOT_FOUND,
                code: "RESOURCE_NOT_FOUND",
                message: format!("resource not found: {resource}/{id}"),
            },
            ControlError::Conflict { resource, id } => Self {
                status: StatusCode::CONFLICT,
                code: "RESOURCE_CONFLICT",
                message: format!("resource already exists: {resource}/{id}"),
            },
            ControlError::InvalidRequest { message } => Self {
                status: StatusCode::BAD_REQUEST,
                code: "INVALID_REQUEST",
                message,
            },
            ControlError::InvalidPayload { message } => Self {
                status: StatusCode::BAD_REQUEST,
                code: "INVALID_PAYLOAD",
                message,
            },
            ControlError::VersionConflict {
                resource,
                id,
                expected,
                actual,
            } => Self {
                status: StatusCode::CONFLICT,
                code: "VERSION_CONFLICT",
                message: format!(
                    "resource version conflict: {resource}/{id} expected {expected}, actual {actual}"
                ),
            },
            ControlError::Validation { errors } => Self {
                status: StatusCode::BAD_REQUEST,
                code: "CONFIG_VALIDATION_FAILED",
                message: format_validation_errors(&errors),
            },
            ControlError::ApplyFailed { message } => Self {
                status: StatusCode::BAD_GATEWAY,
                code: "CONFIG_APPLY_FAILED",
                message,
            },
            ControlError::Storage(err) => Self::from_storage(err),
        }
    }
}

impl ApiError {
    /// 存储错误映射。
    ///
    /// 具体 SQL 错误不返回给客户端，只保留通用文案并写日志。
    fn from_storage(err: StorageError) -> Self {
        match err {
            StorageError::Unavailable { message } => Self {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "STORAGE_UNAVAILABLE",
                message,
            },
            other => {
                // 内部错误只写服务端日志，响应中不暴露细节
                tracing::error!(error = %other, "admin api storage error");
                Self {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    code: "INTERNAL_ERROR",
                    message: "internal storage error".to_string(),
                }
            },
        }
    }
}
