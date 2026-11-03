//! 统一错误类型、错误码和 HTTP 错误响应。
//!
//! 本模块是整个 Gateway 错误处理的核心：
//!
//! 1. `ErrorCode` —— 枚举，列出需求文档（第十一章）规定的所有错误码。
//!    每个错误码有一个常量字符串（例如 `"GATEWAY_UPSTREAM_TIMEOUT"`）。
//!
//! 2. `GatewayError` —— thiserror 错误枚举，承载错误上下文（错误码 +
//!    可选的详细信息）。所有 crate 内部遇到错误时返回此类型。
//!
//! 3. `ErrorResponse` —— 序列化为 JSON 的统一错误响应结构，用于 HTTP
//!    API 返回给客户端：
//!    ```json
//!    {
//!      "code": "GATEWAY_UPSTREAM_TIMEOUT",
//!      "message": "Upstream request timeout",
//!      "request_id": "req-001",
//!      "trace_id": "trace-001"
//!    }
//!    ```
//!
//! 4. `GatewayError::to_http_status()` —— 错误码到 HTTP 状态码的映射。
//!
//! 设计约束：
//!   - 错误码枚举必须完全覆盖需求文档第十一章列出的所有码
//!   - HTTP 状态码映射表必须和需求文档中给出的表一致
//!   - 错误响应中严禁输出内部堆栈、密钥等敏感信息

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// ErrorCode —— 错误码枚举（对应需求第十一章）
// ---------------------------------------------------------------------------

/// Gateway 统一错误码。
///
/// 错误码是稳定的对外契约，出现在 JSON 错误响应的 `code` 字段中。
/// 新增错误码时必须：
///   1. 在 `ErrorCode` 中增加一个变体
///   2. 为它实现 Display（或依赖 thiserror 的自动推导，这里我们手写）
///   3. 在 `to_http_status` 中增加 HTTP 状态码映射
///   4. 更新需求文档（如有）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    /// 网关内部未知错误（兜底）
    GatewayInternalError,
    /// 请求本身不合法（格式错误、参数缺失、类型不匹配等）
    GatewayBadRequest,
    /// 没有匹配到任何路由（等价于 HTTP 404）
    GatewayRouteNotFound,
    /// Method 不被允许（Route 匹配但 Method 不在路由方法列表中）
    GatewayMethodNotAllowed,
    /// 认证失败（JWT/API Key 无效或缺失）
    GatewayAuthenticationFailed,
    /// 授权失败（Consumer 无权限访问该 API）
    GatewayAuthorizationFailed,
    /// 触发限流
    GatewayRateLimited,
    /// 请求体过大
    GatewayRequestTooLarge,
    /// 上游服务不可达（连接拒绝、DNS 解析失败、健康端点全坏）
    GatewayUpstreamUnavailable,
    /// 上游连接/响应超时
    GatewayUpstreamTimeout,
    /// 上游连接建立失败（如 TCP RST）
    GatewayUpstreamConnectionError,
    /// 上游熔断器打开（CIRCUIT_OPEN）
    GatewayCircuitOpen,
    /// 配置本身不合法（Schema 校验失败或引用不存在）
    GatewayConfigurationInvalid,
    /// 配置应用失败（编译或原子交换失败）
    GatewayConfigurationApplyFailed,
    /// 资源耗尽（连接数、并发数、内存等）
    GatewayResourceExhausted,
}

impl ErrorCode {
    /// 把错误码转换为稳定的字符串标识符。
    /// 所有变体的字符串必须和 JSON 错误响应中的 `code` 字段完全一致。
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorCode::GatewayInternalError => "GATEWAY_INTERNAL_ERROR",
            ErrorCode::GatewayBadRequest => "GATEWAY_BAD_REQUEST",
            ErrorCode::GatewayRouteNotFound => "GATEWAY_ROUTE_NOT_FOUND",
            ErrorCode::GatewayMethodNotAllowed => "GATEWAY_METHOD_NOT_ALLOWED",
            ErrorCode::GatewayAuthenticationFailed => "GATEWAY_AUTHENTICATION_FAILED",
            ErrorCode::GatewayAuthorizationFailed => "GATEWAY_AUTHORIZATION_FAILED",
            ErrorCode::GatewayRateLimited => "GATEWAY_RATE_LIMITED",
            ErrorCode::GatewayRequestTooLarge => "GATEWAY_REQUEST_TOO_LARGE",
            ErrorCode::GatewayUpstreamUnavailable => "GATEWAY_UPSTREAM_UNAVAILABLE",
            ErrorCode::GatewayUpstreamTimeout => "GATEWAY_UPSTREAM_TIMEOUT",
            ErrorCode::GatewayUpstreamConnectionError => "GATEWAY_UPSTREAM_CONNECTION_ERROR",
            ErrorCode::GatewayCircuitOpen => "GATEWAY_CIRCUIT_OPEN",
            ErrorCode::GatewayConfigurationInvalid => "GATEWAY_CONFIGURATION_INVALID",
            ErrorCode::GatewayConfigurationApplyFailed => "GATEWAY_CONFIGURATION_APPLY_FAILED",
            ErrorCode::GatewayResourceExhausted => "GATEWAY_RESOURCE_EXHAUSTED",
        }
    }

    /// 根据需求文档中的映射表把错误码转换为 HTTP 状态码。
    /// 返回 `(http::StatusCode)`，不是 `u16`，以获得编译期校验和语义。
    pub fn to_http_status(self) -> http::StatusCode {
        // 需求文档第十一章规定的错误码 → HTTP 状态码映射
        match self {
            // 400 类：请求本身有问题
            ErrorCode::GatewayBadRequest => http::StatusCode::BAD_REQUEST,
            ErrorCode::GatewayAuthenticationFailed => http::StatusCode::UNAUTHORIZED,
            ErrorCode::GatewayAuthorizationFailed => http::StatusCode::FORBIDDEN,
            ErrorCode::GatewayRouteNotFound => http::StatusCode::NOT_FOUND,
            ErrorCode::GatewayMethodNotAllowed => http::StatusCode::METHOD_NOT_ALLOWED,
            ErrorCode::GatewayRequestTooLarge => http::StatusCode::PAYLOAD_TOO_LARGE,
            ErrorCode::GatewayRateLimited => http::StatusCode::TOO_MANY_REQUESTS,

            // 503：上游不可用/熔断器打开
            ErrorCode::GatewayUpstreamUnavailable | ErrorCode::GatewayCircuitOpen => {
                http::StatusCode::SERVICE_UNAVAILABLE
            },

            // 504：上游超时/连接错误
            ErrorCode::GatewayUpstreamTimeout => http::StatusCode::GATEWAY_TIMEOUT,
            ErrorCode::GatewayUpstreamConnectionError => http::StatusCode::BAD_GATEWAY,

            // 500：配置错误、资源耗尽、内部未知错误
            ErrorCode::GatewayConfigurationInvalid
            | ErrorCode::GatewayConfigurationApplyFailed
            | ErrorCode::GatewayResourceExhausted
            | ErrorCode::GatewayInternalError => http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GatewayError —— 统一错误枚举（thiserror）
// ---------------------------------------------------------------------------

/// Gateway 全局错误枚举。
///
/// 所有 crate 的内部错误最终都应能映射到此枚举。`thiserror::Error`
/// 自动实现了 `std::error::Error`，并让 `std::fmt::Display` 返回
/// `#[error("...")]` 中声明的格式化字符串。
///
/// # 使用示例
/// ```rust,ignore
/// use gateway_common::GatewayError;
/// let err: GatewayError = GatewayError::UpstreamTimeout {
///     upstream: "user-service".to_string(),
///     endpoint: "10.0.0.11:8080".to_string(),
/// };
/// assert_eq!(err.code(), ErrorCode::GatewayUpstreamTimeout);
/// assert_eq!(err.to_http_status(), http::StatusCode::GATEWAY_TIMEOUT);
/// ```
#[derive(Debug, Error)]
pub enum GatewayError {
    // ---- 路由/请求类 ---- //
    /// 没有匹配到任何路由（RouteTable 没有 match）
    #[error("route not found for {method} {path}")]
    RouteNotFound {
        /// HTTP 方法，例如 `"GET"`
        method: String,
        /// 原始路径，例如 `"/api/users/42"`
        path: String,
    },

    /// Method 不被允许（Host+Path 匹配成功但 Method 不在路由允许列表里）
    #[error("method {method} not allowed for path {path}")]
    MethodNotAllowed {
        method: String,
        path: String,
        /// 该路径上匹配的 Route 允许的所有 Method（返回给客户端）
        allowed_methods: Vec<String>,
    },

    /// 请求体超过配置的最大值
    #[error("request body too large: {actual} bytes > {limit} bytes")]
    RequestTooLarge {
        /// 实际请求体字节数（如果能确定）
        actual: u64,
        /// 允许的最大字节数
        limit: u64,
    },

    /// 请求本身不合法（URL 格式错误、Header 非法等）
    #[error("bad request: {message}")]
    BadRequest {
        /// 人类可读的错误描述。不能包含敏感信息。
        message: String,
    },

    // ---- 上游类 ---- //
    /// 上游连接超时或响应超时
    #[error("upstream timeout: service={upstream}, endpoint={endpoint}")]
    UpstreamTimeout {
        /// 上游服务名，例如 `"user-service"`
        upstream: String,
        /// 具体端点，例如 `"10.0.0.11:8080"`
        endpoint: String,
    },

    /// 上游连接错误（TCP RST、DNS 解析失败等）
    #[error("upstream connection error: service={upstream}, endpoint={endpoint}, reason={reason}")]
    UpstreamConnectionError {
        upstream: String,
        endpoint: String,
        /// 简短原因，例如 `"connection refused"`、`"dns resolution failed"`
        reason: String,
    },

    /// 所有上游端点都不健康，无法选出实例
    #[error("upstream {upstream} has no healthy endpoints")]
    UpstreamUnavailable { upstream: String },

    /// 上游熔断器打开，拒绝发起新请求
    #[error("circuit breaker open for upstream {upstream}")]
    CircuitOpen { upstream: String },

    // ---- 配置类 ---- //
    /// 配置文件解析或业务校验失败
    #[error("configuration invalid at {path}: {message}")]
    ConfigurationInvalid {
        /// 错误的配置字段路径，例如 `"routes[2].methods"`
        path: String,
        message: String,
    },

    /// 配置编译或原子应用失败
    #[error("configuration apply failed: {message}")]
    ConfigurationApplyFailed { message: String },

    // ---- 资源/运行时类 ---- //
    /// 资源耗尽（连接数、并发数等）
    #[error("resource exhausted: {message}")]
    ResourceExhausted { message: String },

    /// 未知内部错误（兜底；如果走到这里通常是 Bug）
    #[error("internal error: {0}")]
    Internal(String),
}

impl GatewayError {
    /// 把当前错误映射到稳定的 `ErrorCode`。
    /// 此方法是 `GatewayError` → JSON/HTTP 的桥梁。
    pub fn code(&self) -> ErrorCode {
        match self {
            GatewayError::RouteNotFound { .. } => ErrorCode::GatewayRouteNotFound,
            GatewayError::MethodNotAllowed { .. } => ErrorCode::GatewayMethodNotAllowed,
            GatewayError::RequestTooLarge { .. } => ErrorCode::GatewayRequestTooLarge,
            GatewayError::BadRequest { .. } => ErrorCode::GatewayBadRequest,
            GatewayError::UpstreamTimeout { .. } => ErrorCode::GatewayUpstreamTimeout,
            GatewayError::UpstreamConnectionError { .. } => {
                ErrorCode::GatewayUpstreamConnectionError
            },
            GatewayError::UpstreamUnavailable { .. } => ErrorCode::GatewayUpstreamUnavailable,
            GatewayError::CircuitOpen { .. } => ErrorCode::GatewayCircuitOpen,
            GatewayError::ConfigurationInvalid { .. } => ErrorCode::GatewayConfigurationInvalid,
            GatewayError::ConfigurationApplyFailed { .. } => {
                ErrorCode::GatewayConfigurationApplyFailed
            },
            GatewayError::ResourceExhausted { .. } => ErrorCode::GatewayResourceExhausted,
            GatewayError::Internal(_) => ErrorCode::GatewayInternalError,
        }
    }

    /// 把当前错误映射到 HTTP 状态码。
    pub fn to_http_status(&self) -> http::StatusCode {
        self.code().to_http_status()
    }

    /// 生成统一的 `ErrorResponse`，用于 JSON 错误响应。
    /// `request_id` 和 `trace_id` 在请求处理时由调用方注入。
    pub fn to_response(
        &self,
        request_id: Option<String>,
        trace_id: Option<String>,
    ) -> ErrorResponse {
        ErrorResponse {
            code: self.code().as_str().to_string(),
            // 使用 Display（thiserror 自动实现的），获得人类可读消息
            message: self.to_string(),
            request_id,
            trace_id,
        }
    }
}

// ---- 从 anyhow 便捷转换 ---- //
// 业务层可以用 `?` 把 anyhow 错误包装成 GatewayError::Internal。
// 这是最终兜底；任何 crate 在返回 anyhow 之前都应该先映射到更具体的错误。
impl From<anyhow::Error> for GatewayError {
    fn from(err: anyhow::Error) -> Self {
        GatewayError::Internal(err.to_string())
    }
}

// ---------------------------------------------------------------------------
// ErrorResponse —— HTTP JSON 错误响应结构
// ---------------------------------------------------------------------------

/// 统一 JSON 错误响应格式。
///
/// 序列化为：
/// ```json
/// {
///   "code": "GATEWAY_UPSTREAM_TIMEOUT",
///   "message": "upstream timeout: service=user-service, endpoint=10.0.0.11:8080",
///   "request_id": "req-001",
///   "trace_id": "trace-001"
/// }
/// ```
///
/// 注意：`request_id` 和 `trace_id` 是可选字段（`Option<String>`），
/// 当请求上下文里没有对应值时为 `null`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// 稳定的错误码，例如 `"GATEWAY_UPSTREAM_TIMEOUT"`
    pub code: String,
    /// 人类可读的错误描述。严禁包含内部堆栈、密钥等敏感信息。
    pub message: String,
    /// 请求 ID（可选），用于日志关联
    pub request_id: Option<String>,
    /// 分布式追踪 ID（可选）
    pub trace_id: Option<String>,
}

impl ErrorResponse {
    /// 创建一个最基本的错误响应（request_id/trace_id 都为 None）。
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            request_id: None,
            trace_id: None,
        }
    }

    /// 注入 request_id。
    pub fn with_request_id(mut self, id: impl Into<String>) -> Self {
        self.request_id = Some(id.into());
        self
    }

    /// 注入 trace_id。
    pub fn with_trace_id(mut self, id: impl Into<String>) -> Self {
        self.trace_id = Some(id.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_to_http_status() {
        // 需求文档第十一章中约定的映射
        assert_eq!(ErrorCode::GatewayBadRequest.to_http_status(), http::StatusCode::BAD_REQUEST);
        assert_eq!(
            ErrorCode::GatewayAuthenticationFailed.to_http_status(),
            http::StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            ErrorCode::GatewayAuthorizationFailed.to_http_status(),
            http::StatusCode::FORBIDDEN
        );
        assert_eq!(ErrorCode::GatewayRouteNotFound.to_http_status(), http::StatusCode::NOT_FOUND);
        assert_eq!(
            ErrorCode::GatewayMethodNotAllowed.to_http_status(),
            http::StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            ErrorCode::GatewayRequestTooLarge.to_http_status(),
            http::StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            ErrorCode::GatewayRateLimited.to_http_status(),
            http::StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            ErrorCode::GatewayUpstreamUnavailable.to_http_status(),
            http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ErrorCode::GatewayUpstreamTimeout.to_http_status(),
            http::StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(
            ErrorCode::GatewayUpstreamConnectionError.to_http_status(),
            http::StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            ErrorCode::GatewayCircuitOpen.to_http_status(),
            http::StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            ErrorCode::GatewayConfigurationInvalid.to_http_status(),
            http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ErrorCode::GatewayResourceExhausted.to_http_status(),
            http::StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            ErrorCode::GatewayInternalError.to_http_status(),
            http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[test]
    fn error_code_as_str_is_stable() {
        // 字符串必须稳定，因为会暴露到外部 API
        assert_eq!(ErrorCode::GatewayUpstreamTimeout.as_str(), "GATEWAY_UPSTREAM_TIMEOUT");
        assert_eq!(ErrorCode::GatewayRouteNotFound.as_str(), "GATEWAY_ROUTE_NOT_FOUND");
    }

    #[test]
    fn gateway_error_to_response() {
        let err = GatewayError::UpstreamTimeout {
            upstream: "user-service".into(),
            endpoint: "10.0.0.11:8080".into(),
        };
        let resp = err.to_response(Some("req-123".into()), Some("trace-abc".into()));
        assert_eq!(resp.code, "GATEWAY_UPSTREAM_TIMEOUT");
        assert!(resp.message.contains("user-service"));
        assert_eq!(resp.request_id.as_deref(), Some("req-123"));
        assert_eq!(resp.trace_id.as_deref(), Some("trace-abc"));
    }

    #[test]
    fn error_response_serde_roundtrip() {
        let resp = ErrorResponse::new("GATEWAY_BAD_REQUEST", "bad input")
            .with_request_id("req-1")
            .with_trace_id("tr-1");
        let json = serde_json::to_string(&resp).expect("serialize");
        let back: ErrorResponse = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.code, resp.code);
        assert_eq!(back.message, resp.message);
    }
}
