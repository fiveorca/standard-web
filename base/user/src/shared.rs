//! 通用错误、响应与工具函数。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

pub type AppResult<T> = Result<T, AppError>;

pub const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(1);

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{message}")]
    Client {
        status: StatusCode,
        code: &'static str,
        message: String,
        details: Option<serde_json::Value>,
    },
    #[error("{0}")]
    Internal(String),
}

impl AppError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::Client {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: message.into(),
            details: None,
        }
    }

    pub fn validation(field: &str, message: impl Into<String>) -> Self {
        Self::Client {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            code: "validation_failed",
            message: message.into(),
            details: Some(json!({ "field": field })),
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self::Client {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: message.into(),
            details: None,
        }
    }

    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::Client {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: message.into(),
            details: None,
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::Client {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: message.into(),
            details: None,
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Client {
            status: StatusCode::CONFLICT,
            code: "conflict",
            message: message.into(),
            details: None,
        }
    }

    pub fn server_error(message: impl Into<String>) -> Self {
        Self::Internal(message.into())
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::Client { status, .. } => *status,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(error: sqlx::Error) -> Self {
        tracing::error!(error = %error, "数据库操作失败");
        Self::Internal("数据库操作失败".to_string())
    }
}

impl From<reqwest::Error> for AppError {
    fn from(error: reqwest::Error) -> Self {
        tracing::error!(error = %error, "外部请求失败");
        Self::Internal("依赖服务请求失败".to_string())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            Self::Client {
                status,
                code,
                message,
                details,
            } => {
                let body = match details {
                    Some(details) => json!({
                        "code": code,
                        "message": message,
                        "details": details,
                    }),
                    None => json!({ "code": code, "message": message }),
                };
                (status, Json(body)).into_response()
            }
            Self::Internal(message) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "code": "internal_error", "message": message })),
            )
                .into_response(),
        }
    }
}

pub fn ok(data: serde_json::Value) -> Json<serde_json::Value> {
    Json(json!({ "code": "ok", "data": data }))
}

pub fn empty() -> Json<serde_json::Value> {
    Json(json!({ "code": "ok", "data": null }))
}

#[derive(Debug, Clone, Copy, Deserialize)]
pub struct PageQuery {
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub page_size: Option<u32>,
}

impl Default for PageQuery {
    fn default() -> Self {
        Self {
            page: None,
            page_size: None,
        }
    }
}

impl PageQuery {
    pub fn page(&self) -> u32 {
        self.page.unwrap_or(1).max(1)
    }

    pub fn page_size(&self) -> u32 {
        self.page_size.unwrap_or(20).clamp(1, 200)
    }

    pub fn limit(&self) -> i64 {
        self.page_size() as i64
    }

    pub fn offset(&self) -> i64 {
        ((self.page() - 1) * self.page_size()) as i64
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub total: i64,
    pub page: u32,
    pub page_size: u32,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, total: i64, query: &PageQuery) -> Self {
        Self {
            items,
            total,
            page: query.page(),
            page_size: query.page_size(),
        }
    }
}

/// 请求元数据。
#[derive(Debug, Clone, Default)]
pub struct RequestMeta {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub trace_id: Option<String>,
}

impl RequestMeta {
    pub fn new(ip: Option<String>, user_agent: Option<String>, trace_id: Option<String>) -> Self {
        Self {
            ip,
            user_agent,
            trace_id,
        }
    }
}

// ───────────────────────── 工具 ─────────────────────────

pub fn normalize_email(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn normalize_phone(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '+')
        .collect()
}

pub fn normalize_username(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

pub fn is_valid_email(value: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")
            .unwrap_or_else(|_| unreachable!())
    });
    value.len() <= 254 && re.is_match(value)
}

pub fn is_valid_phone(value: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE
        .get_or_init(|| regex::Regex::new(r"^\+?[0-9]{6,20}$").unwrap_or_else(|_| unreachable!()));
    re.is_match(value)
}

pub fn is_valid_username(value: &str) -> bool {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        regex::Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$").unwrap_or_else(|_| unreachable!())
    });
    re.is_match(value)
}

pub fn mask_email(value: &str) -> String {
    match value.split_once('@') {
        Some((local, domain)) if !local.is_empty() => {
            let head: String = local.chars().take(1).collect();
            format!("{head}***@{domain}")
        }
        _ => "***".to_string(),
    }
}

pub fn mask_phone(value: &str) -> String {
    let digits: Vec<char> = value.chars().collect();
    if digits.len() <= 4 {
        return "****".to_string();
    }
    let head: String = digits.iter().take(3).collect();
    let tail: String = digits.iter().skip(digits.len() - 4).collect();
    format!("{head}****{tail}")
}

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    constant_time_eq::constant_time_eq(a, b)
}

pub fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

pub fn parse_uuid(value: &str, field: &str) -> AppResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| AppError::validation(field, "ID 格式不合法"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_identifiers() {
        assert_eq!(normalize_email("  Foo@Example.COM "), "foo@example.com");
        assert_eq!(normalize_phone("+86 138-0013-8000"), "+8613800138000");
        assert_eq!(normalize_username(" Alice "), "alice");
    }

    #[test]
    fn validates_emails_and_phones() {
        assert!(is_valid_email("user@example.com"));
        assert!(!is_valid_email("user@@example.com"));
        assert!(!is_valid_email("not-an-email"));
        assert!(is_valid_phone("+8613800138000"));
        assert!(!is_valid_phone("123"));
        assert!(is_valid_username("alice_01"));
        assert!(!is_valid_username("_alice"));
    }

    #[test]
    fn masks_contact_values() {
        assert_eq!(mask_email("alice@example.com"), "a***@example.com");
        assert_eq!(mask_phone("+8613800138000"), "+86****8000");
        assert_eq!(mask_phone("123"), "****");
    }

    #[test]
    fn pagination_is_bounded() {
        let query = PageQuery {
            page: Some(0),
            page_size: Some(10_000),
        };
        assert_eq!(query.page(), 1);
        assert_eq!(query.page_size(), 200);
        assert_eq!(query.limit(), 200);
        assert_eq!(query.offset(), 0);

        let query = PageQuery {
            page: Some(3),
            page_size: Some(20),
        };
        assert_eq!(query.offset(), 40);
    }

    #[test]
    fn constant_time_comparison_matches() {
        assert!(constant_time_eq(b"secret-token", b"secret-token"));
        assert!(!constant_time_eq(b"secret-token", b"secret-tokeN"));
    }
}
