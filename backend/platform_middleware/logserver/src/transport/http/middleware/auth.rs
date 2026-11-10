// ! HTTP 认证中间件 (简化版，生产对接统一认证中心)

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// 认证后的请求上下文
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub tenant_id: String,
    pub service_name: String,
}

/// 从 HTTP header 中抽取认证上下文
///
/// 生产环境应该对接统一认证中心 (如 gateway 已鉴权后注入 header / JWT)
pub struct Authenticated(pub AuthContext);

impl<S> FromRequestParts<S> for Authenticated
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let tenant_id = parts
            .headers
            .get("X-Tenant-Id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "default".into());

        let service_name = parts
            .headers
            .get("X-Service-Name")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "unknown".into());

        Ok(Authenticated(AuthContext {
            tenant_id,
            service_name,
        }))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("未授权请求")]
    Unauthorized,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let body = serde_json::json!({"error": self.to_string()});
        (StatusCode::UNAUTHORIZED, axum::Json(body)).into_response()
    }
}
