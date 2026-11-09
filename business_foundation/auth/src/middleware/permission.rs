//! 权限校验中间件。

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::bootstrap::AppState;
use crate::domain::AuthContext;
use crate::shared::AppError;

#[derive(Clone)]
pub struct PermissionGuard {
    pub state: Arc<AppState>,
    pub permission: String,
}

impl PermissionGuard {
    pub fn new(state: Arc<AppState>, permission: impl Into<String>) -> Self {
        Self {
            state,
            permission: permission.into(),
        }
    }
}

/// 管理 API 必须挂载此中间件；默认拒绝，不做任何角色名称硬编码判断。
pub async fn permission_middleware(
    State(guard): State<PermissionGuard>,
    request: Request,
    next: Next,
) -> Response {
    let context = request
        .extensions()
        .get::<Option<AuthContext>>()
        .cloned()
        .flatten();
    let Some(context) = context else {
        return AppError::unauthorized("需要登录后访问").into_response();
    };

    match guard
        .state
        .authz
        .require(context.identity_id, context.tenant_id, &guard.permission)
        .await
    {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}
