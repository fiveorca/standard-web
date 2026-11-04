//! # gateway-control-api
//!
//! 控制面 Admin API（HTTP 适配层）。
//!
//! ## 职责
//!
//! - `/api/admin/v1` 路由
//! - Bearer Token 认证 + 两级 RBAC（`admin` / `viewer`）
//! - DTO 转换与分页
//! - 统一错误 JSON：`{ code, message, request_id, trace_id }`
//!
//! ## 分层约束
//!
//! 本 crate 不包含业务规则（业务规则在 `gateway-control-service`），
//! 也不被 `gateway-runtime` 依赖。集成模式由 `apps/gateway` 把本 crate
//! 的 Router 挂载到管理端口。
//!
//! ## 使用示例
//!
//! ```rust,ignore
//! let state = AdminState::new(config_service, admin_auth);
//! let app = build_admin_router(state);
//! axum::serve(listener, app).await?;
//! ```

#![allow(clippy::needless_doctest_main)]

pub mod auth;
pub mod dto;
pub mod error;
pub mod handlers;
pub mod router;
pub mod state;

#[cfg(test)]
mod tests;

pub use auth::{AdminAuth, Principal, Role};
pub use error::ApiError;
pub use router::{build_admin_router, build_router, ADMIN_API_PREFIX};
pub use state::AdminState;
