//! Auth Center：认证授权中心库。
//!
//! 分层结构：
//! - `api`：HTTP 路由、DTO 与协议端点
//! - `application`：业务用例（以 `AppState` 方法实现）
//! - `domain`：领域模型
//! - `authorization`：RBAC/ABAC/ReBAC 授权引擎
//! - `infrastructure`：数据库、Redis、通知、Outbox
//! - `security`：密码、JWT、TOTP、WebAuthn、加密
//! - `middleware`：认证、权限、安全响应头

pub mod api;
pub mod application;
pub mod authorization;
pub mod bootstrap;
pub mod config;
pub mod domain;
pub mod infrastructure;
pub mod middleware;
pub mod protocol;
pub mod security;
pub mod shared;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
