//! User Center：用户资料、联系人、属性、分组与组织中心库。
//!
//! 分层结构：
//! - `api`：HTTP 路由、DTO 与鉴权提取器
//! - `application`：业务用例（用户、联系人、属性、分组、组织、注册、审计）
//! - `domain`：领域模型与事件信封
//! - `auth_client`：访问认证中心的 HTTP 客户端与 JWT 离线校验
//! - `bootstrap`：应用状态、限流与权限校验
//! - `events`：消费认证中心领域事件
//! - `infrastructure`：Redis 与 Transactional Outbox

pub mod api;
pub mod application;
pub mod auth_client;
pub mod bootstrap;
pub mod config;
pub mod domain;
pub mod events;
pub mod infrastructure;
pub mod shared;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
