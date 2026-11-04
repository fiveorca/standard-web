//! # gateway-control-service
//!
//! 控制面业务服务层。
//!
//! ## 职责
//!
//! - 资源 CRUD（写操作自动审计）
//! - 发布配置：全量加载 → 校验 → 编译 → 原子落库 → 应用快照
//! - 回滚：历史快照作为新版本重新发布
//! - 版本 / 审计 / 实例应用记录查询
//!
//! ## 层次
//!
//! ```text
//! gateway-control-api（HTTP / DTO / RBAC）
//!              ↓
//! gateway-control-service（本 crate：业务规则与事务边界）
//!              ↓
//! gateway-config（校验 / 编译）  gateway-storage（持久化）
//! ```
//!
//! 本 crate 不依赖 `gateway-runtime`：快照应用通过
//! [`SnapshotApplier`] 回调注入，避免控制面与数据面耦合。

#![allow(clippy::needless_doctest_main)]

pub mod applier;
pub mod error;
pub mod service;

#[cfg(test)]
mod tests;

pub use applier::SnapshotApplier;
pub use error::ControlError;
pub use service::{
    format_validation_errors, CompilePreview, ConfigService, Page, PublishOutcome, ResourceCounts,
    ValidationErrorView, ValidationReport,
};
