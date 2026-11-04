//! # gateway-storage
//!
//! 控制面持久化层。
//!
//! ## 职责
//!
//! 1. 定义资源仓储接口 [`GatewayRepository`]
//! 2. 内存实现 [`MemoryRepository`]（测试 / 无数据库模式）
//! 3. PostgreSQL 实现（`postgres` 模块，见 P3.2）
//! 4. 管理配置版本、发布记录与审计日志
//!
//! ## 依赖方向
//!
//! ```text
//! gateway-common / gateway-core
//!              ↑
//!       gateway-storage
//!              ↑
//!   gateway-control-service
//! ```
//!
//! 本 crate **不依赖** gateway-config / gateway-runtime / control-service，
//! 避免形成反向依赖或循环依赖。
//!
//! ## 数据模型
//!
//! 资源表采用"关键列 + JSONB 载荷"的混合模型：`id` / `name` / `enabled` /
//! `version` / 时间戳作为可查询列，完整领域对象保存在 `payload` 中。
//! 详见 [`models`] 模块文档。

#![allow(clippy::needless_doctest_main)]

pub mod error;
pub mod memory;
pub mod models;
pub mod pool;
pub mod postgres;
pub mod repository;

pub use error::StorageError;
pub use memory::MemoryRepository;
pub use models::{
    AuditLogEntry, ConfigVersionRecord, PublishCommit, PublishRecord, PublishStatus, ResourceDraft,
    ResourceKind, ResourceUpdate, StoredResource, VersionStatus,
};
pub use pool::{connect_and_migrate, create_pool, run_migrations, PoolSettings};
pub use postgres::PostgresRepository;
pub use repository::{GatewayRepository, SharedRepository};
