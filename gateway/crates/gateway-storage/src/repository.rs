//! 仓储接口（GatewayRepository）。
//!
//! # 设计目标
//!
//! 数据面不能对 PostgreSQL 形成运行时强依赖（需求文档 18.3 第 4 条），
//! 控制面也必须能在没有数据库的环境下做单元测试。因此把所有持久化
//! 操作收敛到一个 trait：
//!   - `MemoryRepository`：进程内实现，支撑全部测试与单机模式
//!   - `PostgresRepository`：生产实现（SQLx 运行时查询）
//!
//! # 为什么用 `Arc<dyn GatewayRepository>` 而不是泛型
//!
//! 控制面服务需要被 Axum handler 共享（`State` 必须 `Clone + Send + Sync`）。
//! 使用 trait object 可以避免把泛型一路传染到 Router 与 handler 的签名里。

use async_trait::async_trait;

use crate::error::StorageError;
use crate::models::{
    AuditLogEntry, ConfigVersionRecord, PublishCommit, PublishRecord, ResourceDraft, ResourceKind,
    ResourceUpdate, StoredResource,
};

/// 控制面仓储接口。
///
/// 所有方法都是异步的；实现者必须保证：
///   1. 单条资源读写是原子的
///   2. [`GatewayRepository::commit_publish`] 在同一事务内完成
///      "分配版本号 + 写版本记录 + 写审计记录"
///   3. 列表查询按 `id` 升序（便于分页结果稳定）
#[async_trait]
pub trait GatewayRepository: Send + Sync {
    // -----------------------------------------------------------------
    // 资源 CRUD
    // -----------------------------------------------------------------

    /// 分页列出某类资源（按 `id` 升序）。
    async fn list_resources(
        &self,
        kind: ResourceKind,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredResource>, StorageError>;

    /// 列出某类资源的全部记录（发布时全量加载使用）。
    async fn list_all_resources(
        &self,
        kind: ResourceKind,
    ) -> Result<Vec<StoredResource>, StorageError>;

    /// 统计某类资源总数（分页响应使用）。
    async fn count_resources(&self, kind: ResourceKind) -> Result<u64, StorageError>;

    /// 按 ID 查询单条资源。
    async fn get_resource(
        &self,
        kind: ResourceKind,
        id: &str,
    ) -> Result<Option<StoredResource>, StorageError>;

    /// 创建资源；ID 已存在时返回 [`StorageError::Conflict`]。
    async fn create_resource(
        &self,
        kind: ResourceKind,
        draft: ResourceDraft,
    ) -> Result<StoredResource, StorageError>;

    /// 更新资源；不存在返回 `NotFound`，版本不匹配返回 `VersionConflict`。
    ///
    /// 更新成功后 `version` 自增 1 并刷新 `updated_at`。
    async fn update_resource(
        &self,
        kind: ResourceKind,
        id: &str,
        update: ResourceUpdate,
    ) -> Result<StoredResource, StorageError>;

    /// 删除资源；不存在返回 `NotFound`，版本不匹配返回 `VersionConflict`。
    async fn delete_resource(
        &self,
        kind: ResourceKind,
        id: &str,
        expected_version: Option<i64>,
    ) -> Result<(), StorageError>;

    // -----------------------------------------------------------------
    // 审计
    // -----------------------------------------------------------------

    /// 追加一条审计记录（非发布类操作使用）。
    async fn append_audit(&self, entry: AuditLogEntry) -> Result<(), StorageError>;

    /// 分页查询审计日志（按时间倒序）。
    ///
    /// `version` 为 `Some(v)` 时只返回关联该版本的记录。
    async fn list_audit_logs(
        &self,
        version: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AuditLogEntry>, StorageError>;

    // -----------------------------------------------------------------
    // 配置版本与发布
    // -----------------------------------------------------------------

    /// 原子提交一次发布。
    ///
    /// 实现必须在**同一个事务**中完成：
    ///   1. 计算新版本号（`MAX(version) + 1`）
    ///   2. 把上一个 `Published` 版本标记为 `Superseded`
    ///   3. 写入新版本记录（status = `published`）
    ///   4. 写入审计记录（审计 entry 的 `version` 由实现填充）
    ///
    /// 返回分配后的版本记录。
    async fn commit_publish(
        &self,
        commit: PublishCommit,
    ) -> Result<ConfigVersionRecord, StorageError>;

    /// 读取最新版本（按版本号倒序取第一条）。
    async fn latest_version(&self) -> Result<Option<ConfigVersionRecord>, StorageError>;

    /// 按版本号读取历史版本。
    async fn get_version(&self, version: u64) -> Result<Option<ConfigVersionRecord>, StorageError>;

    /// 分页列出历史版本（按版本号倒序）。
    async fn list_versions(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ConfigVersionRecord>, StorageError>;

    /// 记录一次实例应用结果（发布状态与实例应用状态分开记录）。
    async fn record_publish(&self, record: PublishRecord) -> Result<(), StorageError>;

    /// 分页列出实例应用记录（按时间倒序）。
    async fn list_publish_records(
        &self,
        version: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<PublishRecord>, StorageError>;
}

/// 共享仓储句柄的别名。
pub type SharedRepository = std::sync::Arc<dyn GatewayRepository>;
