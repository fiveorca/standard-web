//! Admin API 请求 / 响应 DTO。
//!
//! 原则：
//!   1. 请求结构只做"HTTP 形状"校验，领域校验在 control-service
//!   2. 响应结构显式列出字段，避免把内部结构（如仓储错误）直接暴露
//!   3. 所有时间字段使用 UTC（chrono 序列化为 RFC3339）

use chrono::{DateTime, Utc};
use gateway_control_service::PublishOutcome;
use gateway_storage::{AuditLogEntry, ConfigVersionRecord, PublishRecord, StoredResource};
use serde::{Deserialize, Serialize};
use serde_json::Value;

// ---------------------------------------------------------------------------
// 资源
// ---------------------------------------------------------------------------

/// 资源响应。
#[derive(Debug, Clone, Serialize)]
pub struct ResourceView {
    /// 资源 ID
    pub id: String,
    /// 名称
    pub name: Option<String>,
    /// 是否启用
    pub enabled: bool,
    /// 资源版本（乐观锁）
    pub version: i64,
    /// 完整配置体
    pub payload: Value,
    /// 创建时间
    pub created_at: DateTime<Utc>,
    /// 更新时间
    pub updated_at: DateTime<Utc>,
}

impl From<StoredResource> for ResourceView {
    fn from(value: StoredResource) -> Self {
        Self {
            id: value.id,
            name: value.name,
            enabled: value.enabled,
            version: value.version,
            payload: value.payload,
            created_at: value.created_at,
            updated_at: value.updated_at,
        }
    }
}

/// 创建资源请求。
#[derive(Debug, Clone, Deserialize)]
pub struct CreateResourceRequest {
    /// 资源 ID
    pub id: String,
    /// 名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用（默认 true）
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 完整配置体（必须包含 id 字段且与资源 ID 一致）
    pub payload: Value,
}

/// 更新资源请求。
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateResourceRequest {
    /// 新名称
    #[serde(default)]
    pub name: Option<String>,
    /// 新启用状态
    #[serde(default)]
    pub enabled: Option<bool>,
    /// 新配置体
    #[serde(default)]
    pub payload: Option<Value>,
    /// 乐观锁期望版本
    #[serde(default)]
    pub expected_version: Option<i64>,
}

/// 删除资源时的查询参数。
#[derive(Debug, Clone, Deserialize)]
pub struct DeleteQuery {
    /// 乐观锁期望版本
    #[serde(default)]
    pub expected_version: Option<i64>,
}

// ---------------------------------------------------------------------------
// 分页
// ---------------------------------------------------------------------------

/// 分页查询参数。
#[derive(Debug, Clone, Default, Deserialize)]
pub struct PageQuery {
    /// 每页条数（默认 50，最大 200）
    #[serde(default)]
    pub limit: Option<usize>,
    /// 偏移量（默认 0）
    #[serde(default)]
    pub offset: Option<usize>,
    /// 按配置版本过滤（审计日志 / 应用记录使用）
    #[serde(default)]
    pub version: Option<u64>,
}

impl PageQuery {
    /// 生效的每页条数。
    pub fn limit(&self) -> usize {
        self.limit.unwrap_or(50)
    }

    /// 生效的偏移量。
    pub fn offset(&self) -> usize {
        self.offset.unwrap_or(0)
    }
}

/// 分页响应。
#[derive(Debug, Clone, Serialize)]
pub struct PageView<T> {
    /// 当前页数据
    pub items: Vec<T>,
    /// 总条数（部分查询无法高效统计，返回 0 表示未知）
    pub total: u64,
    /// 每页条数
    pub limit: usize,
    /// 偏移量
    pub offset: usize,
}

impl<T> PageView<T> {
    /// 构造分页响应。
    pub fn new(items: Vec<T>, total: u64, limit: usize, offset: usize) -> Self {
        Self {
            items,
            total,
            limit,
            offset,
        }
    }
}

// ---------------------------------------------------------------------------
// 发布 / 回滚
// ---------------------------------------------------------------------------

/// 发布请求。
#[derive(Debug, Clone, Deserialize)]
pub struct PublishRequest {
    /// 发布说明
    #[serde(default)]
    pub note: Option<String>,
}

/// 发布 / 回滚响应。
#[derive(Debug, Clone, Serialize)]
pub struct PublishView {
    /// 新版本号
    pub version: u64,
    /// checksum
    pub checksum: String,
    /// 是否已在数据面生效
    pub applied: bool,
    /// 应用失败原因
    pub apply_error: Option<String>,
    /// 备注
    pub note: Option<String>,
    /// 发布时间
    pub created_at: DateTime<Utc>,
}

impl From<PublishOutcome> for PublishView {
    fn from(value: PublishOutcome) -> Self {
        Self {
            version: value.version,
            checksum: value.checksum,
            applied: value.applied,
            apply_error: value.apply_error,
            note: value.note,
            created_at: value.created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// 版本 / 审计 / 应用记录
// ---------------------------------------------------------------------------

/// 配置版本响应（不含完整快照，避免响应过大）。
#[derive(Debug, Clone, Serialize)]
pub struct VersionView {
    /// 版本号
    pub version: u64,
    /// checksum
    pub checksum: String,
    /// schema 版本
    pub schema_version: String,
    /// 状态
    pub status: String,
    /// 发布者
    pub created_by: String,
    /// 备注
    pub note: Option<String>,
    /// 发布时间
    pub created_at: DateTime<Utc>,
}

impl From<ConfigVersionRecord> for VersionView {
    fn from(value: ConfigVersionRecord) -> Self {
        Self {
            version: value.version,
            checksum: value.checksum,
            schema_version: value.schema_version,
            status: value.status.as_str().to_string(),
            created_by: value.created_by,
            note: value.note,
            created_at: value.created_at,
        }
    }
}

/// 当前已发布配置（`GET /config`）。
#[derive(Debug, Clone, Serialize)]
pub struct CurrentConfigView {
    /// 版本号
    pub version: u64,
    /// checksum
    pub checksum: String,
    /// schema 版本
    pub schema_version: String,
    /// 资源集合快照（ResourceBundle 的 JSON 形式）
    pub resources: Value,
}

impl From<ConfigVersionRecord> for CurrentConfigView {
    fn from(value: ConfigVersionRecord) -> Self {
        Self {
            version: value.version,
            checksum: value.checksum,
            schema_version: value.schema_version,
            resources: value.snapshot,
        }
    }
}

/// 审计日志响应。
#[derive(Debug, Clone, Serialize)]
pub struct AuditLogView {
    /// 记录 ID
    pub id: String,
    /// 操作者
    pub actor: String,
    /// 动作
    pub action: String,
    /// 资源类型
    pub resource_kind: Option<String>,
    /// 资源 ID
    pub resource_id: Option<String>,
    /// 关联版本
    pub version: Option<u64>,
    /// 摘要
    pub detail: String,
    /// 时间
    pub created_at: DateTime<Utc>,
}

impl From<AuditLogEntry> for AuditLogView {
    fn from(value: AuditLogEntry) -> Self {
        Self {
            id: value.id,
            actor: value.actor,
            action: value.action,
            resource_kind: value.resource_kind,
            resource_id: value.resource_id,
            version: value.version,
            detail: value.detail,
            created_at: value.created_at,
        }
    }
}

/// 实例应用记录响应。
#[derive(Debug, Clone, Serialize)]
pub struct PublishRecordView {
    /// 记录 ID
    pub id: String,
    /// 版本号
    pub version: u64,
    /// checksum
    pub checksum: String,
    /// 应用状态
    pub status: String,
    /// 实例标识
    pub instance_id: String,
    /// 失败原因
    pub message: Option<String>,
    /// 时间
    pub created_at: DateTime<Utc>,
}

impl From<PublishRecord> for PublishRecordView {
    fn from(value: PublishRecord) -> Self {
        Self {
            id: value.id,
            version: value.version,
            checksum: value.checksum,
            status: value.status.as_str().to_string(),
            instance_id: value.instance_id,
            message: value.message,
            created_at: value.created_at,
        }
    }
}

// ---------------------------------------------------------------------------
// 状态 / 健康检查
// ---------------------------------------------------------------------------

/// 控制面状态。
#[derive(Debug, Clone, Serialize)]
pub struct StatusView {
    /// 服务标识
    pub service: &'static str,
    /// 当前最新版本号（从未发布时为 null）
    pub published_version: Option<u64>,
    /// 最新版本 checksum
    pub published_checksum: Option<String>,
    /// 是否已经有可用配置
    pub has_configuration: bool,
}

/// 健康检查响应。
#[derive(Debug, Clone, Serialize)]
pub struct HealthView {
    /// 固定为 `"ok"`
    pub status: &'static str,
}

fn default_true() -> bool {
    true
}
