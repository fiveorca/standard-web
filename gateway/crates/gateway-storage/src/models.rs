//! 存储模型——资源类型、资源记录、配置版本、发布记录、审计日志。
//!
//! # 为什么资源载荷用 JSONB 而不是逐字段建表
//!
//! 控制面资源（Route / Service / Upstream / 策略 / 插件）的字段结构会随着
//! 阶段演进而变化（Phase 2 引入策略、后续引入插件）。如果每个字段都建列，
//! 每次 Schema 变更都要写迁移，而且大部分字段只在控制面读写、数据面
//! 只在发布时整体读取。
//!
//! 因此采用"关键列 + JSONB 载荷"的混合模型：
//!   - 关键列：`id` / `name` / `enabled` / `version` / 时间戳，
//!     用于唯一约束、列表过滤与索引
//!   - `payload`：完整领域对象（与 YAML 结构一致），由控制面服务在读写时
//!     反序列化为 `gateway_core` 的强类型配置
//!
//! 这样既保留了数据库层的查询能力，又避免为每个配置字段建列的迁移负担。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::StorageError;

// ---------------------------------------------------------------------------
// ResourceKind —— 资源类型
// ---------------------------------------------------------------------------

/// 控制面可管理的资源类型。
///
/// 每个变体对应一张表。API 路径使用连字符命名（例如 `rate-limit-policies`），
/// 数据库表使用下划线命名（例如 `rate_limit_policies`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// 后端服务
    Service,
    /// 上游（含端点列表）
    Upstream,
    /// 路由
    Route,
    /// 消费者（调用方身份）
    Consumer,
    /// 消费者凭据
    ConsumerCredential,
    /// 鉴权策略
    AuthPolicy,
    /// 限流策略
    RateLimitPolicy,
    /// 重试策略
    RetryPolicy,
    /// 熔断策略
    CircuitBreakerPolicy,
    /// 超时策略
    TimeoutPolicy,
    /// CORS 策略
    CorsPolicy,
    /// 请求 Header 转换策略
    RequestTransformPolicy,
    /// 响应 Header 转换策略
    ResponseTransformPolicy,
    /// 插件元信息
    Plugin,
    /// 插件配置
    PluginConfig,
    // ---- Phase 7：平台化资源 ---- //
    /// 租户（多租户隔离）
    Tenant,
    /// TLS 证书
    Certificate,
    /// OpenAPI 规范文档（导入源）
    ApiSpec,
    /// WAF 策略
    WafPolicy,
    /// 配额策略
    QuotaPolicy,
    /// 集群（多集群 / 多地域）
    Cluster,
}

impl ResourceKind {
    /// API 路径中使用的名称（复数、连字符风格）。
    ///
    /// 例如 `"rate-limit-policies"`。控制面 API 的 `{kind}` 路径参数
    /// 通过 [`ResourceKind::from_api_name`] 解析。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Service => "services",
            Self::Upstream => "upstreams",
            Self::Route => "routes",
            Self::Consumer => "consumers",
            Self::ConsumerCredential => "consumer-credentials",
            Self::AuthPolicy => "auth-policies",
            Self::RateLimitPolicy => "rate-limit-policies",
            Self::RetryPolicy => "retry-policies",
            Self::CircuitBreakerPolicy => "circuit-breaker-policies",
            Self::TimeoutPolicy => "timeout-policies",
            Self::CorsPolicy => "cors-policies",
            Self::RequestTransformPolicy => "request-transform-policies",
            Self::ResponseTransformPolicy => "response-transform-policies",
            Self::Plugin => "plugins",
            Self::PluginConfig => "plugin-configs",
            // Phase 7 资源
            Self::Tenant => "tenants",
            Self::Certificate => "certificates",
            Self::ApiSpec => "api-specs",
            Self::WafPolicy => "waf-policies",
            Self::QuotaPolicy => "quota-policies",
            Self::Cluster => "clusters",
        }
    }

    /// 数据库表名（下划线风格）。
    ///
    /// 只在 SQL 拼装时使用；值来自本枚举的常量，绝不会是用户输入，
    /// 因此不存在 SQL 注入风险。
    pub fn table(self) -> &'static str {
        match self {
            Self::Service => "services",
            Self::Upstream => "upstreams",
            Self::Route => "routes",
            Self::Consumer => "consumers",
            Self::ConsumerCredential => "consumer_credentials",
            Self::AuthPolicy => "auth_policies",
            Self::RateLimitPolicy => "rate_limit_policies",
            Self::RetryPolicy => "retry_policies",
            Self::CircuitBreakerPolicy => "circuit_breaker_policies",
            Self::TimeoutPolicy => "timeout_policies",
            Self::CorsPolicy => "cors_policies",
            Self::RequestTransformPolicy => "request_transform_policies",
            Self::ResponseTransformPolicy => "response_transform_policies",
            Self::Plugin => "plugins",
            Self::PluginConfig => "plugin_configs",
            // Phase 7 资源
            Self::Tenant => "tenants",
            Self::Certificate => "certificates",
            Self::ApiSpec => "api_specs",
            Self::WafPolicy => "waf_policies",
            Self::QuotaPolicy => "quota_policies",
            Self::Cluster => "clusters",
        }
    }

    /// 从 API 路径名称解析资源类型。
    ///
    /// 返回 `None` 表示未知类型；控制面 API 会把它映射为 404。
    pub fn from_api_name(name: &str) -> Option<Self> {
        let kind = match name {
            "services" => Self::Service,
            "upstreams" => Self::Upstream,
            "routes" => Self::Route,
            "consumers" => Self::Consumer,
            "consumer-credentials" => Self::ConsumerCredential,
            "auth-policies" => Self::AuthPolicy,
            "rate-limit-policies" => Self::RateLimitPolicy,
            "retry-policies" => Self::RetryPolicy,
            "circuit-breaker-policies" => Self::CircuitBreakerPolicy,
            "timeout-policies" => Self::TimeoutPolicy,
            "cors-policies" => Self::CorsPolicy,
            "request-transform-policies" => Self::RequestTransformPolicy,
            "response-transform-policies" => Self::ResponseTransformPolicy,
            "plugins" => Self::Plugin,
            "plugin-configs" => Self::PluginConfig,
            // Phase 7 资源
            "tenants" => Self::Tenant,
            "certificates" => Self::Certificate,
            "api-specs" => Self::ApiSpec,
            "waf-policies" => Self::WafPolicy,
            "quota-policies" => Self::QuotaPolicy,
            "clusters" => Self::Cluster,
            _ => return None,
        };
        Some(kind)
    }

    /// 所有资源类型（用于发布时全量加载与启动自检）。
    pub fn all() -> [Self; 21] {
        [
            Self::Service,
            Self::Upstream,
            Self::Route,
            Self::Consumer,
            Self::ConsumerCredential,
            Self::AuthPolicy,
            Self::RateLimitPolicy,
            Self::RetryPolicy,
            Self::CircuitBreakerPolicy,
            Self::TimeoutPolicy,
            Self::CorsPolicy,
            Self::RequestTransformPolicy,
            Self::ResponseTransformPolicy,
            Self::Plugin,
            Self::PluginConfig,
            // Phase 7 资源
            Self::Tenant,
            Self::Certificate,
            Self::ApiSpec,
            Self::WafPolicy,
            Self::QuotaPolicy,
            Self::Cluster,
        ]
    }
}

// ---------------------------------------------------------------------------
// 资源记录
// ---------------------------------------------------------------------------

/// 一条已持久化的资源记录。
///
/// 时间字段统一使用 UTC（需求文档第十章第 7 条）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredResource {
    /// 资源 ID（业务主键）
    pub id: String,
    /// 人类可读名称
    pub name: Option<String>,
    /// 是否启用
    pub enabled: bool,
    /// 资源版本号，每次更新 +1（用于乐观锁）
    pub version: i64,
    /// 完整领域对象（JSONB）
    pub payload: Value,
    /// 创建时间（UTC）
    pub created_at: DateTime<Utc>,
    /// 最后更新时间（UTC）
    pub updated_at: DateTime<Utc>,
}

impl StoredResource {
    /// 把 `payload` 反序列化为强类型领域模型。
    ///
    /// 数据库中的 JSON 可能因为历史迁移或人工修改而不符合当前 schema，
    /// 因此这里必须返回错误而不是 panic。
    pub fn decode<T: serde::de::DeserializeOwned>(&self, kind: ResourceKind) -> Result<T, StorageError> {
        serde_json::from_value(self.payload.clone()).map_err(|e| {
            StorageError::invalid_payload(format!(
                "failed to decode {}/{}: {e}",
                kind.as_str(),
                self.id
            ))
        })
    }
}

/// 新建资源时的输入。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceDraft {
    /// 资源 ID（必填，且必须全局唯一于本类型）
    pub id: String,
    /// 人类可读名称
    pub name: Option<String>,
    /// 是否启用
    pub enabled: bool,
    /// 完整领域对象（JSON，结构由控制面服务校验）
    pub payload: Value,
}

/// 更新资源时的输入。
///
/// 所有字段都是 `Option`：`None` 表示保持原值。
/// `payload` 为 `None` 时只更新元信息（name/enabled），不替换配置体。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResourceUpdate {
    /// 新名称；`None` 表示不变
    pub name: Option<String>,
    /// 新启用状态；`None` 表示不变
    pub enabled: Option<bool>,
    /// 新的完整领域对象；`None` 表示保持不变
    pub payload: Option<Value>,
    /// 乐观锁期望版本；`None` 表示不做版本校验
    pub expected_version: Option<i64>,
}

// ---------------------------------------------------------------------------
// 配置版本
// ---------------------------------------------------------------------------

/// 配置版本状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    /// 已发布（当前可用于数据面）
    Published,
    /// 已被更新版本取代（仍保留用于历史查询与回滚）
    Superseded,
    /// 校验失败，不允许发布
    Invalid,
}

impl VersionStatus {
    /// 数据库中的字符串表示。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Superseded => "superseded",
            Self::Invalid => "invalid",
        }
    }

    /// 从数据库字符串解析；未知值按 `Invalid` 处理（保守策略）。
    pub fn from_db(value: &str) -> Self {
        match value {
            "published" => Self::Published,
            "superseded" => Self::Superseded,
            _ => Self::Invalid,
        }
    }
}

/// 一个已保存的配置版本。
///
/// `snapshot` 保存的是**编译后的资源集合**（canonical JSON），
/// 而不是逐表外键。原因：
///   - 回滚只需读取该版本快照并作为新版本重新发布，不受后续资源删除影响
///   - 历史追溯可以看到"发布那一刻"的完整配置
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigVersionRecord {
    /// 单调递增版本号
    pub version: u64,
    /// 快照 checksum（SHA-256）
    pub checksum: String,
    /// 配置 schema 版本（例如 `"v1"`）
    pub schema_version: String,
    /// 版本状态
    pub status: VersionStatus,
    /// 编译后的资源快照（canonical JSON）
    pub snapshot: Value,
    /// 发布者（管理员标识）
    pub created_by: String,
    /// 发布说明
    pub note: Option<String>,
    /// 发布时间（UTC）
    pub created_at: DateTime<Utc>,
}

/// 发布提交（事务内原子写入）。
///
/// 控制面服务完成校验与编译后，用该结构调用
/// [`crate::GatewayRepository::commit_publish`]：
/// 仓储负责分配版本号，并在同一个事务中写入
/// `config_versions` + `audit_logs`。
#[derive(Debug, Clone)]
pub struct PublishCommit {
    /// 校验通过的快照 checksum
    pub checksum: String,
    /// 配置 schema 版本
    pub schema_version: String,
    /// 编译后的资源快照
    pub snapshot: Value,
    /// 发布者
    pub created_by: String,
    /// 备注（例如 "rollback to v12"）
    pub note: Option<String>,
    /// 需要随本次发布一起写入的审计记录（version 字段由仓储填充）
    pub audit: AuditLogEntry,
}

// ---------------------------------------------------------------------------
// 发布记录（分发 / 应用状态）
// ---------------------------------------------------------------------------

/// 一次版本在某个实例上的应用结果。
///
/// 需求文档第十/十七章要求：发布状态与实例应用状态分开记录。
/// 因此 `config_versions` 记录"版本已保存"，`config_publish_records`
/// 记录"某个实例是否应用成功"。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishStatus {
    /// 应用成功
    Applied,
    /// 应用失败（旧配置继续生效）
    Failed,
}

impl PublishStatus {
    /// 数据库中的字符串表示。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::Failed => "failed",
        }
    }

    /// 从数据库字符串解析；未知值按 `Failed` 处理（保守策略）。
    pub fn from_db(value: &str) -> Self {
        match value {
            "applied" => Self::Applied,
            _ => Self::Failed,
        }
    }
}

/// 一条实例应用记录。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublishRecord {
    /// 记录 ID（UUID）
    pub id: String,
    /// 对应配置版本
    pub version: u64,
    /// 版本 checksum（便于核对实例实际应用的内容）
    pub checksum: String,
    /// 应用结果
    pub status: PublishStatus,
    /// 实例标识（integrated 模式为网关实例名）
    pub instance_id: String,
    /// 失败原因（成功时为空）
    pub message: Option<String>,
    /// 记录时间（UTC）
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// 审计日志
// ---------------------------------------------------------------------------

/// 一条配置审计记录。
///
/// 需求文档第十三章第 10 条要求"配置变更必须审计"。
/// 审计只记录"谁在什么时候做了什么"，`detail` 只保存摘要，
/// **不得保存密钥明文**。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditLogEntry {
    /// 记录 ID（UUID）
    pub id: String,
    /// 操作者（管理员 token 的 label，不是 token 本身）
    pub actor: String,
    /// 动作：`create` / `update` / `delete` / `publish` / `rollback`
    pub action: String,
    /// 资源类型（发布类动作为 `config`）
    pub resource_kind: Option<String>,
    /// 资源 ID（发布类动作为空）
    pub resource_id: Option<String>,
    /// 关联配置版本
    pub version: Option<u64>,
    /// 变更摘要（不含密钥）
    pub detail: String,
    /// 记录时间（UTC）
    pub created_at: DateTime<Utc>,
}

impl AuditLogEntry {
    /// 构造一条审计记录（ID 自动生成，时间为当前 UTC）。
    pub fn new(actor: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            actor: actor.into(),
            action: action.into(),
            resource_kind: None,
            resource_id: None,
            version: None,
            detail: String::new(),
            created_at: Utc::now(),
        }
    }

    /// 设置资源类型与资源 ID。
    pub fn with_resource(mut self, kind: ResourceKind, id: impl Into<String>) -> Self {
        self.resource_kind = Some(kind.as_str().to_string());
        self.resource_id = Some(id.into());
        self
    }

    /// 设置变更摘要。
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = detail.into();
        self
    }

    /// 设置关联版本。
    pub fn with_version(mut self, version: u64) -> Self {
        self.version = Some(version);
        self
    }
}
