//! 控制面业务服务（ConfigService）。
//!
//! # 核心流程
//!
//! ```text
//! CRUD：校验单资源结构 → 写库 → 写审计
//!
//! 发布：
//!   全量加载资源 → 装配 ResourceBundle → validate()
//!       → checksum → commit_publish(版本+审计，单事务)
//!       → SnapshotApplier 应用到数据面 → 记录实例应用结果
//!
//! 回滚：
//!   读取历史版本 snapshot → 校验 checksum → 构造 ResourceBundle
//!       → 走与发布完全相同的流程（版本号继续递增）
//! ```
//!
//! # 关键约束
//!
//! - 校验失败不得写任何版本；旧版本继续有效
//! - 应用失败不删除已保存版本（需求文档第十章）
//! - 审计 detail 只保存摘要，绝不保存密钥明文

use std::sync::Arc;

use chrono::Utc;
use gateway_config::{
    CompiledSnapshot, ConfigError, PoliciesConfig, ResourceBundle, SCHEMA_VERSION,
};
use gateway_core::{
    AuthPolicyConfig, CircuitBreakerPolicyConfig, CorsPolicyConfig, RateLimitPolicyConfig,
    RetryPolicyConfig, RouteConfig, ServiceConfig, TimeoutPolicyConfig, TransformPolicyConfig,
    UpstreamConfig,
};
use gateway_storage::{
    AuditLogEntry, ConfigVersionRecord, PublishCommit, PublishRecord, PublishStatus, ResourceDraft,
    ResourceKind, ResourceUpdate, SharedRepository, StorageError, StoredResource,
};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::applier::SnapshotApplier;
use crate::error::ControlError;

/// 单页最大条数，防止一次查询把内存打爆。
const MAX_PAGE_SIZE: usize = 200;

// ---------------------------------------------------------------------------
// 分页与结果结构
// ---------------------------------------------------------------------------

/// 通用分页结果。
#[derive(Debug, Clone, Serialize)]
pub struct Page<T> {
    /// 当前页数据
    pub items: Vec<T>,
    /// 总条数
    pub total: u64,
    /// 实际生效的每页条数
    pub limit: usize,
    /// 偏移量
    pub offset: usize,
}

/// 发布 / 回滚结果。
#[derive(Debug, Clone, Serialize)]
pub struct PublishOutcome {
    /// 新分配的版本号
    pub version: u64,
    /// 快照 checksum
    pub checksum: String,
    /// 是否已在数据面生效
    pub applied: bool,
    /// 应用失败原因（`applied = false` 且注入了 applier 时可能非空）
    pub apply_error: Option<String>,
    /// 发布说明
    pub note: Option<String>,
    /// 发布时间（UTC）
    pub created_at: chrono::DateTime<Utc>,
}

/// 配置校验报告（发布前 dry-run）。
#[derive(Debug, Clone, Serialize)]
pub struct ValidationReport {
    /// 是否通过
    pub valid: bool,
    /// 校验错误列表
    pub errors: Vec<ValidationErrorView>,
    /// 校验通过时的 checksum
    pub checksum: Option<String>,
    /// 资源数量统计
    pub resource_counts: ResourceCounts,
}

/// 校验错误的可序列化视图（避免直接暴露内部类型）。
#[derive(Debug, Clone, Serialize)]
pub struct ValidationErrorView {
    /// 字段路径，例如 `"routes[2].methods"`
    pub path: String,
    /// 错误描述
    pub message: String,
}

/// 编译预览结果（`POST /config/compile`）。
///
/// 与发布流程共用的校验/checksum 逻辑，但不写版本、不应用数据面，
/// 便于调用方在真正发布前查看将要下发的快照。
#[derive(Debug, Clone, Serialize)]
pub struct CompilePreview {
    /// 预计分配的版本号（当前最新版本 + 1；从未发布时为 1）
    pub version: u64,
    /// 快照 checksum
    pub checksum: String,
    /// schema 版本
    pub schema_version: String,
    /// 编译后的快照（可直接下发给数据面）
    pub snapshot: Value,
}

/// 资源数量统计。
#[derive(Debug, Clone, Serialize)]
pub struct ResourceCounts {
    /// 路由数量
    pub routes: usize,
    /// 服务数量
    pub services: usize,
    /// 上游数量
    pub upstreams: usize,
    /// 策略数量（所有类型合计）
    pub policies: usize,
}

// ---------------------------------------------------------------------------
// ConfigService
// ---------------------------------------------------------------------------

/// 控制面业务服务。
///
/// 该结构体是 `Clone` 的（内部都是 `Arc`），可以直接放进 Axum `State`。
#[derive(Clone)]
pub struct ConfigService {
    /// 仓储
    repo: SharedRepository,
    /// 可选的快照应用回调（集成模式注入）
    applier: Option<Arc<dyn SnapshotApplier>>,
    /// 实例标识（写入发布记录）
    instance_id: String,
}

impl ConfigService {
    /// 创建服务（独立控制面模式：发布只落库，不直接应用到数据面）。
    pub fn new(repo: SharedRepository) -> Self {
        Self {
            repo,
            applier: None,
            instance_id: "control-plane".to_string(),
        }
    }

    /// 创建服务并注入快照应用回调（integrated 模式）。
    pub fn with_applier(
        repo: SharedRepository,
        applier: Arc<dyn SnapshotApplier>,
        instance_id: impl Into<String>,
    ) -> Self {
        Self {
            repo,
            applier: Some(applier),
            instance_id: instance_id.into(),
        }
    }

    /// 只读访问仓储（API 层做版本查询等）。
    pub fn repository(&self) -> &SharedRepository {
        &self.repo
    }

    // -----------------------------------------------------------------
    // 资源 CRUD
    // -----------------------------------------------------------------

    /// 分页列出资源。
    pub async fn list_resources(
        &self,
        kind: ResourceKind,
        limit: usize,
        offset: usize,
    ) -> Result<Page<StoredResource>, ControlError> {
        let limit = limit.clamp(1, MAX_PAGE_SIZE);
        let total = self
            .repo
            .count_resources(kind)
            .await
            .map_err(map_storage_error)?;
        let items = self
            .repo
            .list_resources(kind, limit, offset)
            .await
            .map_err(map_storage_error)?;
        Ok(Page {
            items,
            total,
            limit,
            offset,
        })
    }

    /// 按 ID 查询资源。
    pub async fn get_resource(
        &self,
        kind: ResourceKind,
        id: &str,
    ) -> Result<StoredResource, ControlError> {
        self.repo
            .get_resource(kind, id)
            .await
            .map_err(map_storage_error)?
            .ok_or_else(|| ControlError::not_found(kind.as_str(), id))
    }

    /// 创建资源并写审计。
    pub async fn create_resource(
        &self,
        kind: ResourceKind,
        draft: ResourceDraft,
        actor: &str,
    ) -> Result<StoredResource, ControlError> {
        validate_payload(kind, &draft.payload, Some(&draft.id))?;
        let created = self
            .repo
            .create_resource(kind, draft)
            .await
            .map_err(map_storage_error)?;

        self.append_audit(
            AuditLogEntry::new(actor, "create")
                .with_resource(kind, created.id.clone())
                .with_detail(format!("created {} '{}'", kind.as_str(), created.id)),
        )
        .await?;

        Ok(created)
    }

    /// 更新资源并写审计。
    pub async fn update_resource(
        &self,
        kind: ResourceKind,
        id: &str,
        update: ResourceUpdate,
        actor: &str,
    ) -> Result<StoredResource, ControlError> {
        if update.name.is_none() && update.enabled.is_none() && update.payload.is_none() {
            return Err(ControlError::invalid_request("nothing to update"));
        }
        if let Some(payload) = &update.payload {
            validate_payload(kind, payload, Some(id))?;
        }

        let updated = self
            .repo
            .update_resource(kind, id, update)
            .await
            .map_err(map_storage_error)?;

        self.append_audit(
            AuditLogEntry::new(actor, "update")
                .with_resource(kind, updated.id.clone())
                .with_detail(format!(
                    "updated {} '{}' to resource version {}",
                    kind.as_str(),
                    updated.id,
                    updated.version
                )),
        )
        .await?;

        Ok(updated)
    }

    /// 删除资源并写审计。
    pub async fn delete_resource(
        &self,
        kind: ResourceKind,
        id: &str,
        expected_version: Option<i64>,
        actor: &str,
    ) -> Result<(), ControlError> {
        self.repo
            .delete_resource(kind, id, expected_version)
            .await
            .map_err(map_storage_error)?;

        self.append_audit(
            AuditLogEntry::new(actor, "delete")
                .with_resource(kind, id)
                .with_detail(format!("deleted {} '{}'", kind.as_str(), id)),
        )
        .await?;

        Ok(())
    }

    // -----------------------------------------------------------------
    // 校验与发布
    // -----------------------------------------------------------------

    /// 全量加载资源并装配成 [`ResourceBundle`]。
    ///
    /// 关键点：资源表的 `enabled` / `name` / `id` 列会覆盖 payload 中的同名字段，
    /// 保证"禁用某条资源"的语义在发布时生效。
    pub async fn load_bundle(&self) -> Result<ResourceBundle, ControlError> {
        let routes = self.load_typed::<RouteConfig>(ResourceKind::Route).await?;
        let services = self.load_typed::<ServiceConfig>(ResourceKind::Service).await?;
        let upstreams = self.load_typed::<UpstreamConfig>(ResourceKind::Upstream).await?;

        let auth = self.load_typed::<AuthPolicyConfig>(ResourceKind::AuthPolicy).await?;
        let rate_limit = self
            .load_typed::<RateLimitPolicyConfig>(ResourceKind::RateLimitPolicy)
            .await?;
        let timeout = self
            .load_typed::<TimeoutPolicyConfig>(ResourceKind::TimeoutPolicy)
            .await?;
        let retry = self.load_typed::<RetryPolicyConfig>(ResourceKind::RetryPolicy).await?;
        let circuit_breaker = self
            .load_typed::<CircuitBreakerPolicyConfig>(ResourceKind::CircuitBreakerPolicy)
            .await?;
        let cors = self.load_typed::<CorsPolicyConfig>(ResourceKind::CorsPolicy).await?;
        let request_transform = self
            .load_typed::<TransformPolicyConfig>(ResourceKind::RequestTransformPolicy)
            .await?;
        let response_transform = self
            .load_typed::<TransformPolicyConfig>(ResourceKind::ResponseTransformPolicy)
            .await?;

        Ok(ResourceBundle {
            routes,
            services,
            upstreams,
            policies: PoliciesConfig {
                auth,
                rate_limit,
                timeout,
                retry,
                circuit_breaker,
                cors,
                request_transform,
                response_transform,
            },
        }
        .canonicalized())
    }

    /// 发布前 dry-run 校验。
    pub async fn validate(&self) -> Result<ValidationReport, ControlError> {
        let bundle = self.load_bundle().await?;
        let counts = ResourceCounts {
            routes: bundle.routes.len(),
            services: bundle.services.len(),
            upstreams: bundle.upstreams.len(),
            policies: bundle.policies.auth.len()
                + bundle.policies.rate_limit.len()
                + bundle.policies.timeout.len()
                + bundle.policies.retry.len()
                + bundle.policies.circuit_breaker.len()
                + bundle.policies.cors.len()
                + bundle.policies.request_transform.len()
                + bundle.policies.response_transform.len(),
        };

        match bundle.validate() {
            Ok(()) => Ok(ValidationReport {
                valid: true,
                errors: Vec::new(),
                checksum: bundle.checksum().ok(),
                resource_counts: counts,
            }),
            Err(errors) => Ok(ValidationReport {
                valid: false,
                errors: errors
                    .into_iter()
                    .map(|e| ValidationErrorView {
                        path: e.path,
                        message: e.message,
                    })
                    .collect(),
                checksum: None,
                resource_counts: counts,
            }),
        }
    }

    /// 编译预览：校验通过后返回将要下发的快照，但不写版本、不应用。
    pub async fn compile(&self) -> Result<CompilePreview, ControlError> {
        let bundle = self.load_bundle().await?;
        // 与发布共用同一套校验：失败时返回校验错误，不生成快照
        bundle
            .validate()
            .map_err(|errors| ControlError::Validation { errors })?;

        let checksum = bundle.checksum()?;
        // 版本号由仓储在 commit 时分配，这里只做"预演"
        let version = self
            .repo
            .latest_version()
            .await
            .map_err(map_storage_error)?
            .map(|v| v.version + 1)
            .unwrap_or(1);

        let snapshot = CompiledSnapshot {
            schema_version: SCHEMA_VERSION.to_string(),
            config_version: version,
            checksum: checksum.clone(),
            bundle,
        };
        let snapshot_json = snapshot.to_json().map_err(|e| ControlError::InvalidPayload {
            message: format!("failed to serialize snapshot: {e}"),
        })?;

        Ok(CompilePreview {
            version,
            checksum,
            schema_version: SCHEMA_VERSION.to_string(),
            snapshot: snapshot_json,
        })
    }

    /// 发布当前资源集合。
    pub async fn publish(
        &self,
        actor: &str,
        note: Option<String>,
    ) -> Result<PublishOutcome, ControlError> {
        let bundle = self.load_bundle().await?;
        self.publish_bundle(bundle, actor, note, "publish").await
    }

    /// 回滚到历史版本。
    ///
    /// 回滚不是"删除新版本"，而是把历史快照作为**新版本**重新发布，
    /// 保证版本号单调递增（需求文档第十七章）。
    pub async fn rollback(
        &self,
        target_version: u64,
        actor: &str,
        note: Option<String>,
    ) -> Result<PublishOutcome, ControlError> {
        let target = self
            .repo
            .get_version(target_version)
            .await
            .map_err(map_storage_error)?
            .ok_or_else(|| ControlError::not_found("config-versions", &target_version.to_string()))?;

        let bundle: ResourceBundle =
            serde_json::from_value(target.snapshot).map_err(|e| {
                ControlError::invalid_payload(format!(
                    "version {target_version} snapshot is not a valid resource bundle: {e}"
                ))
            })?;

        // 完整性校验：历史快照的 checksum 必须仍然匹配
        let actual = bundle.checksum()?;
        if actual != target.checksum {
            return Err(ControlError::invalid_payload(format!(
                "version {target_version} checksum mismatch"
            )));
        }

        let note = note.or_else(|| Some(format!("rollback to v{target_version}")));
        self.publish_bundle(bundle, actor, note, "rollback").await
    }

    /// 发布 / 回滚的公共实现。
    async fn publish_bundle(
        &self,
        bundle: ResourceBundle,
        actor: &str,
        note: Option<String>,
        action: &str,
    ) -> Result<PublishOutcome, ControlError> {
        let bundle = bundle.canonicalized();

        // 1. 校验：失败直接返回，不写任何版本
        bundle
            .validate()
            .map_err(|errors| ControlError::Validation { errors })?;

        // 2. checksum + 快照 JSON（快照只保存资源集合，版本号由仓储分配）
        let checksum = bundle.checksum()?;
        let snapshot_json = serde_json::to_value(&bundle).map_err(|e| {
            ControlError::invalid_payload(format!("failed to serialize bundle: {e}"))
        })?;

        // 3. 原子写入版本 + 审计
        let audit = AuditLogEntry::new(actor, action).with_detail(format!(
            "{} config: {} route(s), {} service(s), {} upstream(s)",
            action,
            bundle.routes.len(),
            bundle.services.len(),
            bundle.upstreams.len()
        ));
        let record = self
            .repo
            .commit_publish(PublishCommit {
                checksum: checksum.clone(),
                schema_version: SCHEMA_VERSION.to_string(),
                snapshot: snapshot_json,
                created_by: actor.to_string(),
                note: note.clone(),
                audit,
            })
            .await
            .map_err(map_storage_error)?;

        // 4. 应用到数据面（如果注入了 applier）
        let snapshot = CompiledSnapshot {
            schema_version: SCHEMA_VERSION.to_string(),
            config_version: record.version,
            checksum: record.checksum.clone(),
            bundle,
        };

        let mut applied = false;
        let mut apply_error = None;
        if let Some(applier) = &self.applier {
            match applier.apply(&snapshot).await {
                Ok(_) => applied = true,
                Err(err) => {
                    // 截断错误信息，避免超长堆栈进入数据库/响应
                    let mut message = err;
                    if message.len() > 300 {
                        message.truncate(300);
                        message.push_str("...");
                    }
                    apply_error = Some(message);
                },
            }

            // 实例应用状态单独记录（不阻塞、不回滚已保存版本）
            let publish_record = PublishRecord {
                id: Uuid::new_v4().to_string(),
                version: record.version,
                checksum: record.checksum.clone(),
                status: if applied {
                    PublishStatus::Applied
                } else {
                    PublishStatus::Failed
                },
                instance_id: self.instance_id.clone(),
                message: apply_error.clone(),
                created_at: Utc::now(),
            };
            self.repo
                .record_publish(publish_record)
                .await
                .map_err(map_storage_error)?;
        }

        Ok(PublishOutcome {
            version: record.version,
            checksum: record.checksum,
            applied,
            apply_error,
            note,
            created_at: record.created_at,
        })
    }

    // -----------------------------------------------------------------
    // 版本 / 审计 / 发布记录查询
    // -----------------------------------------------------------------

    /// 最新版本。
    pub async fn latest_version(&self) -> Result<Option<ConfigVersionRecord>, ControlError> {
        self.repo.latest_version().await.map_err(map_storage_error)
    }

    /// 按版本号查询。
    pub async fn get_version(&self, version: u64) -> Result<ConfigVersionRecord, ControlError> {
        self.repo
            .get_version(version)
            .await
            .map_err(map_storage_error)?
            .ok_or_else(|| ControlError::not_found("config-versions", &version.to_string()))
    }

    /// 分页查询历史版本。
    pub async fn list_versions(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Page<ConfigVersionRecord>, ControlError> {
        let limit = limit.clamp(1, MAX_PAGE_SIZE);
        let items = self
            .repo
            .list_versions(limit, offset)
            .await
            .map_err(map_storage_error)?;
        // 版本总数：用 latest_version 的版本号近似（版本号单调递增且从 1 开始）
        let total = self
            .repo
            .latest_version()
            .await
            .map_err(map_storage_error)?
            .map(|v| v.version)
            .unwrap_or(0);
        Ok(Page {
            items,
            total,
            limit,
            offset,
        })
    }

    /// 分页查询审计日志。
    pub async fn list_audit_logs(
        &self,
        version: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Page<AuditLogEntry>, ControlError> {
        let limit = limit.clamp(1, MAX_PAGE_SIZE);
        let items = self
            .repo
            .list_audit_logs(version, limit, offset)
            .await
            .map_err(map_storage_error)?;
        Ok(Page {
            items,
            total: 0,
            limit,
            offset,
        })
    }

    /// 分页查询实例应用记录。
    pub async fn list_publish_records(
        &self,
        version: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Page<PublishRecord>, ControlError> {
        let limit = limit.clamp(1, MAX_PAGE_SIZE);
        let items = self
            .repo
            .list_publish_records(version, limit, offset)
            .await
            .map_err(map_storage_error)?;
        Ok(Page {
            items,
            total: 0,
            limit,
            offset,
        })
    }

    // -----------------------------------------------------------------
    // 内部辅助
    // -----------------------------------------------------------------

    /// 加载某类资源并反序列化为领域类型。
    async fn load_typed<T: DeserializeOwned>(
        &self,
        kind: ResourceKind,
    ) -> Result<Vec<T>, ControlError> {
        let items = self
            .repo
            .list_all_resources(kind)
            .await
            .map_err(map_storage_error)?;

        let mut decoded = Vec::with_capacity(items.len());
        for item in items {
            let mut payload = item.payload.clone();
            if let Some(obj) = payload.as_object_mut() {
                // 关键列覆盖 payload 同名字段，保证 enabled 语义一致
                obj.insert("id".to_string(), Value::String(item.id.clone()));
                obj.insert("enabled".to_string(), Value::Bool(item.enabled));
                if let Some(name) = &item.name {
                    obj.insert("name".to_string(), Value::String(name.clone()));
                }
            }
            let value: T = serde_json::from_value(payload).map_err(|e| {
                ControlError::InvalidPayload {
                    message: format!("failed to decode {}/{}: {e}", kind.as_str(), item.id),
                }
            })?;
            decoded.push(value);
        }
        Ok(decoded)
    }

    /// 写审计记录。
    async fn append_audit(&self, entry: AuditLogEntry) -> Result<(), ControlError> {
        self.repo.append_audit(entry).await.map_err(map_storage_error)
    }
}

// ---------------------------------------------------------------------------
// 辅助函数
// ---------------------------------------------------------------------------

/// 校验单条资源的 payload 结构。
///
/// 只在写入时校验"单资源结构"，不校验跨资源引用——否则无法按
/// "先建上游、再建服务、最后建路由"的顺序分步创建。
fn validate_payload(
    kind: ResourceKind,
    payload: &Value,
    expected_id: Option<&str>,
) -> Result<(), ControlError> {
    let obj = payload
        .as_object()
        .ok_or_else(|| ControlError::invalid_payload("payload must be a JSON object"))?;

    // payload 的 id 必须与资源 ID 一致，避免"库里的 id"和"配置里的 id"分叉
    if let Some(expected) = expected_id {
        let actual = obj.get("id").and_then(Value::as_str).ok_or_else(|| {
            ControlError::invalid_payload("payload must contain a string 'id' field")
        })?;
        if actual != expected {
            return Err(ControlError::invalid_payload(format!(
                "payload id '{actual}' does not match resource id '{expected}'"
            )));
        }
    }

    // 按类型做结构校验（未知类型仅要求是对象）
    let decode_err = |e: serde_json::Error| {
        ControlError::invalid_payload(format!(
            "payload does not match {} schema: {e}",
            kind.as_str()
        ))
    };
    match kind {
        ResourceKind::Service => serde_json::from_value::<ServiceConfig>(payload.clone())
            .map(|_| ())
            .map_err(decode_err),
        ResourceKind::Upstream => serde_json::from_value::<UpstreamConfig>(payload.clone())
            .map(|_| ())
            .map_err(decode_err),
        ResourceKind::Route => serde_json::from_value::<RouteConfig>(payload.clone())
            .map(|_| ())
            .map_err(decode_err),
        ResourceKind::AuthPolicy => serde_json::from_value::<AuthPolicyConfig>(payload.clone())
            .map(|_| ())
            .map_err(decode_err),
        ResourceKind::RateLimitPolicy => {
            serde_json::from_value::<RateLimitPolicyConfig>(payload.clone())
                .map(|_| ())
                .map_err(decode_err)
        },
        ResourceKind::TimeoutPolicy => {
            serde_json::from_value::<TimeoutPolicyConfig>(payload.clone())
                .map(|_| ())
                .map_err(decode_err)
        },
        ResourceKind::RetryPolicy => serde_json::from_value::<RetryPolicyConfig>(payload.clone())
            .map(|_| ())
            .map_err(decode_err),
        ResourceKind::CircuitBreakerPolicy => {
            serde_json::from_value::<CircuitBreakerPolicyConfig>(payload.clone())
                .map(|_| ())
                .map_err(decode_err)
        },
        ResourceKind::CorsPolicy => serde_json::from_value::<CorsPolicyConfig>(payload.clone())
            .map(|_| ())
            .map_err(decode_err),
        ResourceKind::RequestTransformPolicy | ResourceKind::ResponseTransformPolicy => {
            serde_json::from_value::<TransformPolicyConfig>(payload.clone())
                .map(|_| ())
                .map_err(decode_err)
        },
        // 消费者 / 凭据 / 插件：Phase 3 只做持久化，结构由后续阶段启用
        ResourceKind::Consumer
        | ResourceKind::ConsumerCredential
        | ResourceKind::Plugin
        | ResourceKind::PluginConfig => Ok(()),
    }
}

/// 把存储错误映射为控制面语义错误。
fn map_storage_error(err: StorageError) -> ControlError {
    match err {
        StorageError::NotFound { kind, id } => ControlError::not_found(&kind, &id),
        StorageError::Conflict { kind, id } => ControlError::Conflict {
            resource: kind,
            id,
        },
        StorageError::VersionConflict {
            kind,
            id,
            expected,
            actual,
        } => ControlError::VersionConflict {
            resource: kind,
            id,
            expected,
            actual,
        },
        StorageError::InvalidPayload { message } => ControlError::InvalidPayload { message },
        other => ControlError::Storage(other),
    }
}

/// 校验错误的显示文本（用于日志）。
pub fn format_validation_errors(errors: &[ConfigError]) -> String {
    errors
        .iter()
        .map(|e| format!("{}: {}", e.path, e.message))
        .collect::<Vec<_>>()
        .join("; ")
}
