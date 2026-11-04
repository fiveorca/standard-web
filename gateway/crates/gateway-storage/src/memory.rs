//! 内存仓储实现（MemoryRepository）。
//!
//! 用途：
//!   1. 控制面服务的全部单元测试与 API 集成测试（无需 PostgreSQL）
//!   2. 单机 / 开发环境（无数据库）下的控制面
//!
//! 语义与 PostgreSQL 实现保持一致（包括乐观锁和发布事务），
//! 这样在两种实现之间切换时，上层逻辑不需要分支。

use std::collections::{BTreeMap, HashMap};

use async_trait::async_trait;
use chrono::Utc;
use tokio::sync::RwLock;

use crate::error::StorageError;
use crate::models::{
    AuditLogEntry, ConfigVersionRecord, PublishCommit, PublishRecord, ResourceDraft, ResourceKind,
    ResourceUpdate, StoredResource, VersionStatus,
};
use crate::repository::GatewayRepository;

/// 内存状态：资源 + 版本 + 发布记录 + 审计日志。
#[derive(Default)]
struct MemoryState {
    /// 资源键为 `(类型, ID)`，保证不同类型下同名 ID 不冲突
    resources: HashMap<(ResourceKind, String), StoredResource>,
    /// 配置版本，按版本号升序保存
    versions: BTreeMap<u64, ConfigVersionRecord>,
    /// 实例应用记录（按插入顺序，查询时倒序返回）
    publish_records: Vec<PublishRecord>,
    /// 审计日志（按插入顺序，查询时倒序返回）
    audit_logs: Vec<AuditLogEntry>,
}

/// 进程内仓储实现。
///
/// 所有写操作通过 `RwLock` 串行化；读操作可并发。
/// 单机模式下数据仅在进程内保存，重启即丢失——这与"控制面使用
/// PostgreSQL"的生产部署不冲突，仅作为测试与开发替身。
pub struct MemoryRepository {
    state: RwLock<MemoryState>,
}

impl MemoryRepository {
    /// 创建空的内存仓储。
    pub fn new() -> Self {
        Self {
            state: RwLock::new(MemoryState::default()),
        }
    }

    /// 校验版本是否与期望一致。
    ///
    /// `expected` 为 `None` 时不做校验。
    fn check_expected(
        kind: ResourceKind,
        id: &str,
        expected: Option<i64>,
        actual: i64,
    ) -> Result<(), StorageError> {
        if let Some(expected) = expected {
            if expected != actual {
                return Err(StorageError::VersionConflict {
                    kind: kind.as_str().to_string(),
                    id: id.to_string(),
                    expected,
                    actual,
                });
            }
        }
        Ok(())
    }
}

impl Default for MemoryRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl GatewayRepository for MemoryRepository {
    async fn list_resources(
        &self,
        kind: ResourceKind,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredResource>, StorageError> {
        let state = self.state.read().await;
        let mut items: Vec<StoredResource> = state
            .resources
            .iter()
            .filter(|((k, _), _)| *k == kind)
            .map(|(_, v)| v.clone())
            .collect();
        // 按 ID 升序，保证分页结果稳定
        items.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(items.into_iter().skip(offset).take(limit).collect())
    }

    async fn list_all_resources(
        &self,
        kind: ResourceKind,
    ) -> Result<Vec<StoredResource>, StorageError> {
        let state = self.state.read().await;
        let mut items: Vec<StoredResource> = state
            .resources
            .iter()
            .filter(|((k, _), _)| *k == kind)
            .map(|(_, v)| v.clone())
            .collect();
        items.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(items)
    }

    async fn count_resources(&self, kind: ResourceKind) -> Result<u64, StorageError> {
        let state = self.state.read().await;
        let count = state.resources.keys().filter(|(k, _)| *k == kind).count();
        Ok(count as u64)
    }

    async fn get_resource(
        &self,
        kind: ResourceKind,
        id: &str,
    ) -> Result<Option<StoredResource>, StorageError> {
        let state = self.state.read().await;
        Ok(state.resources.get(&(kind, id.to_string())).cloned())
    }

    async fn create_resource(
        &self,
        kind: ResourceKind,
        draft: ResourceDraft,
    ) -> Result<StoredResource, StorageError> {
        // ID 不能为空（空 ID 无法做路由与引用）
        if draft.id.trim().is_empty() {
            return Err(StorageError::invalid_payload("resource id must not be empty"));
        }

        let mut state = self.state.write().await;
        let key = (kind, draft.id.clone());
        if state.resources.contains_key(&key) {
            return Err(StorageError::conflict(kind.as_str(), &draft.id));
        }

        let now = Utc::now();
        let record = StoredResource {
            id: draft.id,
            name: draft.name,
            enabled: draft.enabled,
            version: 1,
            payload: draft.payload,
            created_at: now,
            updated_at: now,
        };
        state.resources.insert(key, record.clone());
        Ok(record)
    }

    async fn update_resource(
        &self,
        kind: ResourceKind,
        id: &str,
        update: ResourceUpdate,
    ) -> Result<StoredResource, StorageError> {
        let mut state = self.state.write().await;
        let key = (kind, id.to_string());
        let record = state
            .resources
            .get_mut(&key)
            .ok_or_else(|| StorageError::not_found(kind.as_str(), id))?;

        // 乐观锁校验
        Self::check_expected(kind, id, update.expected_version, record.version)?;

        // 只覆盖显式提供的字段
        if let Some(name) = update.name {
            record.name = Some(name);
        }
        if let Some(enabled) = update.enabled {
            record.enabled = enabled;
        }
        if let Some(payload) = update.payload {
            record.payload = payload;
        }
        record.version += 1;
        record.updated_at = Utc::now();

        Ok(record.clone())
    }

    async fn delete_resource(
        &self,
        kind: ResourceKind,
        id: &str,
        expected_version: Option<i64>,
    ) -> Result<(), StorageError> {
        let mut state = self.state.write().await;
        let key = (kind, id.to_string());
        let record = state
            .resources
            .get(&key)
            .ok_or_else(|| StorageError::not_found(kind.as_str(), id))?;
        Self::check_expected(kind, id, expected_version, record.version)?;
        state.resources.remove(&key);
        Ok(())
    }

    async fn append_audit(&self, entry: AuditLogEntry) -> Result<(), StorageError> {
        let mut state = self.state.write().await;
        state.audit_logs.push(entry);
        Ok(())
    }

    async fn list_audit_logs(
        &self,
        version: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AuditLogEntry>, StorageError> {
        let state = self.state.read().await;
        let items = state
            .audit_logs
            .iter()
            .rev()
            .filter(|entry| version.is_none_or(|v| entry.version == Some(v)))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        Ok(items)
    }

    async fn commit_publish(
        &self,
        commit: PublishCommit,
    ) -> Result<ConfigVersionRecord, StorageError> {
        let mut state = self.state.write().await;

        // 版本号单调递增：取当前最大版本 + 1
        let next_version = state
            .versions
            .keys()
            .next_back()
            .map(|v| v.saturating_add(1))
            .unwrap_or(1);

        // 旧版本标记为 superseded（仍保留，供回滚与审计）
        for record in state.versions.values_mut() {
            if record.status == VersionStatus::Published {
                record.status = VersionStatus::Superseded;
            }
        }

        let record = ConfigVersionRecord {
            version: next_version,
            checksum: commit.checksum,
            schema_version: commit.schema_version,
            status: VersionStatus::Published,
            snapshot: commit.snapshot,
            created_by: commit.created_by,
            note: commit.note,
            created_at: Utc::now(),
        };
        state.versions.insert(next_version, record.clone());

        // 审计与版本写入在同一临界区完成，等价于单事务
        let audit = commit.audit.with_version(next_version);
        state.audit_logs.push(audit);

        Ok(record)
    }

    async fn latest_version(&self) -> Result<Option<ConfigVersionRecord>, StorageError> {
        let state = self.state.read().await;
        Ok(state.versions.values().next_back().cloned())
    }

    async fn get_version(
        &self,
        version: u64,
    ) -> Result<Option<ConfigVersionRecord>, StorageError> {
        let state = self.state.read().await;
        Ok(state.versions.get(&version).cloned())
    }

    async fn list_versions(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ConfigVersionRecord>, StorageError> {
        let state = self.state.read().await;
        let items = state
            .versions
            .values()
            .rev()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        Ok(items)
    }

    async fn record_publish(&self, record: PublishRecord) -> Result<(), StorageError> {
        let mut state = self.state.write().await;
        state.publish_records.push(record);
        Ok(())
    }

    async fn list_publish_records(
        &self,
        version: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<PublishRecord>, StorageError> {
        let state = self.state.read().await;
        let items = state
            .publish_records
            .iter()
            .rev()
            .filter(|record| version.is_none_or(|v| record.version == v))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect();
        Ok(items)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::models::PublishStatus;

    fn draft(id: &str) -> ResourceDraft {
        ResourceDraft {
            id: id.to_string(),
            name: Some(format!("{id}-name")),
            enabled: true,
            payload: json!({ "id": id }),
        }
    }

    #[tokio::test]
    async fn crud_roundtrip() {
        let repo = MemoryRepository::new();
        let created = repo
            .create_resource(ResourceKind::Route, draft("r1"))
            .await
            .expect("create");
        assert_eq!(created.version, 1);

        // 重复创建 → 冲突
        let err = repo
            .create_resource(ResourceKind::Route, draft("r1"))
            .await
            .expect_err("duplicate");
        assert!(matches!(err, StorageError::Conflict { .. }));

        // 更新后版本自增
        let updated = repo
            .update_resource(
                ResourceKind::Route,
                "r1",
                ResourceUpdate {
                    name: Some("renamed".into()),
                    enabled: Some(false),
                    payload: None,
                    expected_version: Some(1),
                },
            )
            .await
            .expect("update");
        assert_eq!(updated.version, 2);
        assert_eq!(updated.name.as_deref(), Some("renamed"));
        assert!(!updated.enabled);

        // 乐观锁不匹配 → 版本冲突
        let err = repo
            .update_resource(
                ResourceKind::Route,
                "r1",
                ResourceUpdate {
                    name: None,
                    enabled: None,
                    payload: None,
                    expected_version: Some(1),
                },
            )
            .await
            .expect_err("stale version");
        assert!(matches!(err, StorageError::VersionConflict { .. }));

        repo.delete_resource(ResourceKind::Route, "r1", None)
            .await
            .expect("delete");
        assert!(repo
            .get_resource(ResourceKind::Route, "r1")
            .await
            .expect("get")
            .is_none());
    }

    #[tokio::test]
    async fn pagination_and_count() {
        let repo = MemoryRepository::new();
        for id in ["a", "b", "c"] {
            repo.create_resource(ResourceKind::Service, draft(id))
                .await
                .expect("create");
        }
        assert_eq!(
            repo.count_resources(ResourceKind::Service).await.expect("count"),
            3
        );
        let page = repo
            .list_resources(ResourceKind::Service, 1, 1)
            .await
            .expect("list");
        assert_eq!(page.len(), 1);
        assert_eq!(page[0].id, "b");
    }

    #[tokio::test]
    async fn publish_allocates_monotonic_versions_and_audits() {
        let repo = MemoryRepository::new();

        let audit = AuditLogEntry::new("alice", "publish").with_detail("initial");
        let first = repo
            .commit_publish(PublishCommit {
                checksum: "sum-1".into(),
                schema_version: "v1".into(),
                snapshot: json!({ "routes": [] }),
                created_by: "alice".into(),
                note: None,
                audit,
            })
            .await
            .expect("publish");
        assert_eq!(first.version, 1);

        let audit = AuditLogEntry::new("bob", "publish");
        let second = repo
            .commit_publish(PublishCommit {
                checksum: "sum-2".into(),
                schema_version: "v1".into(),
                snapshot: json!({ "routes": [] }),
                created_by: "bob".into(),
                note: Some("second".into()),
                audit,
            })
            .await
            .expect("publish");
        assert_eq!(second.version, 2);

        // 旧版本被标记为 superseded，但仍可查询
        let old = repo.get_version(1).await.expect("get").expect("exists");
        assert_eq!(old.status, VersionStatus::Superseded);
        assert_eq!(old.checksum, "sum-1");

        // 审计记录带版本号
        let logs = repo.list_audit_logs(None, 10, 0).await.expect("audit");
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].version, Some(2));
        assert_eq!(logs[1].version, Some(1));
    }

    #[tokio::test]
    async fn publish_records_are_filterable() {
        let repo = MemoryRepository::new();
        for (version, status) in [(1, PublishStatus::Applied), (2, PublishStatus::Failed)] {
            repo.record_publish(PublishRecord {
                id: format!("rec-{version}"),
                version,
                checksum: format!("sum-{version}"),
                status,
                instance_id: "instance-1".into(),
                message: None,
                created_at: Utc::now(),
            })
            .await
            .expect("record");
        }

        let filtered = repo
            .list_publish_records(Some(2), 10, 0)
            .await
            .expect("list");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].status, PublishStatus::Failed);
    }
}
