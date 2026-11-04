//! PostgreSQL 仓储实现（PostgresRepository）。
//!
//! # 实现要点
//!
//! 1. **不使用 `query!` / `query_as!` 编译期宏**：那样需要 `DATABASE_URL`，
//!    在没有数据库的 CI/开发机上无法编译。全部改用运行时 `sqlx::query`。
//! 2. **表名来自 [`ResourceKind::table`]**：枚举常量，不接受任何用户输入拼接。
//! 3. **更新使用 `SELECT ... FOR UPDATE`**：与乐观锁版本号配合，避免并发覆盖。
//! 4. **发布使用 Postgres 咨询锁 + 单事务**：保证版本号单调递增，且
//!    "版本记录 + 审计记录"原子写入。

use async_trait::async_trait;
use chrono::Utc;
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::{PgPool, Row};
use serde_json::Value;

use crate::error::StorageError;
use crate::models::{
    AuditLogEntry, ConfigVersionRecord, PublishCommit, PublishRecord, PublishStatus, ResourceDraft,
    ResourceKind, ResourceUpdate, StoredResource, VersionStatus,
};
use crate::repository::GatewayRepository;

/// PostgreSQL 仓储实现。
#[derive(Debug, Clone)]
pub struct PostgresRepository {
    pool: PgPool,
}

impl PostgresRepository {
    /// 使用已有连接池构造仓储。
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// 只读访问内部连接池（健康检查 / 测试用）。
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// 把数据库行转换为 [`StoredResource`]。
fn row_to_resource(row: &PgRow) -> Result<StoredResource, StorageError> {
    let payload: Json<Value> = row.try_get("payload")?;
    Ok(StoredResource {
        id: row.try_get("id")?,
        name: row.try_get("name")?,
        enabled: row.try_get("enabled")?,
        version: row.try_get("version")?,
        payload: payload.0,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

/// 把数据库行转换为 [`ConfigVersionRecord`]。
fn row_to_version(row: &PgRow) -> Result<ConfigVersionRecord, StorageError> {
    let version: i64 = row.try_get("version")?;
    let status: String = row.try_get("status")?;
    let snapshot: Json<Value> = row.try_get("snapshot")?;
    Ok(ConfigVersionRecord {
        version: u64::try_from(version)
            .map_err(|_| StorageError::invalid_payload("negative config version in database"))?,
        checksum: row.try_get("checksum")?,
        schema_version: row.try_get("schema_version")?,
        status: VersionStatus::from_db(&status),
        snapshot: snapshot.0,
        created_by: row.try_get("created_by")?,
        note: row.try_get("note")?,
        created_at: row.try_get("created_at")?,
    })
}

/// 把数据库行转换为 [`PublishRecord`]。
fn row_to_publish_record(row: &PgRow) -> Result<PublishRecord, StorageError> {
    let version: i64 = row.try_get("version")?;
    let status: String = row.try_get("status")?;
    Ok(PublishRecord {
        id: row.try_get("id")?,
        version: u64::try_from(version)
            .map_err(|_| StorageError::invalid_payload("negative config version in database"))?,
        checksum: row.try_get("checksum")?,
        status: PublishStatus::from_db(&status),
        instance_id: row.try_get("instance_id")?,
        message: row.try_get("message")?,
        created_at: row.try_get("created_at")?,
    })
}

/// 把主键冲突映射为 [`StorageError::Conflict`]，其余错误统一转换。
fn map_write_error(err: sqlx::Error, kind: ResourceKind, id: &str) -> StorageError {
    if let sqlx::Error::Database(db_err) = &err {
        // PostgreSQL 唯一约束冲突 SQLSTATE = 23505
        if db_err.code().as_deref() == Some("23505") {
            return StorageError::conflict(kind.as_str(), id);
        }
    }
    StorageError::from(err)
}

#[async_trait]
impl GatewayRepository for PostgresRepository {
    async fn list_resources(
        &self,
        kind: ResourceKind,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<StoredResource>, StorageError> {
        let sql = format!(
            "SELECT id, name, enabled, version, payload, created_at, updated_at \
             FROM {} ORDER BY id ASC LIMIT $1 OFFSET $2",
            kind.table()
        );
        let rows = sqlx::query(&sql)
            .bind(limit as i64)
            .bind(offset as i64)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(row_to_resource).collect()
    }

    async fn list_all_resources(
        &self,
        kind: ResourceKind,
    ) -> Result<Vec<StoredResource>, StorageError> {
        let sql = format!(
            "SELECT id, name, enabled, version, payload, created_at, updated_at \
             FROM {} ORDER BY id ASC",
            kind.table()
        );
        let rows = sqlx::query(&sql).fetch_all(&self.pool).await?;
        rows.iter().map(row_to_resource).collect()
    }

    async fn count_resources(&self, kind: ResourceKind) -> Result<u64, StorageError> {
        let sql = format!("SELECT COUNT(*) FROM {}", kind.table());
        let count: i64 = sqlx::query_scalar(&sql).fetch_one(&self.pool).await?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    async fn get_resource(
        &self,
        kind: ResourceKind,
        id: &str,
    ) -> Result<Option<StoredResource>, StorageError> {
        let sql = format!(
            "SELECT id, name, enabled, version, payload, created_at, updated_at \
             FROM {} WHERE id = $1",
            kind.table()
        );
        let row = sqlx::query(&sql).bind(id).fetch_optional(&self.pool).await?;
        row.as_ref().map(row_to_resource).transpose()
    }

    async fn create_resource(
        &self,
        kind: ResourceKind,
        draft: ResourceDraft,
    ) -> Result<StoredResource, StorageError> {
        if draft.id.trim().is_empty() {
            return Err(StorageError::invalid_payload("resource id must not be empty"));
        }

        let now = Utc::now();
        let sql = format!(
            "INSERT INTO {} (id, name, enabled, version, payload, created_at, updated_at) \
             VALUES ($1, $2, $3, 1, $4, $5, $5) \
             RETURNING id, name, enabled, version, payload, created_at, updated_at",
            kind.table()
        );
        let row = sqlx::query(&sql)
            .bind(&draft.id)
            .bind(&draft.name)
            .bind(draft.enabled)
            .bind(Json(draft.payload))
            .bind(now)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| map_write_error(e, kind, &draft.id))?;

        row_to_resource(&row)
    }

    async fn update_resource(
        &self,
        kind: ResourceKind,
        id: &str,
        update: ResourceUpdate,
    ) -> Result<StoredResource, StorageError> {
        let mut tx = self.pool.begin().await?;

        let select_sql = format!(
            "SELECT id, name, enabled, version, payload, created_at, updated_at \
             FROM {} WHERE id = $1 FOR UPDATE",
            kind.table()
        );
        let row = sqlx::query(&select_sql)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            return Err(StorageError::not_found(kind.as_str(), id));
        };

        let mut record = row_to_resource(&row)?;
        if let Some(expected) = update.expected_version {
            if expected != record.version {
                return Err(StorageError::VersionConflict {
                    kind: kind.as_str().to_string(),
                    id: id.to_string(),
                    expected,
                    actual: record.version,
                });
            }
        }

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

        let update_sql = format!(
            "UPDATE {} SET name = $2, enabled = $3, version = $4, payload = $5, updated_at = $6 \
             WHERE id = $1",
            kind.table()
        );
        sqlx::query(&update_sql)
            .bind(id)
            .bind(&record.name)
            .bind(record.enabled)
            .bind(record.version)
            .bind(Json(record.payload.clone()))
            .bind(record.updated_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| map_write_error(e, kind, id))?;

        tx.commit().await?;
        Ok(record)
    }

    async fn delete_resource(
        &self,
        kind: ResourceKind,
        id: &str,
        expected_version: Option<i64>,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool.begin().await?;

        let select_sql = format!("SELECT version FROM {} WHERE id = $1 FOR UPDATE", kind.table());
        let row = sqlx::query(&select_sql)
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
        let Some(row) = row else {
            return Err(StorageError::not_found(kind.as_str(), id));
        };

        let actual: i64 = row.try_get("version")?;
        if let Some(expected) = expected_version {
            if expected != actual {
                return Err(StorageError::VersionConflict {
                    kind: kind.as_str().to_string(),
                    id: id.to_string(),
                    expected,
                    actual,
                });
            }
        }

        let delete_sql = format!("DELETE FROM {} WHERE id = $1", kind.table());
        sqlx::query(&delete_sql).bind(id).execute(&mut *tx).await?;

        tx.commit().await?;
        Ok(())
    }

    async fn append_audit(&self, entry: AuditLogEntry) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO audit_logs \
             (id, actor, action, resource_kind, resource_id, version, detail, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&entry.id)
        .bind(&entry.actor)
        .bind(&entry.action)
        .bind(&entry.resource_kind)
        .bind(&entry.resource_id)
        .bind(entry.version.map(|v| v as i64))
        .bind(&entry.detail)
        .bind(entry.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_audit_logs(
        &self,
        version: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<AuditLogEntry>, StorageError> {
        let rows = match version {
            Some(v) => {
                sqlx::query(
                    "SELECT id, actor, action, resource_kind, resource_id, version, detail, created_at \
                     FROM audit_logs WHERE version = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                )
                .bind(v as i64)
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await?
            },
            None => {
                sqlx::query(
                    "SELECT id, actor, action, resource_kind, resource_id, version, detail, created_at \
                     FROM audit_logs ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                )
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await?
            },
        };

        let mut items = Vec::with_capacity(rows.len());
        for row in &rows {
            let version: Option<i64> = row.try_get("version")?;
            items.push(AuditLogEntry {
                id: row.try_get("id")?,
                actor: row.try_get("actor")?,
                action: row.try_get("action")?,
                resource_kind: row.try_get("resource_kind")?,
                resource_id: row.try_get("resource_id")?,
                version: version
                    .map(|v| {
                        u64::try_from(v).map_err(|_| {
                            StorageError::invalid_payload("negative audit version in database")
                        })
                    })
                    .transpose()?,
                detail: row.try_get("detail")?,
                created_at: row.try_get("created_at")?,
            });
        }
        Ok(items)
    }

    async fn commit_publish(
        &self,
        commit: PublishCommit,
    ) -> Result<ConfigVersionRecord, StorageError> {
        let mut tx = self.pool.begin().await?;

        // 咨询锁串行化并发发布，避免 MAX(version)+1 的竞态。
        // 锁在事务结束时自动释放（pg_advisory_xact_lock 语义）。
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(PUBLISH_LOCK_ID)
            .execute(&mut *tx)
            .await?;

        let next: i64 =
            sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) + 1 FROM config_versions")
                .fetch_one(&mut *tx)
                .await?;
        let next_version = u64::try_from(next)
            .map_err(|_| StorageError::invalid_payload("config version overflow"))?;

        // 旧版本标记为 superseded，仍保留供回滚与历史查询
        sqlx::query("UPDATE config_versions SET status = 'superseded' WHERE status = 'published'")
            .execute(&mut *tx)
            .await?;

        let row = sqlx::query(
            "INSERT INTO config_versions \
             (version, checksum, schema_version, status, snapshot, created_by, note, created_at) \
             VALUES ($1, $2, $3, 'published', $4, $5, $6, $7) \
             RETURNING version, checksum, schema_version, status, snapshot, created_by, note, created_at",
        )
        .bind(next_version as i64)
        .bind(&commit.checksum)
        .bind(&commit.schema_version)
        .bind(Json(commit.snapshot))
        .bind(&commit.created_by)
        .bind(&commit.note)
        .bind(Utc::now())
        .fetch_one(&mut *tx)
        .await?;

        let record = row_to_version(&row)?;

        // 审计与版本在同一事务内写入
        sqlx::query(
            "INSERT INTO audit_logs \
             (id, actor, action, resource_kind, resource_id, version, detail, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(&commit.audit.id)
        .bind(&commit.audit.actor)
        .bind(&commit.audit.action)
        .bind(&commit.audit.resource_kind)
        .bind(&commit.audit.resource_id)
        .bind(next_version as i64)
        .bind(&commit.audit.detail)
        .bind(commit.audit.created_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(record)
    }

    async fn latest_version(&self) -> Result<Option<ConfigVersionRecord>, StorageError> {
        let row = sqlx::query(
            "SELECT version, checksum, schema_version, status, snapshot, created_by, note, created_at \
             FROM config_versions ORDER BY version DESC LIMIT 1",
        )
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_version).transpose()
    }

    async fn get_version(&self, version: u64) -> Result<Option<ConfigVersionRecord>, StorageError> {
        let row = sqlx::query(
            "SELECT version, checksum, schema_version, status, snapshot, created_by, note, created_at \
             FROM config_versions WHERE version = $1",
        )
        .bind(version as i64)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(row_to_version).transpose()
    }

    async fn list_versions(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<ConfigVersionRecord>, StorageError> {
        let rows = sqlx::query(
            "SELECT version, checksum, schema_version, status, snapshot, created_by, note, created_at \
             FROM config_versions ORDER BY version DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(row_to_version).collect()
    }

    async fn record_publish(&self, record: PublishRecord) -> Result<(), StorageError> {
        let version = i64::try_from(record.version)
            .map_err(|_| StorageError::invalid_payload("publish version overflow"))?;
        sqlx::query(
            "INSERT INTO config_publish_records \
             (id, version, checksum, status, instance_id, message, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(&record.id)
        .bind(version)
        .bind(&record.checksum)
        .bind(record.status.as_str())
        .bind(&record.instance_id)
        .bind(&record.message)
        .bind(record.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn list_publish_records(
        &self,
        version: Option<u64>,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<PublishRecord>, StorageError> {
        let rows = match version {
            Some(v) => {
                sqlx::query(
                    "SELECT id, version, checksum, status, instance_id, message, created_at \
                     FROM config_publish_records WHERE version = $1 \
                     ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                )
                .bind(v as i64)
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await?
            },
            None => {
                sqlx::query(
                    "SELECT id, version, checksum, status, instance_id, message, created_at \
                     FROM config_publish_records ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                )
                .bind(limit as i64)
                .bind(offset as i64)
                .fetch_all(&self.pool)
                .await?
            },
        };
        rows.iter().map(row_to_publish_record).collect()
    }
}

/// 发布咨询锁的固定键（任意常量，只要全系统一致即可）。
const PUBLISH_LOCK_ID: i64 = 0x4741_5445; // "GATE"

#[cfg(test)]
mod tests {
    use super::*;

    /// PostgreSQL 集成测试默认忽略。
    ///
    /// 运行方式：
    /// ```bash
    /// GATEWAY_TEST_DATABASE_URL=postgres://... cargo test -p gateway-storage -- --ignored
    /// ```
    #[tokio::test]
    #[ignore = "requires GATEWAY_TEST_DATABASE_URL"]
    async fn postgres_crud_roundtrip() {
        let url = match std::env::var("GATEWAY_TEST_DATABASE_URL") {
            Ok(url) => url,
            Err(_) => return,
        };
        let pool = crate::pool::connect_and_migrate(&url, Default::default())
            .await
            .expect("connect");
        let repo = PostgresRepository::new(pool);

        let created = repo
            .create_resource(
                ResourceKind::Route,
                ResourceDraft {
                    id: "pg-route-1".into(),
                    name: Some("pg route".into()),
                    enabled: true,
                    payload: serde_json::json!({ "id": "pg-route-1", "hosts": [], "methods": [], "path_value": "/", "service_id": "svc" }),
                },
            )
            .await
            .expect("create");
        assert_eq!(created.version, 1);

        let updated = repo
            .update_resource(
                ResourceKind::Route,
                "pg-route-1",
                ResourceUpdate {
                    name: None,
                    enabled: Some(false),
                    payload: None,
                    expected_version: Some(1),
                },
            )
            .await
            .expect("update");
        assert_eq!(updated.version, 2);
        assert!(!updated.enabled);

        repo.delete_resource(ResourceKind::Route, "pg-route-1", None)
            .await
            .expect("delete");
        assert!(repo
            .get_resource(ResourceKind::Route, "pg-route-1")
            .await
            .expect("get")
            .is_none());
    }
}
