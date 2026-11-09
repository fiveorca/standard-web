//! 安全审计日志：哈希链保证可检测篡改。

use serde_json::{json, Value};
use sqlx::{PgConnection, PgPool};
use uuid::Uuid;

use crate::domain::{AuditLog, DomainEvent};
use crate::infrastructure::outbox;
use crate::shared::{canonical_json, now, sha256_hex, AppResult};

#[derive(Debug, Clone, Default)]
pub struct AuditEntry {
    pub tenant_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub actor_type: Option<String>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub result: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub trace_id: Option<String>,
    pub detail: Value,
}

impl AuditEntry {
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            action: action.into(),
            detail: Value::Object(Default::default()),
            ..Self::default()
        }
    }

    pub fn tenant(mut self, tenant_id: Uuid) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    pub fn actor(mut self, actor_id: Uuid) -> Self {
        self.actor_id = Some(actor_id);
        self
    }

    pub fn resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    pub fn result(mut self, result: impl Into<String>) -> Self {
        self.result = Some(result.into());
        self
    }

    pub fn request_context(
        mut self,
        ip: Option<String>,
        user_agent: Option<String>,
        trace_id: Option<String>,
    ) -> Self {
        self.ip = ip;
        self.user_agent = user_agent;
        self.trace_id = trace_id;
        self
    }

    pub fn detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }
}

/// 在独立连接中记录审计。
pub async fn record(pool: &PgPool, entry: AuditEntry) -> AppResult<()> {
    let mut tx = pool.begin().await?;
    record_in_tx(&mut tx, entry).await?;
    tx.commit().await?;
    Ok(())
}

/// 在业务事务中记录审计（保证业务与审计同时提交）。
pub async fn record_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entry: AuditEntry,
) -> AppResult<()> {
    record_in_connection(&mut *tx, entry).await
}

pub async fn record_in_connection(conn: &mut PgConnection, entry: AuditEntry) -> AppResult<()> {
    // 串行化哈希链，避免并发写入导致 prev_hash 分叉。
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('auth_center.audit_chain'))")
        .execute(&mut *conn)
        .await?;

    let prev: Option<(String,)> =
        sqlx::query_as("SELECT hash FROM security_audit_logs ORDER BY id DESC LIMIT 1")
            .fetch_optional(&mut *conn)
            .await?;
    let prev_hash = prev.map(|row| row.0);
    let created_at = now();
    let detail = entry.detail.clone();
    let payload = canonical_json(&json!({
        "tenant_id": entry.tenant_id,
        "actor_id": entry.actor_id,
        "actor_type": entry.actor_type.clone().unwrap_or_else(|| "user".to_string()),
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "result": entry.result.clone().unwrap_or_else(|| "success".to_string()),
        "detail": detail,
        "created_at": created_at.to_rfc3339(),
    }));
    let hash = sha256_hex(format!(
        "{}|{}",
        prev_hash.clone().unwrap_or_default(),
        payload
    ));

    sqlx::query(
        "INSERT INTO security_audit_logs
            (tenant_id, actor_id, actor_type, action, resource_type, resource_id, result,
             ip, user_agent, trace_id, detail, prev_hash, hash, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
    )
    .bind(entry.tenant_id)
    .bind(entry.actor_id)
    .bind(entry.actor_type.unwrap_or_else(|| "user".to_string()))
    .bind(entry.action)
    .bind(entry.resource_type)
    .bind(entry.resource_id)
    .bind(entry.result.unwrap_or_else(|| "success".to_string()))
    .bind(entry.ip)
    .bind(entry.user_agent)
    .bind(entry.trace_id)
    .bind(detail)
    .bind(prev_hash)
    .bind(hash)
    .bind(created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// 校验最近 `limit` 条审计日志的哈希链。
pub async fn verify_chain(pool: &PgPool, limit: i64) -> AppResult<(bool, i64, i64)> {
    let limit = limit.clamp(1, 10_000);
    let rows = sqlx::query_as::<_, AuditLog>(
        "SELECT id, tenant_id, actor_id, actor_type, action, resource_type, resource_id, result,
                ip, user_agent, trace_id, detail, prev_hash, hash, created_at
         FROM security_audit_logs ORDER BY id DESC LIMIT $1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    let mut checked = 0i64;
    let mut valid = true;
    for window in rows.windows(2) {
        let current = &window[0];
        let previous = &window[1];
        if current.prev_hash.as_deref() != Some(previous.hash.as_str()) {
            valid = false;
        }
        let payload = canonical_json(&json!({
            "tenant_id": current.tenant_id,
            "actor_id": current.actor_id,
            "actor_type": current.actor_type,
            "action": current.action,
            "resource_type": current.resource_type,
            "resource_id": current.resource_id,
            "result": current.result,
            "detail": current.detail,
            "created_at": current.created_at.to_rfc3339(),
        }));
        let expected = sha256_hex(format!(
            "{}|{}",
            current.prev_hash.clone().unwrap_or_default(),
            payload
        ));
        if expected != current.hash {
            valid = false;
        }
        checked += 1;
    }
    let latest = rows.first().map(|row| row.id).unwrap_or(0);
    Ok((valid, checked, latest))
}

/// 写入审计事件到 Outbox，便于外部审计系统消费。
pub async fn enqueue_audit_event(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    entry: &AuditEntry,
) -> AppResult<()> {
    let event = DomainEvent::new(
        "auth.audit.recorded",
        "audit",
        entry
            .resource_id
            .clone()
            .unwrap_or_else(|| Uuid::now_v7().to_string()),
        json!({
            "action": entry.action,
            "tenant_id": entry.tenant_id,
            "actor_id": entry.actor_id,
            "result": entry.result,
            "resource_type": entry.resource_type,
            "resource_id": entry.resource_id,
        }),
    )
    .with_trace(entry.trace_id.clone());
    outbox::enqueue(tx, &event).await
}
