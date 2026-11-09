//! 用户中心审计日志（不含敏感凭证）。

use serde_json::{json, Value};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::shared::{AppResult, RequestMeta, DEFAULT_TENANT_ID};

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub tenant_id: Uuid,
    pub actor_id: Option<Uuid>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub result: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub trace_id: Option<String>,
    pub detail: Value,
}

impl AuditEntry {
    pub fn new(action: impl Into<String>) -> Self {
        Self {
            tenant_id: DEFAULT_TENANT_ID,
            actor_id: None,
            action: action.into(),
            resource_type: None,
            resource_id: None,
            result: "success".to_string(),
            ip: None,
            user_agent: None,
            trace_id: None,
            detail: json!({}),
        }
    }

    pub fn tenant(mut self, tenant_id: Uuid) -> Self {
        self.tenant_id = tenant_id;
        self
    }

    pub fn actor(mut self, actor_id: Option<Uuid>) -> Self {
        self.actor_id = actor_id;
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
        self.result = result.into();
        self
    }

    pub fn detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }

    pub fn request_context(&mut self, meta: &RequestMeta) -> &mut Self {
        self.ip = meta.ip.clone();
        self.user_agent = meta.user_agent.clone();
        self.trace_id = meta.trace_id.clone();
        self
    }
}

pub async fn record(pool: &PgPool, entry: AuditEntry) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO user_audit_logs
            (tenant_id, actor_id, action, resource_type, resource_id, result,
             ip, user_agent, trace_id, detail)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(entry.tenant_id)
    .bind(entry.actor_id)
    .bind(&entry.action)
    .bind(&entry.resource_type)
    .bind(&entry.resource_id)
    .bind(&entry.result)
    .bind(&entry.ip)
    .bind(&entry.user_agent)
    .bind(&entry.trace_id)
    .bind(&entry.detail)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn record_in_tx(tx: &mut Transaction<'_, Postgres>, entry: AuditEntry) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO user_audit_logs
            (tenant_id, actor_id, action, resource_type, resource_id, result,
             ip, user_agent, trace_id, detail)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
    )
    .bind(entry.tenant_id)
    .bind(entry.actor_id)
    .bind(&entry.action)
    .bind(&entry.resource_type)
    .bind(&entry.resource_id)
    .bind(&entry.result)
    .bind(&entry.ip)
    .bind(&entry.user_agent)
    .bind(&entry.trace_id)
    .bind(&entry.detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 记录一条状态历史。
pub async fn status_history(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    user_id: Uuid,
    from_status: Option<&str>,
    to_status: &str,
    reason: Option<&str>,
    operator_id: Option<Uuid>,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO user_status_history
            (tenant_id, user_id, from_status, to_status, reason, operator_id)
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(from_status)
    .bind(to_status)
    .bind(reason)
    .bind(operator_id)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
