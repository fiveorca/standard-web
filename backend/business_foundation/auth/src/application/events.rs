//! 事件消费：认证中心接收用户中心的账户状态、资料与组织关系变更。
//!
//! 所有消费均通过 Inbox 表保证幂等；组织关系写入本地投影后立即失效授权缓存。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::application::RequestMeta;
use crate::bootstrap::AppState;
use crate::infrastructure::outbox;
use crate::shared::{AppError, AppResult};

pub const CONSUMER: &str = "auth-center";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventEnvelope {
    #[serde(default = "Uuid::now_v7")]
    pub event_id: Uuid,
    pub event_type: String,
    #[serde(default)]
    pub aggregate_type: String,
    #[serde(default)]
    pub aggregate_id: String,
    #[serde(default = "Utc::now")]
    pub occurred_at: DateTime<Utc>,
    #[serde(default = "default_version")]
    pub version: i32,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub payload: Value,
}

fn default_version() -> i32 {
    1
}

#[derive(Debug, Clone, Serialize)]
pub struct EventHandleResult {
    pub accepted: bool,
    pub duplicate: bool,
    pub event_type: String,
}

fn required_uuid(payload: &Value, field: &str) -> AppResult<Uuid> {
    payload
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| AppError::validation(field, "事件缺少必要字段"))?
        .parse()
        .map_err(|_| AppError::validation(field, "UUID 格式不正确"))
}

impl AppState {
    pub async fn handle_incoming_event(
        &self,
        event: EventEnvelope,
    ) -> AppResult<EventHandleResult> {
        let accepted = outbox::inbox_accept(
            &self.pool,
            CONSUMER,
            event.event_id,
            &event.event_type,
            &event.payload,
        )
        .await?;
        if !accepted {
            return Ok(EventHandleResult {
                accepted: true,
                duplicate: true,
                event_type: event.event_type,
            });
        }

        let result = self.apply_event(&event).await;
        match &result {
            Ok(()) => {
                outbox::inbox_mark(&self.pool, CONSUMER, event.event_id, true, None).await?;
                audit::record(
                    &self.pool,
                    AuditEntry::new("auth.event.consumed")
                        .request_context(None, None, event.trace_id.clone())
                        .detail(json!({
                            "event_id": event.event_id,
                            "event_type": event.event_type,
                            "aggregate_id": event.aggregate_id,
                        })),
                )
                .await?;
            }
            Err(error) => {
                outbox::inbox_mark(
                    &self.pool,
                    CONSUMER,
                    event.event_id,
                    false,
                    Some(&error.to_string()),
                )
                .await?;
            }
        }
        result?;
        Ok(EventHandleResult {
            accepted: true,
            duplicate: false,
            event_type: event.event_type,
        })
    }

    async fn apply_event(&self, event: &EventEnvelope) -> AppResult<()> {
        let meta = RequestMeta::new(None, None, event.trace_id.clone());
        match event.event_type.as_str() {
            "user.account_status.changed" => {
                let identity_id = required_uuid(&event.payload, "identity_id")?;
                let status = event
                    .payload
                    .get("status")
                    .and_then(Value::as_str)
                    .ok_or_else(|| AppError::validation("status", "缺少状态"))?;
                let target = match status {
                    "active" => "active",
                    "disabled" | "frozen" => "disabled",
                    "locked" => "locked",
                    "deleting" => "deleting",
                    "deleted" => "deleted",
                    _ => {
                        tracing::warn!(status, "忽略未知的用户状态事件");
                        return Ok(());
                    }
                };
                let reason = event
                    .payload
                    .get("reason")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                self.update_identity_status(identity_id, target, reason, None, &meta)
                    .await?;
            }
            "user.deleted" => {
                let identity_id = required_uuid(&event.payload, "identity_id")?;
                self.update_identity_status(
                    identity_id,
                    "deleted",
                    Some("user_center_deleted".to_string()),
                    None,
                    &meta,
                )
                .await?;
            }
            "user.profile.updated" => {
                let identity_id = required_uuid(&event.payload, "identity_id")?;
                let display_name = event
                    .payload
                    .get("display_name")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let avatar_url = event
                    .payload
                    .get("avatar_url")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                self.sync_identity_profile(identity_id, display_name, avatar_url, None, None)
                    .await?;
            }
            "user.organization.changed" => {
                let identity_id = required_uuid(&event.payload, "identity_id")?;
                let tenant_id = required_uuid(&event.payload, "tenant_id")?;
                self.sync_org_memberships(identity_id, tenant_id, &event.payload)
                    .await?;
            }
            other => {
                tracing::debug!(event_type = other, "认证中心忽略未订阅事件");
            }
        }
        Ok(())
    }

    async fn sync_org_memberships(
        &self,
        identity_id: Uuid,
        tenant_id: Uuid,
        payload: &Value,
    ) -> AppResult<()> {
        self.ensure_tenant(tenant_id).await?;
        let memberships = payload
            .get("memberships")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "DELETE FROM identity_org_memberships WHERE identity_id = $1 AND tenant_id = $2",
        )
        .bind(identity_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        for membership in &memberships {
            let organization_id = membership
                .get("organization_id")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok());
            let department_id = membership
                .get("department_id")
                .and_then(Value::as_str)
                .and_then(|value| Uuid::parse_str(value).ok());
            let department_path = membership
                .get("department_path")
                .and_then(Value::as_str)
                .map(str::to_string);
            let is_primary = membership
                .get("is_primary")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            sqlx::query(
                "INSERT INTO identity_org_memberships
                    (identity_id, tenant_id, organization_id, department_id, department_path, is_primary)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 ON CONFLICT DO NOTHING",
            )
            .bind(identity_id)
            .bind(tenant_id)
            .bind(organization_id)
            .bind(department_id)
            .bind(&department_path)
            .bind(is_primary)
            .execute(&mut *tx)
            .await?;
        }
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("auth.org_membership.synced")
                .tenant(tenant_id)
                .actor(identity_id)
                .resource("identity", identity_id.to_string())
                .detail(json!({ "count": memberships.len() })),
        )
        .await?;
        tx.commit().await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(())
    }
}
