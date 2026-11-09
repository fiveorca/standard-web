//! 认证中心事件消费（幂等）。

use serde_json::{json, Value};
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::bootstrap::AppState;
use crate::domain::EventEnvelope;
use crate::infrastructure::outbox::inbox_accept;
use crate::shared::{AppResult, DEFAULT_TENANT_ID};

pub const CONSUMER: &str = "user-center.auth-events";

fn payload_uuid(payload: &Value, key: &str) -> Option<Uuid> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .and_then(|value| Uuid::parse_str(value).ok())
}

fn payload_str<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

/// 消费认证中心事件；返回是否为重复事件。
pub async fn handle_incoming(state: &AppState, event: &EventEnvelope) -> AppResult<bool> {
    let duplicate = !inbox_accept(
        &state.pool,
        CONSUMER,
        event.event_id,
        &event.event_type,
        &event.payload,
    )
    .await?;
    if duplicate {
        return Ok(true);
    }
    match process(state, event).await {
        Ok(()) => {
            crate::infrastructure::outbox::inbox_mark(
                &state.pool,
                CONSUMER,
                event.event_id,
                true,
                None,
            )
            .await?;
            audit::record(
                &state.pool,
                AuditEntry::new("user.auth_event.consumed")
                    .tenant(payload_uuid(&event.payload, "tenant_id").unwrap_or(DEFAULT_TENANT_ID))
                    .resource("auth_event", event.event_id.to_string())
                    .detail(json!({ "event_type": event.event_type })),
            )
            .await?;
            Ok(false)
        }
        Err(error) => {
            crate::infrastructure::outbox::inbox_mark(
                &state.pool,
                CONSUMER,
                event.event_id,
                false,
                Some(&error.to_string()),
            )
            .await?;
            Err(error)
        }
    }
}

async fn process(state: &AppState, event: &EventEnvelope) -> AppResult<()> {
    let payload = &event.payload;
    let tenant_id = payload_uuid(payload, "tenant_id").unwrap_or(DEFAULT_TENANT_ID);
    match event.event_type.as_str() {
        "auth.identity.registered" => {
            let Some(identity_id) = payload_uuid(payload, "identity_id") else {
                return Ok(());
            };
            ensure_placeholder(state, tenant_id, identity_id, payload).await?;
        }
        "auth.identity.activated" => {
            if let Some(identity_id) = payload_uuid(payload, "identity_id") {
                sync_status(state, tenant_id, identity_id, "active", false).await?;
            }
        }
        "auth.identity.disabled" => {
            if let Some(identity_id) = payload_uuid(payload, "identity_id") {
                sync_status(state, tenant_id, identity_id, "disabled", false).await?;
            }
        }
        "auth.identity.deleted" => {
            if let Some(identity_id) = payload_uuid(payload, "identity_id") {
                sync_status(state, tenant_id, identity_id, "deleted", true).await?;
            }
        }
        "auth.identity.restored" => {
            if let Some(identity_id) = payload_uuid(payload, "identity_id") {
                sqlx::query(
                    "UPDATE users SET status = 'active', deleted_at = NULL, updated_at = now()
                      WHERE id = $1 AND deleted_at IS NOT NULL",
                )
                .bind(identity_id)
                .execute(&state.pool)
                .await?;
                sqlx::query(
                    "UPDATE users SET status = 'active', updated_at = now()
                      WHERE id = $1 AND status IN ('pending', 'disabled', 'locked', 'frozen')",
                )
                .bind(identity_id)
                .execute(&state.pool)
                .await?;
            }
        }
        "auth.identity.credentials_changed" => {
            if let Some(identity_id) = payload_uuid(payload, "identity_id") {
                sqlx::query("UPDATE users SET updated_at = now() WHERE id = $1")
                    .bind(identity_id)
                    .execute(&state.pool)
                    .await?;
            }
        }
        "auth.session.created" => {
            if let Some(identity_id) = payload_uuid(payload, "identity_id") {
                let ip = payload_str(payload, "ip");
                state.touch_login(identity_id, ip).await?;
            }
        }
        "auth.user_roles.changed" | "auth.permissions.changed" => {
            if let Some(identity_id) = payload_uuid(payload, "identity_id") {
                state.invalidate_permission_cache(Some(identity_id)).await;
            }
        }
        other => {
            tracing::debug!(event_type = other, "忽略未处理的认证事件");
        }
    }
    Ok(())
}

async fn ensure_placeholder(
    state: &AppState,
    tenant_id: Uuid,
    identity_id: Uuid,
    payload: &Value,
) -> AppResult<()> {
    let exists: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE id = $1")
        .bind(identity_id)
        .fetch_optional(&state.pool)
        .await?;
    if exists.is_some() {
        return Ok(());
    }
    let Some(username) = payload_str(payload, "username") else {
        return Ok(());
    };
    let mut tx = state.pool.begin().await?;
    let inserted = sqlx::query(
        "INSERT INTO users (id, tenant_id, username, email, email_verified, phone,
                            phone_verified, status, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', 'auth_event')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(identity_id)
    .bind(tenant_id)
    .bind(username)
    .bind(payload_str(payload, "email"))
    .bind(
        payload
            .get("email_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
    .bind(payload_str(payload, "phone"))
    .bind(
        payload
            .get("phone_verified")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        tx.rollback().await?;
        return Ok(());
    }
    sqlx::query("INSERT INTO user_profiles (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING")
        .bind(identity_id)
        .execute(&mut *tx)
        .await?;
    audit::record_in_tx(
        &mut tx,
        AuditEntry::new("user.provisioned_from_auth")
            .tenant(tenant_id)
            .resource("user", identity_id.to_string())
            .detail(json!({ "source": "auth.identity.registered" })),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

async fn sync_status(
    state: &AppState,
    tenant_id: Uuid,
    identity_id: Uuid,
    status: &str,
    soft_delete: bool,
) -> AppResult<()> {
    if soft_delete {
        sqlx::query(
            "UPDATE users SET status = 'deleted', deleted_at = COALESCE(deleted_at, now()),
                    updated_at = now()
              WHERE id = $1 AND status <> 'deleted'",
        )
        .bind(identity_id)
        .execute(&state.pool)
        .await?;
        return Ok(());
    }
    let current: Option<(String,)> = sqlx::query_as("SELECT status FROM users WHERE id = $1")
        .bind(identity_id)
        .fetch_optional(&state.pool)
        .await?;
    let Some((current,)) = current else {
        return Ok(());
    };
    if matches!(current.as_str(), "deleting" | "deleted") {
        return Ok(());
    }
    if status == "active"
        && !matches!(
            current.as_str(),
            "pending" | "disabled" | "locked" | "frozen"
        )
    {
        return Ok(());
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query("UPDATE users SET status = $2, updated_at = now() WHERE id = $1")
        .bind(identity_id)
        .bind(status)
        .execute(&mut *tx)
        .await?;
    audit::status_history(
        &mut tx,
        tenant_id,
        identity_id,
        Some(&current),
        status,
        Some("auth_identity_sync"),
        None,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}
