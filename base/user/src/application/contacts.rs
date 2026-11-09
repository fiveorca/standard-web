//! 联系方式管理：邮箱与手机号的绑定、验证、换绑与解绑。

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::json;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::application::users::EVENT_CONTACT_CHANGED;
use crate::bootstrap::AppState;
use crate::domain::UserContact;
use crate::infrastructure::outbox::{self, OutboxEvent};
use crate::shared::{
    is_valid_email, is_valid_phone, mask_email, mask_phone, normalize_email, normalize_phone,
    AppError, AppResult, RequestMeta,
};

#[derive(Debug, Clone, Serialize)]
pub struct ContactView {
    pub id: Uuid,
    pub kind: String,
    pub value: String,
    pub verified: bool,
    pub is_primary: bool,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContactsView {
    pub items: Vec<ContactView>,
}

fn normalize(kind: &str, value: &str) -> AppResult<String> {
    match kind {
        "email" => {
            let value = normalize_email(value);
            if !is_valid_email(&value) {
                return Err(AppError::validation("value", "邮箱格式不正确"));
            }
            Ok(value)
        }
        "phone" => {
            let value = normalize_phone(value);
            if !is_valid_phone(&value) {
                return Err(AppError::validation("value", "手机号格式不正确"));
            }
            Ok(value)
        }
        _ => Err(AppError::bad_request("不支持的联系方式类型")),
    }
}

/// 在事务内写入（或更新）联系方式。
pub async fn insert_contact(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    user_id: Uuid,
    kind: &str,
    value: &str,
    verified: bool,
) -> AppResult<()> {
    let normalized = normalize(kind, value)?;
    let existing: Option<(Uuid, Uuid)> = sqlx::query_as(
        "SELECT id, user_id FROM user_contacts WHERE kind = $1 AND normalized_value = $2",
    )
    .bind(kind)
    .bind(&normalized)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some((_, owner)) = existing {
        if owner != user_id {
            return Err(AppError::conflict("该联系方式已被其他用户绑定"));
        }
        sqlx::query(
            "UPDATE user_contacts
                SET value = $3, verified = $4,
                    verified_at = CASE WHEN $4 THEN COALESCE(verified_at, now()) ELSE NULL END,
                    updated_at = now()
              WHERE kind = $1 AND normalized_value = $2",
        )
        .bind(kind)
        .bind(&normalized)
        .bind(value)
        .bind(verified)
        .execute(&mut **tx)
        .await?;
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO user_contacts
            (tenant_id, user_id, kind, value, normalized_value, verified, is_primary, verified_at)
         VALUES ($1, $2, $3, $4, $5, $6, TRUE, CASE WHEN $6 THEN now() ELSE NULL END)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(kind)
    .bind(value)
    .bind(&normalized)
    .bind(verified)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

impl AppState {
    pub async fn list_contacts(&self, tenant_id: Uuid, user_id: Uuid) -> AppResult<ContactsView> {
        self.get_user(tenant_id, user_id).await?;
        let rows = sqlx::query_as::<_, UserContact>(
            "SELECT id, tenant_id, user_id, kind, value, normalized_value, verified, is_primary,
                    verified_at, created_at, updated_at
               FROM user_contacts WHERE user_id = $1 ORDER BY kind, is_primary DESC, created_at",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        let items = rows
            .into_iter()
            .map(|row| ContactView {
                id: row.id,
                kind: row.kind.clone(),
                value: if row.kind == "email" {
                    mask_email(&row.value)
                } else {
                    mask_phone(&row.value)
                },
                verified: row.verified,
                is_primary: row.is_primary,
                verified_at: row.verified_at,
                created_at: row.created_at,
            })
            .collect();
        Ok(ContactsView { items })
    }

    pub async fn request_contact_change(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        channel: &str,
        value: &str,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let user = self.get_user(tenant_id, user_id).await?;
        let channel = match channel {
            "email" => "email",
            "phone" | "sms" => "sms",
            _ => return Err(AppError::bad_request("不支持的联系方式类型")),
        };
        let normalized = if channel == "email" {
            normalize_email(value)
        } else {
            normalize_phone(value)
        };
        if channel == "email" && !is_valid_email(&normalized) {
            return Err(AppError::validation("value", "邮箱格式不正确"));
        }
        if channel == "sms" && !is_valid_phone(&normalized) {
            return Err(AppError::validation("value", "手机号格式不正确"));
        }
        let key = format!("contact:{}:{}:{}", tenant_id, user.id, channel);
        if !self
            .allow(&key, 3, std::time::Duration::from_secs(60))
            .await
        {
            return Err(AppError::Client {
                status: axum::http::StatusCode::TOO_MANY_REQUESTS,
                code: "too_many_requests",
                message: "验证码发送过于频繁，请稍后再试".to_string(),
                details: None,
            });
        }
        self.auth
            .request_contact_change(user_id, channel, &normalized)
            .await?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.contact.verification_requested")
                .tenant(tenant_id)
                .actor(Some(user_id))
                .resource("user", user_id.to_string())
                .detail(json!({ "channel": channel }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(())
    }

    pub async fn confirm_contact_change(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        channel: &str,
        value: &str,
        code: &str,
        meta: &RequestMeta,
    ) -> AppResult<ContactsView> {
        self.get_user(tenant_id, user_id).await?;
        let kind = match channel {
            "email" => "email",
            "phone" | "sms" => "phone",
            _ => return Err(AppError::bad_request("不支持的联系方式类型")),
        };
        let normalized = normalize(kind, value)?;
        self.auth
            .confirm_contact_change(user_id, channel, &normalized, code)
            .await?;

        let mut tx = self.pool.begin().await?;
        insert_contact(&mut tx, tenant_id, user_id, kind, &normalized, true).await?;
        if kind == "email" {
            sqlx::query(
                "UPDATE users SET email = $2, email_verified = TRUE, updated_at = now(),
                        version = version + 1 WHERE id = $1",
            )
            .bind(user_id)
            .bind(&normalized)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE users SET phone = $2, phone_verified = TRUE, updated_at = now(),
                        version = version + 1 WHERE id = $1",
            )
            .bind(user_id)
            .bind(&normalized)
            .execute(&mut *tx)
            .await?;
        }
        audit::record_in_tx(
            &mut tx,
            {
                let mut entry = AuditEntry::new("user.contact.changed")
                    .tenant(tenant_id)
                    .actor(Some(user_id))
                    .resource("user", user_id.to_string())
                    .detail(json!({
                        "kind": kind,
                        "masked": if kind == "email" { mask_email(&normalized) } else { mask_phone(&normalized) },
                    }));
                entry.request_context(meta);
                entry
            },
        )
        .await?;
        outbox::enqueue(
            &mut tx,
            &OutboxEvent::new(
                EVENT_CONTACT_CHANGED,
                "user",
                user_id.to_string(),
                json!({ "identity_id": user_id, "tenant_id": tenant_id, "kind": kind, "verified": true }),
            )
            .with_trace(meta.trace_id.clone()),
        )
        .await?;
        tx.commit().await?;
        self.list_contacts(tenant_id, user_id).await
    }

    pub async fn unbind_contact(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        kind: &str,
        meta: &RequestMeta,
        actor_id: Option<Uuid>,
    ) -> AppResult<ContactsView> {
        let kind = match kind {
            "email" => "email",
            "phone" => "phone",
            _ => return Err(AppError::bad_request("不支持的联系方式类型")),
        };
        self.get_user(tenant_id, user_id).await?;
        self.auth.clear_contact(user_id, kind).await?;

        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM user_contacts WHERE user_id = $1 AND kind = $2")
            .bind(user_id)
            .bind(kind)
            .execute(&mut *tx)
            .await?;
        if kind == "email" {
            sqlx::query(
                "UPDATE users SET email = NULL, email_verified = FALSE, updated_at = now(),
                        version = version + 1 WHERE id = $1",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE users SET phone = NULL, phone_verified = FALSE, updated_at = now(),
                        version = version + 1 WHERE id = $1",
            )
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        }
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.contact.unbound")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user", user_id.to_string())
                .detail(json!({ "kind": kind }));
            entry.request_context(meta);
            entry
        })
        .await?;
        tx.commit().await?;
        self.list_contacts(tenant_id, user_id).await
    }

    /// 由认证中心驱动的联系方式同步（已验证）。
    pub async fn sync_verified_contact(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        kind: &str,
        value: &str,
        verified: bool,
    ) -> AppResult<()> {
        let mut tx = self.pool.begin().await?;
        insert_contact(&mut tx, tenant_id, user_id, kind, value, verified).await?;
        if kind == "email" {
            sqlx::query(
                "UPDATE users SET email = $2, email_verified = $3, updated_at = now()
                  WHERE id = $1",
            )
            .bind(user_id)
            .bind(value)
            .bind(verified)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE users SET phone = $2, phone_verified = $3, updated_at = now()
                  WHERE id = $1",
            )
            .bind(user_id)
            .bind(value)
            .bind(verified)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
}
