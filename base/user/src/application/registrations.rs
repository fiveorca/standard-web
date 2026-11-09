//! 注册业务、审核与第三方账号关联信息。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::application::users::CreateUserInput;
use crate::bootstrap::AppState;
use crate::domain::{AccountLink, RegistrationRecord};
use crate::shared::{
    is_valid_email, is_valid_phone, is_valid_username, normalize_email, normalize_phone,
    normalize_username, AppError, AppResult, Page, PageQuery, RequestMeta, DEFAULT_TENANT_ID,
};

#[derive(Debug, Clone, Deserialize)]
pub struct RegistrationInput {
    #[serde(default)]
    pub tenant_id: Option<Uuid>,
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    pub password: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub channel: Option<String>,
    #[serde(default)]
    pub campaign: Option<String>,
    #[serde(default)]
    pub invite_code: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReviewInput {
    pub approve: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AccountLinkInput {
    pub provider: String,
    pub provider_subject: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegistrationResult {
    pub user_id: Uuid,
    pub registration_id: Uuid,
    pub status: String,
    pub requires_review: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RegistrationListQuery {
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub page_size: Option<u32>,
    #[serde(default)]
    pub status: Option<String>,
}

impl AppState {
    pub async fn register_user(
        &self,
        input: &RegistrationInput,
        meta: &RequestMeta,
    ) -> AppResult<RegistrationResult> {
        if !self.config.registration.enabled {
            return Err(AppError::forbidden("当前未开放自助注册"));
        }
        let limit = self.config.registration.rate_limit_per_minute;
        let key = format!(
            "register:{}:{}",
            input.tenant_id.unwrap_or(DEFAULT_TENANT_ID),
            meta.ip.clone().unwrap_or_else(|| "unknown".to_string())
        );
        if !self
            .allow(&key, limit, std::time::Duration::from_secs(60))
            .await
        {
            return Err(AppError::Client {
                status: axum::http::StatusCode::TOO_MANY_REQUESTS,
                code: "too_many_requests",
                message: "注册请求过于频繁，请稍后再试".to_string(),
                details: None,
            });
        }
        if input.password.len() < 8 || input.password.len() > 128 {
            return Err(AppError::validation("password", "密码长度需在 8-128 之间"));
        }
        let username = normalize_username(&input.username);
        if !is_valid_username(&username) {
            return Err(AppError::validation("username", "用户名格式不正确"));
        }
        let email = input.email.as_deref().map(normalize_email);
        if let Some(email) = &email {
            if !is_valid_email(email) {
                return Err(AppError::validation("email", "邮箱格式不正确"));
            }
        }
        let phone = input.phone.as_deref().map(normalize_phone);
        if let Some(phone) = &phone {
            if !is_valid_phone(phone) {
                return Err(AppError::validation("phone", "手机号格式不正确"));
            }
        }
        let tenant_id = input.tenant_id.unwrap_or(DEFAULT_TENANT_ID);
        let requires_review = self.config.registration.require_review;
        let identity_status = if requires_review {
            "disabled"
        } else {
            "active"
        };
        let user_status = if requires_review { "pending" } else { "active" };

        let identity = self
            .auth
            .create_identity(json!({
                "tenant_id": tenant_id,
                "username": username,
                "email": email,
                "phone": phone,
                "password": input.password,
                "display_name": input.display_name,
                "status": identity_status,
                "email_verified": false,
                "phone_verified": false,
                "source": input.source.clone().unwrap_or_else(|| "registration".to_string()),
            }))
            .await?;

        let created = self
            .create_user(
                CreateUserInput {
                    id: Some(identity.id),
                    tenant_id,
                    username: username.clone(),
                    email: email.clone(),
                    phone: phone.clone(),
                    password: None,
                    display_name: input.display_name.clone(),
                    avatar_url: None,
                    status: Some(user_status.to_string()),
                    source: Some(
                        input
                            .source
                            .clone()
                            .unwrap_or_else(|| "registration".to_string()),
                    ),
                    remark: None,
                    tags: Vec::new(),
                    profile: None,
                    email_verified: false,
                    phone_verified: false,
                },
                Some(identity.id),
                meta,
            )
            .await;

        let user = match created {
            Ok(user) => user,
            Err(error) => {
                let _ = self
                    .auth
                    .update_status(identity.id, "deleted", Some("registration_failed"))
                    .await;
                return Err(error);
            }
        };

        let record = sqlx::query_as::<_, RegistrationRecord>(
            "INSERT INTO user_registration_records
                (tenant_id, user_id, username, email, phone, source, channel, campaign,
                 invite_code, status, payload)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
             RETURNING id, tenant_id, user_id, username, email, phone, source, channel, campaign,
                       invite_code, status, reviewer_id, reviewed_at, reject_reason, payload,
                       created_at, updated_at",
        )
        .bind(tenant_id)
        .bind(user.id)
        .bind(&username)
        .bind(&email)
        .bind(&phone)
        .bind(
            input
                .source
                .clone()
                .unwrap_or_else(|| "registration".to_string()),
        )
        .bind(input.channel.as_deref())
        .bind(input.campaign.as_deref())
        .bind(input.invite_code.as_deref())
        .bind(if requires_review {
            "pending"
        } else {
            "completed"
        })
        .bind(json!({
            "display_name": input.display_name,
        }))
        .fetch_one(&self.pool)
        .await?;

        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.registration.created")
                .tenant(tenant_id)
                .actor(Some(user.id))
                .resource("user", user.id.to_string())
                .detail(json!({
                    "registration_id": record.id,
                    "status": record.status,
                    "channel": record.channel,
                }));
            entry.request_context(meta);
            entry
        })
        .await?;

        Ok(RegistrationResult {
            user_id: user.id,
            registration_id: record.id,
            status: record.status,
            requires_review,
        })
    }

    pub async fn list_registrations(
        &self,
        tenant_id: Uuid,
        query: &RegistrationListQuery,
    ) -> AppResult<Page<RegistrationRecord>> {
        let page = PageQuery {
            page: query.page,
            page_size: query.page_size,
        };
        let total: i64 = match query.status.as_deref() {
            Some(status) => sqlx::query_scalar(
                "SELECT count(*) FROM user_registration_records WHERE tenant_id = $1 AND status = $2",
            )
            .bind(tenant_id)
            .bind(status)
            .fetch_one(&self.pool)
            .await?,
            None => sqlx::query_scalar(
                "SELECT count(*) FROM user_registration_records WHERE tenant_id = $1",
            )
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?,
        };
        let rows = match query.status.as_deref() {
            Some(status) => {
                sqlx::query_as::<_, RegistrationRecord>(
                    "SELECT id, tenant_id, user_id, username, email, phone, source, channel,
                            campaign, invite_code, status, reviewer_id, reviewed_at, reject_reason,
                            payload, created_at, updated_at
                       FROM user_registration_records
                      WHERE tenant_id = $1 AND status = $2
                      ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                )
                .bind(tenant_id)
                .bind(status)
                .bind(page.limit())
                .bind(page.offset())
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, RegistrationRecord>(
                    "SELECT id, tenant_id, user_id, username, email, phone, source, channel,
                            campaign, invite_code, status, reviewer_id, reviewed_at, reject_reason,
                            payload, created_at, updated_at
                       FROM user_registration_records
                      WHERE tenant_id = $1
                      ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                )
                .bind(tenant_id)
                .bind(page.limit())
                .bind(page.offset())
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(Page::new(rows, total, &page))
    }

    pub async fn get_registration(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> AppResult<RegistrationRecord> {
        sqlx::query_as::<_, RegistrationRecord>(
            "SELECT id, tenant_id, user_id, username, email, phone, source, channel, campaign,
                    invite_code, status, reviewer_id, reviewed_at, reject_reason, payload,
                    created_at, updated_at
               FROM user_registration_records WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("注册记录不存在"))
    }

    pub async fn review_registration(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: &ReviewInput,
        reviewer_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<RegistrationRecord> {
        let record = self.get_registration(tenant_id, id).await?;
        if record.status != "pending" {
            return Err(AppError::conflict("该注册记录已处理"));
        }
        let Some(user_id) = record.user_id else {
            return Err(AppError::conflict("注册记录未关联用户"));
        };
        if input.approve {
            self.change_status(
                tenant_id,
                user_id,
                "active",
                input.reason.as_deref().or(Some("registration_approved")),
                reviewer_id,
                meta,
            )
            .await?;
        } else {
            let reason = input.reason.as_deref().unwrap_or("registration_rejected");
            self.change_status(
                tenant_id,
                user_id,
                "disabled",
                Some(reason),
                reviewer_id,
                meta,
            )
            .await?;
            if let Err(error) = self
                .auth
                .update_status(user_id, "deleted", Some(reason))
                .await
            {
                tracing::warn!(user_id = %user_id, error = %error, "注册拒绝后同步认证身份失败");
            }
        }
        let updated = sqlx::query_as::<_, RegistrationRecord>(
            "UPDATE user_registration_records SET
                status = $3, reviewer_id = $4, reviewed_at = now(),
                reject_reason = $5, updated_at = now()
              WHERE id = $1 AND tenant_id = $2
             RETURNING id, tenant_id, user_id, username, email, phone, source, channel, campaign,
                       invite_code, status, reviewer_id, reviewed_at, reject_reason, payload,
                       created_at, updated_at",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(if input.approve {
            "approved"
        } else {
            "rejected"
        })
        .bind(reviewer_id)
        .bind(if input.approve {
            None
        } else {
            input.reason.as_deref()
        })
        .fetch_one(&self.pool)
        .await?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.registration.reviewed")
                .tenant(tenant_id)
                .actor(reviewer_id)
                .resource("registration", id.to_string())
                .detail(json!({
                    "approve": input.approve,
                    "reason": input.reason,
                }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(updated)
    }

    pub async fn list_account_links(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Vec<AccountLink>> {
        self.get_user(tenant_id, user_id).await?;
        let rows = sqlx::query_as::<_, AccountLink>(
            "SELECT id, tenant_id, user_id, provider, provider_subject, linked_at, last_login_at
               FROM user_account_links WHERE user_id = $1 ORDER BY linked_at DESC",
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn add_account_link(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        input: &AccountLinkInput,
        meta: &RequestMeta,
    ) -> AppResult<AccountLink> {
        self.get_user(tenant_id, user_id).await?;
        if input.provider.trim().is_empty() || input.provider_subject.trim().is_empty() {
            return Err(AppError::bad_request(
                "provider 与 provider_subject 不能为空",
            ));
        }
        let row = sqlx::query_as::<_, AccountLink>(
            "INSERT INTO user_account_links (tenant_id, user_id, provider, provider_subject)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (user_id, provider) DO UPDATE SET
                provider_subject = EXCLUDED.provider_subject
             RETURNING id, tenant_id, user_id, provider, provider_subject, linked_at, last_login_at",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(input.provider.trim())
        .bind(input.provider_subject.trim())
        .fetch_one(&self.pool)
        .await
        .map_err(|error| {
            if let sqlx::Error::Database(db_error) = &error {
                if db_error.code().as_deref() == Some("23505") {
                    return AppError::conflict("该第三方账号已关联其他用户");
                }
            }
            error.into()
        })?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.account_link.created")
                .tenant(tenant_id)
                .actor(Some(user_id))
                .resource("user", user_id.to_string())
                .detail(json!({ "provider": row.provider }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(row)
    }

    pub async fn remove_account_link(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        provider: &str,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        self.get_user(tenant_id, user_id).await?;
        let result = sqlx::query(
            "DELETE FROM user_account_links WHERE user_id = $1 AND provider = $2 AND tenant_id = $3",
        )
        .bind(user_id)
        .bind(provider)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::not_found("关联不存在"));
        }
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.account_link.removed")
                .tenant(tenant_id)
                .actor(Some(user_id))
                .resource("user", user_id.to_string())
                .detail(json!({ "provider": provider }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(())
    }

    pub async fn touch_account_link(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        provider: &str,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE user_account_links SET last_login_at = now()
              WHERE user_id = $1 AND provider = $2 AND tenant_id = $3",
        )
        .bind(user_id)
        .bind(provider)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// 外部身份冲突处理：返回当前 provider+subject 的关联用户。
    pub async fn find_account_link(
        &self,
        provider: &str,
        provider_subject: &str,
    ) -> AppResult<Option<AccountLink>> {
        let row = sqlx::query_as::<_, AccountLink>(
            "SELECT id, tenant_id, user_id, provider, provider_subject, linked_at, last_login_at
               FROM user_account_links WHERE provider = $1 AND provider_subject = $2",
        )
        .bind(provider)
        .bind(provider_subject)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// 管理端聚合：用户详情 + 注册记录。
    pub async fn user_registration(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Option<Value>> {
        let row: Option<(Uuid, String, Option<String>, Option<String>, Value)> = sqlx::query_as(
            "SELECT id, status, channel, campaign, payload FROM user_registration_records
              WHERE tenant_id = $1 AND user_id = $2 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|row| {
            json!({
                "id": row.0,
                "status": row.1,
                "channel": row.2,
                "campaign": row.3,
                "payload": row.4,
            })
        }))
    }
}
