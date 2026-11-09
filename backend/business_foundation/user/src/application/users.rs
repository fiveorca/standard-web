//! 用户资料与账户生命周期。

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::application::{completeness, ContactsView, ProfileInput, UserView};
use crate::bootstrap::AppState;
use crate::domain::{User, UserProfile};
use crate::infrastructure::outbox::{self, OutboxEvent};
use crate::shared::{
    is_valid_email, is_valid_phone, is_valid_username, normalize_email, normalize_phone,
    normalize_username, AppError, AppResult, Page, PageQuery, RequestMeta,
};

pub const EVENT_USER_CREATED: &str = "user.created";
pub const EVENT_USER_STATUS_CHANGED: &str = "user.account_status.changed";
pub const EVENT_USER_DELETED: &str = "user.deleted";
pub const EVENT_USER_PROFILE_UPDATED: &str = "user.profile.updated";
pub const EVENT_ORG_CHANGED: &str = "user.organization.changed";
pub const EVENT_GROUP_CHANGED: &str = "user.group.changed";
pub const EVENT_CONTACT_CHANGED: &str = "user.contact.changed";

const USER_COLUMNS: &str = "u.id, u.tenant_id, u.username, u.email, u.email_verified, u.phone, \
     u.phone_verified, u.display_name, u.avatar_url, u.status, u.source, u.remark, \
     u.last_active_at, u.last_login_at, u.registered_at, u.version, u.created_at, \
     u.updated_at, u.deleted_at";

#[derive(Debug, Clone, Deserialize)]
pub struct CreateUserInput {
    #[serde(default)]
    pub id: Option<Uuid>,
    pub tenant_id: Uuid,
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub phone: Option<String>,
    /// 仅透传给认证中心，用户中心不保存密码。
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub remark: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub profile: Option<ProfileInput>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub phone_verified: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UpdateUserInput {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub remark: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserListQuery {
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub page_size: Option<u32>,
    #[serde(default)]
    pub keyword: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    #[serde(default)]
    pub group_id: Option<Uuid>,
    #[serde(default)]
    pub organization_id: Option<Uuid>,
    #[serde(default)]
    pub department_id: Option<Uuid>,
    #[serde(default)]
    pub attribute_code: Option<String>,
    #[serde(default)]
    pub attribute_value: Option<Value>,
    #[serde(default)]
    pub created_from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub created_to: Option<DateTime<Utc>>,
    #[serde(default)]
    pub sort: Option<String>,
}

impl UserListQuery {
    fn page_query(&self) -> PageQuery {
        PageQuery {
            page: self.page,
            page_size: self.page_size,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BatchUpdateItem {
    pub id: Uuid,
    #[serde(flatten)]
    pub patch: UpdateUserInput,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    pub success: usize,
    pub failed: usize,
    pub errors: Vec<Value>,
}

fn like_pattern(keyword: &str) -> String {
    let escaped = keyword
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_");
    format!("%{escaped}%")
}

fn validate_status(status: &str) -> AppResult<()> {
    if matches!(
        status,
        "active" | "pending" | "disabled" | "locked" | "frozen" | "deleting" | "deleted"
    ) {
        Ok(())
    } else {
        Err(AppError::validation("status", "不支持的用户状态"))
    }
}

fn auth_status(status: &str) -> &'static str {
    match status {
        "active" => "active",
        "pending" => "pending",
        "locked" => "locked",
        "deleting" => "deleting",
        "deleted" => "deleted",
        _ => "disabled",
    }
}

fn map_unique(error: sqlx::Error, field: &str) -> AppError {
    if let sqlx::Error::Database(db_error) = &error {
        if db_error.code().as_deref() == Some("23505") {
            return AppError::conflict(format!("{field} 已被使用"));
        }
    }
    error.into()
}

impl AppState {
    pub async fn create_user(
        &self,
        input: CreateUserInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<User> {
        let username = normalize_username(&input.username);
        if !is_valid_username(&username) {
            return Err(AppError::validation(
                "username",
                "用户名需以字母或数字开头，长度 3-64，仅允许字母、数字、点、下划线和短横线",
            ));
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
        let status = input.status.clone().unwrap_or_else(|| "active".to_string());
        validate_status(&status)?;
        let source = input
            .source
            .clone()
            .unwrap_or_else(|| "registration".to_string());

        self.assert_local_unique(
            input.tenant_id,
            &username,
            email.as_deref(),
            phone.as_deref(),
        )
        .await?;

        let id = match input.id {
            Some(id) => id,
            None => {
                let identity = self
                    .auth
                    .create_identity(json!({
                        "tenant_id": input.tenant_id,
                        "username": username,
                        "email": email,
                        "phone": phone,
                        "password": input.password,
                        "display_name": input.display_name,
                        "avatar_url": input.avatar_url,
                        "status": auth_status(&status),
                        "email_verified": input.email_verified,
                        "phone_verified": input.phone_verified,
                        "source": source,
                    }))
                    .await?;
                identity.id
            }
        };

        let mut tx = self.pool.begin().await?;
        let inserted = sqlx::query_as::<_, User>(
            "INSERT INTO users
                (id, tenant_id, username, email, email_verified, phone, phone_verified,
                 display_name, avatar_url, status, source, remark)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             RETURNING id, tenant_id, username, email, email_verified, phone, phone_verified,
                       display_name, avatar_url, status, source, remark, last_active_at,
                       last_login_at, registered_at, version, created_at, updated_at, deleted_at",
        )
        .bind(id)
        .bind(input.tenant_id)
        .bind(&username)
        .bind(&email)
        .bind(input.email_verified)
        .bind(&phone)
        .bind(input.phone_verified)
        .bind(input.display_name.as_deref())
        .bind(input.avatar_url.as_deref())
        .bind(&status)
        .bind(&source)
        .bind(input.remark.as_deref())
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| map_unique(error, "用户名/邮箱/手机号"))?;

        let profile = input.profile.clone().unwrap_or_default();
        let score = completeness(&inserted, None);
        sqlx::query(
            "INSERT INTO user_profiles
                (user_id, gender, birthday, bio, region, timezone, locale, website, company,
                 job_title, extra, completeness)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(id)
        .bind(profile.gender.as_deref())
        .bind(profile.birthday)
        .bind(profile.bio.as_deref())
        .bind(profile.region.as_deref())
        .bind(profile.timezone.as_deref())
        .bind(profile.locale.as_deref())
        .bind(profile.website.as_deref())
        .bind(profile.company.as_deref())
        .bind(profile.job_title.as_deref())
        .bind(profile.extra.clone().unwrap_or_else(|| json!({})))
        .bind(score)
        .execute(&mut *tx)
        .await?;

        if let Some(email) = &email {
            crate::application::contacts::insert_contact(
                &mut tx,
                input.tenant_id,
                id,
                "email",
                email,
                input.email_verified,
            )
            .await?;
        }
        if let Some(phone) = &phone {
            crate::application::contacts::insert_contact(
                &mut tx,
                input.tenant_id,
                id,
                "phone",
                phone,
                input.phone_verified,
            )
            .await?;
        }
        for tag in &input.tags {
            let tag = tag.trim();
            if tag.is_empty() {
                continue;
            }
            sqlx::query(
                "INSERT INTO user_tags (tenant_id, user_id, tag) VALUES ($1, $2, $3)
                 ON CONFLICT (user_id, tag) DO NOTHING",
            )
            .bind(input.tenant_id)
            .bind(id)
            .bind(tag)
            .execute(&mut *tx)
            .await?;
        }

        audit::status_history(
            &mut tx,
            input.tenant_id,
            id,
            None,
            &status,
            Some("user_created"),
            actor_id,
        )
        .await?;

        let mut entry = AuditEntry::new("user.created")
            .tenant(input.tenant_id)
            .actor(actor_id)
            .resource("user", id.to_string())
            .detail(json!({
                "username": username,
                "source": source,
                "status": status,
            }));
        entry.request_context(meta);
        audit::record_in_tx(&mut tx, entry).await?;

        outbox::enqueue(
            &mut tx,
            &OutboxEvent::new(
                EVENT_USER_CREATED,
                "user",
                id.to_string(),
                json!({
                    "identity_id": id,
                    "tenant_id": input.tenant_id,
                    "username": username,
                    "status": status,
                }),
            )
            .with_trace(meta.trace_id.clone()),
        )
        .await?;

        tx.commit().await?;
        Ok(inserted)
    }

    async fn assert_local_unique(
        &self,
        tenant_id: Uuid,
        username: &str,
        email: Option<&str>,
        phone: Option<&str>,
    ) -> AppResult<()> {
        let exists: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM users
              WHERE deleted_at IS NULL AND tenant_id = $1 AND lower(username) = lower($2)",
        )
        .bind(tenant_id)
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        if exists.is_some() {
            return Err(AppError::conflict("用户名已被使用"));
        }
        if let Some(email) = email {
            let exists: Option<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM users WHERE deleted_at IS NULL AND lower(email) = lower($1)",
            )
            .bind(email)
            .fetch_optional(&self.pool)
            .await?;
            if exists.is_some() {
                return Err(AppError::conflict("邮箱已被使用"));
            }
        }
        if let Some(phone) = phone {
            let exists: Option<(Uuid,)> =
                sqlx::query_as("SELECT id FROM users WHERE deleted_at IS NULL AND phone = $1")
                    .bind(phone)
                    .fetch_optional(&self.pool)
                    .await?;
            if exists.is_some() {
                return Err(AppError::conflict("手机号已被使用"));
            }
        }
        Ok(())
    }

    pub async fn get_user(&self, tenant_id: Uuid, id: Uuid) -> AppResult<User> {
        sqlx::query_as::<_, User>(&format!(
            "SELECT {USER_COLUMNS} FROM users u
              WHERE u.id = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL"
        ))
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("用户不存在"))
    }

    pub async fn get_user_view(&self, tenant_id: Uuid, id: Uuid) -> AppResult<UserView> {
        let user = self.get_user(tenant_id, id).await?;
        let profile = crate::application::load_profile(self, id).await?;
        let tags: Vec<String> =
            sqlx::query_scalar("SELECT tag FROM user_tags WHERE user_id = $1 ORDER BY tag")
                .bind(id)
                .fetch_all(&self.pool)
                .await?;
        Ok(UserView {
            user,
            profile,
            tags,
        })
    }

    pub async fn list_users(
        &self,
        tenant_id: Uuid,
        query: &UserListQuery,
    ) -> AppResult<Page<UserView>> {
        let page_query = query.page_query();
        let mut count_qb = QueryBuilder::new("SELECT count(*) FROM users u");
        push_user_filters(&mut count_qb, tenant_id, query);
        let total: i64 = count_qb.build_query_scalar().fetch_one(&self.pool).await?;

        let order = match query.sort.as_deref() {
            Some("created_at_asc") => "u.created_at ASC",
            Some("last_login_at") => "u.last_login_at DESC NULLS LAST",
            Some("username") => "lower(u.username) ASC",
            _ => "u.created_at DESC",
        };
        let mut qb = QueryBuilder::new(format!("SELECT {USER_COLUMNS} FROM users u"));
        push_user_filters(&mut qb, tenant_id, query);
        qb.push(format!(" ORDER BY {order} LIMIT "));
        qb.push_bind(page_query.limit());
        qb.push(" OFFSET ");
        qb.push_bind(page_query.offset());
        let users: Vec<User> = qb.build_query_as().fetch_all(&self.pool).await?;

        let ids: Vec<Uuid> = users.iter().map(|user| user.id).collect();
        let mut profiles: HashMap<Uuid, UserProfile> = HashMap::new();
        let mut tags: HashMap<Uuid, Vec<String>> = HashMap::new();
        if !ids.is_empty() {
            let rows: Vec<UserProfile> = sqlx::query_as(
                "SELECT user_id, gender, birthday, bio, region, timezone, locale, website,
                        company, job_title, extra, completeness, created_at, updated_at
                   FROM user_profiles WHERE user_id = ANY($1)",
            )
            .bind(&ids)
            .fetch_all(&self.pool)
            .await?;
            for profile in rows {
                profiles.insert(profile.user_id, profile);
            }
            let rows: Vec<(Uuid, String)> =
                sqlx::query_as("SELECT user_id, tag FROM user_tags WHERE user_id = ANY($1)")
                    .bind(&ids)
                    .fetch_all(&self.pool)
                    .await?;
            for (user_id, tag) in rows {
                tags.entry(user_id).or_default().push(tag);
            }
        }
        let items = users
            .into_iter()
            .map(|user| UserView {
                profile: profiles.remove(&user.id),
                tags: tags.remove(&user.id).unwrap_or_default(),
                user,
            })
            .collect::<Vec<_>>();
        Ok(Page::new(items, total, &page_query))
    }

    pub async fn update_user(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        patch: &UpdateUserInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<User> {
        let display_name = patch.display_name.as_deref().map(|value| value.trim());
        let avatar_url = patch.avatar_url.as_deref().map(str::trim);
        if let Some(url) = avatar_url {
            if !url.is_empty() && !(url.starts_with("https://") || url.starts_with("http://")) {
                return Err(AppError::validation(
                    "avatar_url",
                    "头像地址必须是 HTTP(S) URL",
                ));
            }
            if url.len() > 2048 {
                return Err(AppError::validation("avatar_url", "头像地址过长"));
            }
        }
        let user = self.get_user(tenant_id, id).await?;
        let updated = sqlx::query_as::<_, User>(
            "UPDATE users SET
                display_name = COALESCE($3, display_name),
                avatar_url = COALESCE($4, avatar_url),
                remark = COALESCE($5, remark),
                version = version + 1,
                updated_at = now()
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
             RETURNING id, tenant_id, username, email, email_verified, phone, phone_verified,
                       display_name, avatar_url, status, source, remark, last_active_at,
                       last_login_at, registered_at, version, created_at, updated_at, deleted_at",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(display_name.filter(|value| !value.is_empty()))
        .bind(avatar_url.filter(|value| !value.is_empty()))
        .bind(patch.remark.as_deref())
        .fetch_one(&self.pool)
        .await?;

        let profile = crate::application::load_profile(self, id).await?;
        let score = completeness(&updated, profile.as_ref());
        sqlx::query(
            "UPDATE user_profiles SET completeness = $2, updated_at = now() WHERE user_id = $1",
        )
        .bind(id)
        .bind(score)
        .execute(&self.pool)
        .await?;

        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.updated")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user", id.to_string());
            entry.request_context(meta);
            entry.detail(json!({
                "display_name_changed": updated.display_name != user.display_name,
                "avatar_changed": updated.avatar_url != user.avatar_url,
            }))
        })
        .await?;

        let mut tx = self.pool.begin().await?;
        outbox::enqueue(
            &mut tx,
            &OutboxEvent::new(
                EVENT_USER_PROFILE_UPDATED,
                "user",
                id.to_string(),
                json!({
                    "identity_id": id,
                    "tenant_id": tenant_id,
                    "display_name": updated.display_name,
                    "avatar_url": updated.avatar_url,
                }),
            )
            .with_trace(meta.trace_id.clone()),
        )
        .await?;
        tx.commit().await?;

        if let Err(error) = self
            .auth
            .sync_profile(
                id,
                updated.display_name.as_deref(),
                updated.avatar_url.as_deref(),
            )
            .await
        {
            tracing::warn!(user_id = %id, error = %error, "同步资料到认证中心失败，将由事件补偿");
        }
        Ok(updated)
    }

    pub async fn update_profile(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: &ProfileInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<UserProfile> {
        let user = self.get_user(tenant_id, id).await?;
        if let Some(gender) = &input.gender {
            if !matches!(gender.as_str(), "male" | "female" | "other" | "undisclosed") {
                return Err(AppError::validation("gender", "性别取值不合法"));
            }
        }
        if let Some(url) = &input.website {
            if !url.is_empty() && !(url.starts_with("https://") || url.starts_with("http://")) {
                return Err(AppError::validation(
                    "website",
                    "个人网站必须是 HTTP(S) URL",
                ));
            }
        }
        let existing = crate::application::load_profile(self, id).await?;
        let profile = sqlx::query_as::<_, UserProfile>(
            "INSERT INTO user_profiles
                (user_id, gender, birthday, bio, region, timezone, locale, website, company,
                 job_title, extra, completeness)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             ON CONFLICT (user_id) DO UPDATE SET
                gender = COALESCE(EXCLUDED.gender, user_profiles.gender),
                birthday = COALESCE(EXCLUDED.birthday, user_profiles.birthday),
                bio = COALESCE(EXCLUDED.bio, user_profiles.bio),
                region = COALESCE(EXCLUDED.region, user_profiles.region),
                timezone = COALESCE(EXCLUDED.timezone, user_profiles.timezone),
                locale = COALESCE(EXCLUDED.locale, user_profiles.locale),
                website = COALESCE(EXCLUDED.website, user_profiles.website),
                company = COALESCE(EXCLUDED.company, user_profiles.company),
                job_title = COALESCE(EXCLUDED.job_title, user_profiles.job_title),
                extra = user_profiles.extra || EXCLUDED.extra,
                updated_at = now()
             RETURNING user_id, gender, birthday, bio, region, timezone, locale, website,
                       company, job_title, extra, completeness, created_at, updated_at",
        )
        .bind(id)
        .bind(input.gender.as_deref())
        .bind(input.birthday)
        .bind(input.bio.as_deref())
        .bind(input.region.as_deref())
        .bind(input.timezone.as_deref())
        .bind(input.locale.as_deref())
        .bind(input.website.as_deref())
        .bind(input.company.as_deref())
        .bind(input.job_title.as_deref())
        .bind(input.extra.clone().unwrap_or_else(|| json!({})))
        .bind(completeness(&user, existing.as_ref()))
        .fetch_one(&self.pool)
        .await?;

        let score = completeness(&user, Some(&profile));
        sqlx::query("UPDATE user_profiles SET completeness = $2 WHERE user_id = $1")
            .bind(id)
            .bind(score)
            .execute(&self.pool)
            .await?;

        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.profile.updated")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user", id.to_string());
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(UserProfile {
            completeness: score,
            ..profile
        })
    }

    pub async fn set_tags(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        tags: &[String],
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<Vec<String>> {
        self.get_user(tenant_id, id).await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM user_tags WHERE user_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let mut saved = Vec::new();
        for tag in tags {
            let tag = tag.trim();
            if tag.is_empty() {
                continue;
            }
            sqlx::query(
                "INSERT INTO user_tags (tenant_id, user_id, tag) VALUES ($1, $2, $3)
                 ON CONFLICT (user_id, tag) DO NOTHING",
            )
            .bind(tenant_id)
            .bind(id)
            .bind(tag)
            .execute(&mut *tx)
            .await?;
            saved.push(tag.to_string());
        }
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.tags.updated")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user", id.to_string())
                .detail(json!({ "tags": saved }));
            entry.request_context(meta);
            entry
        })
        .await?;
        tx.commit().await?;
        Ok(saved)
    }

    pub async fn change_status(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
        reason: Option<&str>,
        operator_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<User> {
        validate_status(status)?;
        let user = self.get_user(tenant_id, id).await?;
        if user.status == status {
            return Ok(user);
        }
        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query_as::<_, User>(
            "UPDATE users SET status = $3, version = version + 1, updated_at = now()
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
             RETURNING id, tenant_id, username, email, email_verified, phone, phone_verified,
                       display_name, avatar_url, status, source, remark, last_active_at,
                       last_login_at, registered_at, version, created_at, updated_at, deleted_at",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(status)
        .fetch_one(&mut *tx)
        .await?;
        audit::status_history(
            &mut tx,
            tenant_id,
            id,
            Some(&user.status),
            status,
            reason,
            operator_id,
        )
        .await?;
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.status.changed")
                .tenant(tenant_id)
                .actor(operator_id)
                .resource("user", id.to_string())
                .detail(json!({ "from": user.status, "to": status, "reason": reason }));
            entry.request_context(meta);
            entry
        })
        .await?;
        outbox::enqueue(
            &mut tx,
            &OutboxEvent::new(
                EVENT_USER_STATUS_CHANGED,
                "user",
                id.to_string(),
                json!({
                    "identity_id": id,
                    "tenant_id": tenant_id,
                    "status": status,
                    "reason": reason,
                }),
            )
            .with_trace(meta.trace_id.clone()),
        )
        .await?;
        tx.commit().await?;

        if matches!(
            status,
            "disabled" | "frozen" | "locked" | "deleting" | "deleted"
        ) {
            if let Err(error) = self.auth.revoke_sessions(id).await {
                tracing::warn!(user_id = %id, error = %error, "撤销认证中心会话失败");
            }
        }
        if let Err(error) = self
            .auth
            .update_status(id, auth_status(status), reason)
            .await
        {
            tracing::warn!(user_id = %id, error = %error, "同步状态到认证中心失败，将由事件补偿");
        }
        Ok(updated)
    }

    pub async fn delete_user(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        reason: Option<&str>,
        operator_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let user = self.get_user(tenant_id, id).await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE users SET status = 'deleted', deleted_at = now(), version = version + 1,
                    updated_at = now()
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        audit::status_history(
            &mut tx,
            tenant_id,
            id,
            Some(&user.status),
            "deleted",
            reason,
            operator_id,
        )
        .await?;
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.deleted")
                .tenant(tenant_id)
                .actor(operator_id)
                .resource("user", id.to_string())
                .detail(json!({ "reason": reason }));
            entry.request_context(meta);
            entry
        })
        .await?;
        outbox::enqueue(
            &mut tx,
            &OutboxEvent::new(
                EVENT_USER_DELETED,
                "user",
                id.to_string(),
                json!({ "identity_id": id, "tenant_id": tenant_id, "reason": reason }),
            )
            .with_trace(meta.trace_id.clone()),
        )
        .await?;
        tx.commit().await?;

        let _ = self.auth.revoke_sessions(id).await;
        if let Err(error) = self.auth.update_status(id, "deleted", reason).await {
            tracing::warn!(user_id = %id, error = %error, "同步删除状态失败，将由事件补偿");
        }
        Ok(())
    }

    pub async fn restore_user(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        operator_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<User> {
        let row = sqlx::query_as::<_, User>(
            "UPDATE users SET status = 'active', deleted_at = NULL, version = version + 1,
                    updated_at = now()
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NOT NULL
             RETURNING id, tenant_id, username, email, email_verified, phone, phone_verified,
                       display_name, avatar_url, status, source, remark, last_active_at,
                       last_login_at, registered_at, version, created_at, updated_at, deleted_at",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("用户不存在或未被删除"))?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.restored")
                .tenant(tenant_id)
                .actor(operator_id)
                .resource("user", id.to_string());
            entry.request_context(meta);
            entry
        })
        .await?;
        let mut tx = self.pool.begin().await?;
        outbox::enqueue(
            &mut tx,
            &OutboxEvent::new(
                EVENT_USER_STATUS_CHANGED,
                "user",
                id.to_string(),
                json!({ "identity_id": id, "tenant_id": tenant_id, "status": "active" }),
            )
            .with_trace(meta.trace_id.clone()),
        )
        .await?;
        tx.commit().await?;
        let _ = self
            .auth
            .update_status(id, "active", Some("user_restored"))
            .await;
        Ok(row)
    }

    pub async fn batch_create(
        &self,
        inputs: Vec<CreateUserInput>,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<BatchResult> {
        if inputs.len() > self.config.batch.max_items {
            return Err(AppError::bad_request(format!(
                "单次最多处理 {} 条",
                self.config.batch.max_items
            )));
        }
        let mut result = BatchResult {
            success: 0,
            failed: 0,
            errors: Vec::new(),
        };
        for (index, input) in inputs.into_iter().enumerate() {
            let username = input.username.clone();
            match self.create_user(input, actor_id, meta).await {
                Ok(_) => result.success += 1,
                Err(error) => {
                    result.failed += 1;
                    result.errors.push(json!({
                        "index": index,
                        "username": username,
                        "error": error.to_string(),
                    }));
                }
            }
        }
        Ok(result)
    }

    pub async fn batch_update(
        &self,
        tenant_id: Uuid,
        items: Vec<BatchUpdateItem>,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<BatchResult> {
        if items.len() > self.config.batch.max_items {
            return Err(AppError::bad_request(format!(
                "单次最多处理 {} 条",
                self.config.batch.max_items
            )));
        }
        let mut result = BatchResult {
            success: 0,
            failed: 0,
            errors: Vec::new(),
        };
        for item in items {
            match self
                .update_user(tenant_id, item.id, &item.patch, actor_id, meta)
                .await
            {
                Ok(_) => result.success += 1,
                Err(error) => {
                    result.failed += 1;
                    result.errors.push(json!({
                        "id": item.id,
                        "error": error.to_string(),
                    }));
                }
            }
        }
        Ok(result)
    }

    pub async fn export_users_csv(
        &self,
        tenant_id: Uuid,
        query: &UserListQuery,
    ) -> AppResult<String> {
        let mut page_query = query.clone();
        page_query.page = Some(1);
        page_query.page_size = Some(200);
        let mut items = Vec::new();
        loop {
            let page = self.list_users(tenant_id, &page_query).await?;
            let count = page.items.len();
            items.extend(page.items);
            if count < 200 || items.len() as i64 >= page.total {
                break;
            }
            page_query.page = Some(page_query.page.unwrap_or(1) + 1);
        }
        let mut writer = csv::Writer::from_writer(Vec::new());
        writer
            .write_record([
                "id",
                "tenant_id",
                "username",
                "email",
                "email_verified",
                "phone",
                "phone_verified",
                "display_name",
                "status",
                "source",
                "registered_at",
                "tags",
            ])
            .map_err(|error| AppError::server_error(format!("生成导出文件失败: {error}")))?;
        for item in items {
            writer
                .write_record([
                    item.user.id.to_string(),
                    item.user.tenant_id.to_string(),
                    item.user.username.clone(),
                    item.user.email.clone().unwrap_or_default(),
                    item.user.email_verified.to_string(),
                    item.user.phone.clone().unwrap_or_default(),
                    item.user.phone_verified.to_string(),
                    item.user.display_name.clone().unwrap_or_default(),
                    item.user.status.clone(),
                    item.user.source.clone(),
                    item.user.registered_at.to_rfc3339(),
                    item.tags.join("|"),
                ])
                .map_err(|error| AppError::server_error(format!("生成导出文件失败: {error}")))?;
        }
        let bytes = writer
            .into_inner()
            .map_err(|error| AppError::server_error(format!("生成导出文件失败: {error}")))?;
        String::from_utf8(bytes)
            .map_err(|error| AppError::server_error(format!("导出文件编码错误: {error}")))
    }

    pub async fn import_users_csv(
        &self,
        tenant_id: Uuid,
        content: &str,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<BatchResult> {
        let mut reader = csv::ReaderBuilder::new()
            .trim(csv::Trim::All)
            .flexible(true)
            .from_reader(content.as_bytes());
        let headers = reader
            .headers()
            .map_err(|error| AppError::bad_request(format!("CSV 表头无效: {error}")))?
            .clone();
        let index = |name: &str| headers.iter().position(|header| header == name);
        let username_index =
            index("username").ok_or_else(|| AppError::bad_request("CSV 缺少 username 列"))?;
        let email_index = index("email");
        let phone_index = index("phone");
        let display_index = index("display_name");
        let status_index = index("status");
        let source_index = index("source");
        let password_index = index("password");
        let tags_index = index("tags");

        let mut result = BatchResult {
            success: 0,
            failed: 0,
            errors: Vec::new(),
        };
        for (row, record) in reader.records().enumerate() {
            if row >= self.config.batch.max_items {
                result.errors.push(json!({
                    "row": row + 2,
                    "error": format!("超过单次导入上限 {}", self.config.batch.max_items),
                }));
                break;
            }
            let record = match record {
                Ok(record) => record,
                Err(error) => {
                    result.failed += 1;
                    result
                        .errors
                        .push(json!({ "row": row + 2, "error": error.to_string() }));
                    continue;
                }
            };
            let get = |index: Option<usize>| {
                index
                    .and_then(|index| record.get(index))
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(str::to_string)
            };
            let input = CreateUserInput {
                id: None,
                tenant_id,
                username: get(Some(username_index)).unwrap_or_default(),
                email: get(email_index),
                phone: get(phone_index),
                password: get(password_index),
                display_name: get(display_index),
                avatar_url: None,
                status: get(status_index),
                source: get(source_index),
                remark: None,
                tags: get(tags_index)
                    .map(|value| {
                        value
                            .split('|')
                            .map(str::trim)
                            .filter(|tag| !tag.is_empty())
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default(),
                profile: None,
                email_verified: false,
                phone_verified: false,
            };
            let username = input.username.clone();
            match self.create_user(input, actor_id, meta).await {
                Ok(_) => result.success += 1,
                Err(error) => {
                    result.failed += 1;
                    result.errors.push(json!({
                        "row": row + 2,
                        "username": username,
                        "error": error.to_string(),
                    }));
                }
            }
        }
        Ok(result)
    }

    pub async fn ensure_user_from_context(
        &self,
        ctx: &crate::auth_client::AuthContext,
    ) -> AppResult<User> {
        if let Ok(user) = self.get_user(ctx.tenant_id, ctx.identity_id).await {
            return Ok(user);
        }
        let identity = self.auth.get_identity(ctx.identity_id).await?;
        if identity.tenant_id != ctx.tenant_id {
            return Err(AppError::forbidden("身份与租户不匹配"));
        }
        let score = completeness(
            &User {
                id: identity.id,
                tenant_id: identity.tenant_id,
                username: identity.username.clone(),
                email: identity.email.clone(),
                email_verified: identity.email_verified,
                phone: identity.phone.clone(),
                phone_verified: identity.phone_verified,
                display_name: identity.display_name.clone(),
                avatar_url: identity.avatar_url.clone(),
                status: "active".to_string(),
                source: "auth_sync".to_string(),
                remark: None,
                last_active_at: None,
                last_login_at: None,
                registered_at: Utc::now(),
                version: 0,
                created_at: Utc::now(),
                updated_at: Utc::now(),
                deleted_at: None,
            },
            None,
        );
        let mut tx = self.pool.begin().await?;
        let user = sqlx::query_as::<_, User>(
            "INSERT INTO users
                (id, tenant_id, username, email, email_verified, phone, phone_verified,
                 display_name, avatar_url, status, source)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'active', 'auth_sync')
             ON CONFLICT (id) DO UPDATE SET updated_at = now()
             RETURNING id, tenant_id, username, email, email_verified, phone, phone_verified,
                       display_name, avatar_url, status, source, remark, last_active_at,
                       last_login_at, registered_at, version, created_at, updated_at, deleted_at",
        )
        .bind(identity.id)
        .bind(identity.tenant_id)
        .bind(&identity.username)
        .bind(&identity.email)
        .bind(identity.email_verified)
        .bind(&identity.phone)
        .bind(identity.phone_verified)
        .bind(&identity.display_name)
        .bind(&identity.avatar_url)
        .fetch_one(&mut *tx)
        .await
        .map_err(|error| map_unique(error, "用户"))?;
        sqlx::query(
            "INSERT INTO user_profiles (user_id, completeness) VALUES ($1, $2)
             ON CONFLICT (user_id) DO NOTHING",
        )
        .bind(user.id)
        .bind(score)
        .execute(&mut *tx)
        .await?;
        if let Some(email) = &identity.email {
            crate::application::contacts::insert_contact(
                &mut tx,
                identity.tenant_id,
                identity.id,
                "email",
                email,
                identity.email_verified,
            )
            .await?;
        }
        if let Some(phone) = &identity.phone {
            crate::application::contacts::insert_contact(
                &mut tx,
                identity.tenant_id,
                identity.id,
                "phone",
                phone,
                identity.phone_verified,
            )
            .await?;
        }
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("user.auto_provisioned")
                .tenant(identity.tenant_id)
                .actor(Some(identity.id))
                .resource("user", identity.id.to_string())
                .detail(json!({ "source": "auth_sync" })),
        )
        .await?;
        tx.commit().await?;
        Ok(user)
    }

    pub async fn touch_login(&self, identity_id: Uuid, ip: Option<&str>) -> AppResult<()> {
        sqlx::query(
            "UPDATE users SET last_login_at = now(), last_active_at = now(), updated_at = now()
              WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(identity_id)
        .execute(&self.pool)
        .await?;
        if let Some(ip) = ip {
            tracing::debug!(identity_id = %identity_id, ip = %ip, "用户登录事件已同步");
        }
        Ok(())
    }

    pub async fn list_status_history(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> AppResult<Vec<crate::domain::StatusHistory>> {
        self.get_user(tenant_id, id).await?;
        let rows = sqlx::query_as::<_, crate::domain::StatusHistory>(
            "SELECT id, tenant_id, user_id, from_status, to_status, reason, operator_id, created_at
               FROM user_status_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 200",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn list_audit_logs(
        &self,
        tenant_id: Uuid,
        page: &PageQuery,
    ) -> AppResult<Page<Value>> {
        let total: i64 =
            sqlx::query_scalar("SELECT count(*) FROM user_audit_logs WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?;
        let rows: Vec<(
            i64,
            Uuid,
            Option<Uuid>,
            String,
            Option<String>,
            Option<String>,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Value,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT id, tenant_id, actor_id, action, resource_type, resource_id, result,
                    ip, user_agent, trace_id, detail, created_at
               FROM user_audit_logs WHERE tenant_id = $1
              ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(&self.pool)
        .await?;
        let items = rows
            .into_iter()
            .map(|row| {
                json!({
                    "id": row.0,
                    "tenant_id": row.1,
                    "actor_id": row.2,
                    "action": row.3,
                    "resource_type": row.4,
                    "resource_id": row.5,
                    "result": row.6,
                    "ip": row.7,
                    "user_agent": row.8,
                    "trace_id": row.9,
                    "detail": row.10,
                    "created_at": row.11,
                })
            })
            .collect();
        Ok(Page::new(items, total, page))
    }

    /// 用户详情聚合（联系人 + 分组 + 组织）。
    pub async fn user_detail(&self, tenant_id: Uuid, id: Uuid) -> AppResult<Value> {
        let view = self.get_user_view(tenant_id, id).await?;
        let contacts: ContactsView = self.list_contacts(tenant_id, id).await?;
        let groups: Vec<crate::domain::UserGroup> = self.list_user_groups(tenant_id, id).await?;
        let memberships = self.list_user_memberships(tenant_id, id).await?;
        let attributes = self.list_user_attribute_values(tenant_id, id).await?;
        Ok(json!({
            "user": view,
            "contacts": contacts,
            "groups": groups,
            "memberships": memberships,
            "attributes": attributes,
        }))
    }
}

fn push_user_filters(qb: &mut QueryBuilder<'_, Postgres>, tenant_id: Uuid, query: &UserListQuery) {
    qb.push(" WHERE u.deleted_at IS NULL AND u.tenant_id = ");
    qb.push_bind(tenant_id);
    if let Some(status) = query.status.as_deref().filter(|value| !value.is_empty()) {
        qb.push(" AND u.status = ");
        qb.push_bind(status.to_string());
    }
    if let Some(source) = query.source.as_deref().filter(|value| !value.is_empty()) {
        qb.push(" AND u.source = ");
        qb.push_bind(source.to_string());
    }
    if let Some(keyword) = query
        .keyword
        .as_deref()
        .filter(|value| !value.trim().is_empty())
    {
        let pattern = like_pattern(keyword.trim());
        qb.push(" AND (u.username ILIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" ESCAPE '\\' OR COALESCE(u.email, '') ILIKE ");
        qb.push_bind(pattern.clone());
        qb.push(" ESCAPE '\\' OR COALESCE(u.display_name, '') ILIKE ");
        qb.push_bind(pattern);
        qb.push(" ESCAPE '\\')");
    }
    if let Some(tag) = query.tag.as_deref().filter(|value| !value.is_empty()) {
        qb.push(" AND EXISTS (SELECT 1 FROM user_tags t WHERE t.user_id = u.id AND t.tag = ");
        qb.push_bind(tag.to_string());
        qb.push(")");
    }
    if let Some(group_id) = query.group_id {
        qb.push(" AND EXISTS (SELECT 1 FROM user_group_members m WHERE m.user_id = u.id AND m.group_id = ");
        qb.push_bind(group_id);
        qb.push(")");
    }
    if let Some(organization_id) = query.organization_id {
        qb.push(" AND EXISTS (SELECT 1 FROM organization_members om WHERE om.user_id = u.id AND om.left_at IS NULL AND om.organization_id = ");
        qb.push_bind(organization_id);
        qb.push(")");
    }
    if let Some(department_id) = query.department_id {
        qb.push(" AND EXISTS (SELECT 1 FROM department_members dm WHERE dm.user_id = u.id AND dm.left_at IS NULL AND dm.department_id = ");
        qb.push_bind(department_id);
        qb.push(")");
    }
    if let (Some(code), Some(value)) = (&query.attribute_code, &query.attribute_value) {
        qb.push(" AND EXISTS (SELECT 1 FROM user_attribute_values v JOIN user_attributes a ON a.id = v.attribute_id WHERE v.user_id = u.id AND lower(a.code) = lower(");
        qb.push_bind(code.clone());
        qb.push(") AND v.value = ");
        qb.push_bind(value.clone());
        qb.push(")");
    }
    if let Some(from) = query.created_from {
        qb.push(" AND u.created_at >= ");
        qb.push_bind(from);
    }
    if let Some(to) = query.created_to {
        qb.push(" AND u.created_at <= ");
        qb.push_bind(to);
    }
}
