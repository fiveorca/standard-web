//! 身份、凭据、标识与验证码用例。

use chrono::{Duration, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::application::RequestMeta;
use crate::bootstrap::AppState;
use crate::domain::{
    DomainEvent, Identity, EVENT_CREDENTIALS_CHANGED, EVENT_IDENTITY_ACTIVATED,
    EVENT_IDENTITY_DELETED, EVENT_IDENTITY_DISABLED, EVENT_IDENTITY_REGISTERED, IDENTITY_ACTIVE,
    IDENTITY_DELETED, IDENTITY_DISABLED, IDENTITY_LOCKED, IDENTITY_PENDING,
};
use crate::infrastructure::outbox;
use crate::infrastructure::redis;
use crate::security::password::{hash_verification_code, validate_password};
use crate::shared::{
    constant_time_eq, is_valid_email, is_valid_phone, is_valid_username, normalize_email,
    normalize_phone, normalize_username, now, AppError, AppResult,
};

#[derive(Debug, Clone)]
pub struct CreateIdentityInput {
    pub tenant_id: Uuid,
    pub username: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub password: Option<String>,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub status: Option<String>,
    pub email_verified: bool,
    pub phone_verified: bool,
    pub metadata: Value,
    pub require_email_verification: bool,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct LoginIdentity {
    pub identity: Identity,
    pub password_hash: Option<String>,
}

impl AppState {
    pub async fn ensure_tenant(&self, tenant_id: Uuid) -> AppResult<()> {
        let exists: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM tenants WHERE id = $1 AND status = 'active' AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        if exists.is_none() {
            return Err(AppError::not_found("租户不存在或已被禁用"));
        }
        Ok(())
    }

    pub async fn get_identity(&self, identity_id: Uuid) -> AppResult<Identity> {
        sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(identity_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("身份不存在"))
    }

    pub async fn identity_by_login(
        &self,
        tenant_id: Uuid,
        identifier: &str,
    ) -> AppResult<Option<LoginIdentity>> {
        let (kind, normalized) = classify_identifier(identifier);
        let identity = sqlx::query_as::<_, Identity>(
            "SELECT i.* FROM identities i
             JOIN identity_identifiers ii ON ii.identity_id = i.id
             WHERE ii.kind = $1 AND ii.normalized_value = $2 AND i.tenant_id = $3
               AND i.deleted_at IS NULL",
        )
        .bind(kind)
        .bind(&normalized)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some(identity) = identity else {
            return Ok(None);
        };
        let password_hash: Option<(String,)> = sqlx::query_as(
            "SELECT secret_hash FROM identity_credentials
             WHERE identity_id = $1 AND credential_type = 'password'",
        )
        .bind(identity.id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(Some(LoginIdentity {
            identity,
            password_hash: password_hash.map(|row| row.0),
        }))
    }

    /// 创建身份（管理端 / 内部 API / 注册共用）。
    pub async fn create_identity(
        &self,
        input: CreateIdentityInput,
        meta: &RequestMeta,
    ) -> AppResult<Identity> {
        self.ensure_tenant(input.tenant_id).await?;

        let username = input.username.trim().to_string();
        if !is_valid_username(&username) {
            return Err(AppError::validation(
                "username",
                "用户名需为 3-64 位字母、数字或 ._-",
            ));
        }
        let normalized_username = normalize_username(&username);
        let email = input
            .email
            .as_deref()
            .map(normalize_email)
            .filter(|v| !v.is_empty());
        if let Some(email) = &email {
            if !is_valid_email(email) {
                return Err(AppError::validation("email", "邮箱格式不正确"));
            }
        }
        let phone = input
            .phone
            .as_deref()
            .map(normalize_phone)
            .filter(|v| !v.is_empty());
        if let Some(phone) = &phone {
            if !is_valid_phone(phone) {
                return Err(AppError::validation("phone", "手机号格式不正确"));
            }
        }

        if let Some(existing) = self
            .identifier_exists("username", &normalized_username)
            .await?
        {
            return Err(AppError::conflict(format!("用户名 {existing} 已被占用")));
        }
        if let Some(email) = &email {
            if let Some(existing) = self.identifier_exists("email", email).await? {
                return Err(AppError::conflict(format!("邮箱 {existing} 已被使用")));
            }
        }
        if let Some(phone) = &phone {
            if let Some(existing) = self.identifier_exists("phone", phone).await? {
                return Err(AppError::conflict(format!("手机号 {existing} 已被使用")));
            }
        }

        let password_hash = if let Some(password) = input.password.as_deref() {
            let mut fragments = vec![normalized_username.as_str()];
            if let Some(email) = &email {
                if let Some((local, _)) = email.split_once('@') {
                    fragments.push(local);
                }
            }
            if let Some(phone) = &phone {
                fragments.push(phone.as_str());
            }
            validate_password(password, &self.config.security.password, &fragments)?;
            Some(self.password.hash(password.to_string()).await?)
        } else {
            None
        };

        let status = input.status.unwrap_or_else(|| {
            if input.require_email_verification && email.is_some() && !input.email_verified {
                IDENTITY_PENDING.to_string()
            } else {
                IDENTITY_ACTIVE.to_string()
            }
        });
        if !matches!(
            status.as_str(),
            IDENTITY_PENDING | IDENTITY_ACTIVE | IDENTITY_DISABLED | IDENTITY_LOCKED
        ) {
            return Err(AppError::validation("status", "非法的初始状态"));
        }
        let identity_id = Uuid::now_v7();
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO identities
                (id, tenant_id, username, email, email_verified, phone, phone_verified,
                 display_name, avatar_url, status, metadata, password_updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(identity_id)
        .bind(input.tenant_id)
        .bind(&username)
        .bind(&email)
        .bind(input.email_verified)
        .bind(&phone)
        .bind(input.phone_verified)
        .bind(&input.display_name)
        .bind(&input.avatar_url)
        .bind(&status)
        .bind(&input.metadata)
        .bind(if password_hash.is_some() {
            Some(now())
        } else {
            None
        })
        .execute(&mut *tx)
        .await?;

        self.insert_identifier(
            &mut tx,
            identity_id,
            input.tenant_id,
            "username",
            &username,
            &normalized_username,
            true,
        )
        .await?;
        if let Some(email) = &email {
            self.insert_identifier(
                &mut tx,
                identity_id,
                input.tenant_id,
                "email",
                email,
                email,
                true,
            )
            .await?;
        }
        if let Some(phone) = &phone {
            self.insert_identifier(
                &mut tx,
                identity_id,
                input.tenant_id,
                "phone",
                phone,
                phone,
                true,
            )
            .await?;
        }
        if let Some(hash) = &password_hash {
            sqlx::query(
                "INSERT INTO identity_credentials (identity_id, credential_type, secret_hash)
                 VALUES ($1, 'password', $2)",
            )
            .bind(identity_id)
            .bind(hash)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO password_history (identity_id, password_hash) VALUES ($1, $2)",
            )
            .bind(identity_id)
            .bind(hash)
            .execute(&mut *tx)
            .await?;
        }

        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("identity.created")
                .tenant(input.tenant_id)
                .resource("identity", identity_id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                )
                .detail(json!({ "username": username, "source": input.source, "status": status })),
        )
        .await?;

        outbox::enqueue(
            &mut tx,
            &DomainEvent::new(
                EVENT_IDENTITY_REGISTERED,
                "identity",
                identity_id.to_string(),
                json!({
                    "identity_id": identity_id,
                    "tenant_id": input.tenant_id,
                    "username": username,
                    "email": email,
                    "email_verified": input.email_verified,
                    "phone": phone,
                    "phone_verified": input.phone_verified,
                    "display_name": input.display_name,
                    "avatar_url": input.avatar_url,
                    "status": status,
                    "metadata": input.metadata,
                    "source": input.source,
                }),
            )
            .with_trace(meta.trace_id.clone()),
        )
        .await?;
        tx.commit().await?;

        self.get_identity(identity_id).await
    }

    async fn insert_identifier(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        identity_id: Uuid,
        tenant_id: Uuid,
        kind: &str,
        value: &str,
        normalized: &str,
        primary: bool,
    ) -> AppResult<()> {
        sqlx::query(
            "INSERT INTO identity_identifiers
                (identity_id, tenant_id, kind, value, normalized_value, is_primary, verified_at)
             VALUES ($1, $2, $3, $4, $5, $6, NULL)",
        )
        .bind(identity_id)
        .bind(tenant_id)
        .bind(kind)
        .bind(value)
        .bind(normalized)
        .bind(primary)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    async fn identifier_exists(&self, kind: &str, normalized: &str) -> AppResult<Option<String>> {
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT value FROM identity_identifiers WHERE kind = $1 AND normalized_value = $2",
        )
        .bind(kind)
        .bind(normalized)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|item| item.0))
    }

    /// 修改身份状态，并同步会话、事件与授权缓存。
    pub async fn update_identity_status(
        &self,
        identity_id: Uuid,
        target: &str,
        reason: Option<String>,
        actor: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<Identity> {
        if !matches!(
            target,
            IDENTITY_ACTIVE | IDENTITY_DISABLED | IDENTITY_LOCKED | "deleting" | IDENTITY_DELETED
        ) {
            return Err(AppError::validation("status", "非法目标状态"));
        }
        let identity = self.get_identity(identity_id).await?;
        if identity.status == target {
            return Ok(identity);
        }
        if identity.status == IDENTITY_DELETED && target != IDENTITY_DELETED {
            return Err(AppError::conflict("已删除身份不能恢复到其他状态"));
        }

        let mut tx = self.pool.begin().await?;
        if target == IDENTITY_DELETED {
            sqlx::query(
                "UPDATE identities SET status = $2, status_reason = $3, deleted_at = now(), updated_at = now(), version = version + 1
                 WHERE id = $1",
            )
            .bind(identity_id)
            .bind(target)
            .bind(&reason)
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM identity_identifiers WHERE identity_id = $1")
                .bind(identity_id)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query(
                "UPDATE identities SET status = $2, status_reason = $3, locked_until = NULL,
                        failed_attempts = 0, updated_at = now(), version = version + 1
                 WHERE id = $1",
            )
            .bind(identity_id)
            .bind(target)
            .bind(&reason)
            .execute(&mut *tx)
            .await?;
        }

        let event_type = match target {
            IDENTITY_ACTIVE => EVENT_IDENTITY_ACTIVATED,
            IDENTITY_DISABLED | IDENTITY_LOCKED | "deleting" => EVENT_IDENTITY_DISABLED,
            IDENTITY_DELETED => EVENT_IDENTITY_DELETED,
            _ => EVENT_IDENTITY_ACTIVATED,
        };
        outbox::enqueue(
            &mut tx,
            &DomainEvent::new(
                event_type,
                "identity",
                identity_id.to_string(),
                json!({
                    "identity_id": identity_id,
                    "tenant_id": identity.tenant_id,
                    "status": target,
                    "reason": reason,
                }),
            )
            .with_trace(meta.trace_id.clone()),
        )
        .await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("identity.status_changed")
                .tenant(identity.tenant_id)
                .actor(actor.unwrap_or(identity_id))
                .resource("identity", identity_id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                )
                .detail(json!({ "from": identity.status, "to": target, "reason": reason })),
        )
        .await?;
        tx.commit().await?;

        if target != IDENTITY_ACTIVE {
            self.revoke_all_sessions(identity_id, "identity_status_changed")
                .await?;
        }
        self.authz.invalidate_tenant(identity.tenant_id).await?;
        self.get_identity(identity_id).await
    }

    /// 更新身份的基础资料字段（由用户中心事件同步）。
    pub async fn sync_identity_profile(
        &self,
        identity_id: Uuid,
        display_name: Option<String>,
        avatar_url: Option<String>,
        email: Option<String>,
        phone: Option<String>,
    ) -> AppResult<()> {
        let Some(identity) = sqlx::query_as::<_, Identity>(
            "SELECT * FROM identities WHERE id = $1 AND deleted_at IS NULL",
        )
        .bind(identity_id)
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(());
        };
        sqlx::query(
            "UPDATE identities SET display_name = COALESCE($2, display_name),
                    avatar_url = COALESCE($3, avatar_url), updated_at = now()
             WHERE id = $1",
        )
        .bind(identity_id)
        .bind(&display_name)
        .bind(&avatar_url)
        .execute(&self.pool)
        .await?;

        // 邮箱/手机号由认证中心权威维护，用户中心只允许同步已验证值。
        if let Some(email) = email.map(|value| normalize_email(&value)) {
            if is_valid_email(&email) && identity.email.as_deref() != Some(email.as_str()) {
                let mut tx = self.pool.begin().await?;
                sqlx::query(
                    "UPDATE identities SET email = $2, email_verified = TRUE, updated_at = now() WHERE id = $1",
                )
                .bind(identity_id)
                .bind(&email)
                .execute(&mut *tx)
                .await?;
                sqlx::query("UPDATE identity_identifiers SET value = $2, normalized_value = $2, verified_at = now() WHERE identity_id = $1 AND kind = 'email'")
                    .bind(identity_id)
                    .bind(&email)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
        }
        if let Some(phone) = phone.map(|value| normalize_phone(&value)) {
            if is_valid_phone(&phone) && identity.phone.as_deref() != Some(phone.as_str()) {
                let mut tx = self.pool.begin().await?;
                sqlx::query(
                    "UPDATE identities SET phone = $2, phone_verified = TRUE, updated_at = now() WHERE id = $1",
                )
                .bind(identity_id)
                .bind(&phone)
                .execute(&mut *tx)
                .await?;
                sqlx::query("UPDATE identity_identifiers SET value = $2, normalized_value = $2, verified_at = now() WHERE identity_id = $1 AND kind = 'phone'")
                    .bind(identity_id)
                    .bind(&phone)
                    .execute(&mut *tx)
                    .await?;
                tx.commit().await?;
            }
        }
        Ok(())
    }

    /// 发送验证码：生成、存储哈希并调用通知 Provider。
    pub async fn issue_verification_code(
        &self,
        tenant_id: Uuid,
        identity_id: Option<Uuid>,
        purpose: &str,
        channel: &str,
        target: &str,
    ) -> AppResult<()> {
        let otp = &self.config.security.otp;
        if let Some(redis) = &self.redis {
            let cooldown_key = self.cache_key(&["otp", "cooldown", purpose, channel, target]);
            if !redis::mark_once(redis, &cooldown_key, otp.resend_cooldown_secs).await? {
                return Err(AppError::too_many_requests(
                    "验证码发送过于频繁，请稍后再试",
                    Some(otp.resend_cooldown_secs),
                ));
            }
        }
        let code = crate::shared::util::random_numeric(otp.length.clamp(4, 10));
        let master = crate::config::decode_master_key(&self.config.security.master_key)
            .map_err(|_| AppError::server_error("主密钥不可用"))?;
        let code_hash = hash_verification_code(&master, purpose, target, &code);
        let expires_at = now() + Duration::seconds(otp.ttl_secs as i64);
        sqlx::query(
            "INSERT INTO verification_codes
                (tenant_id, identity_id, purpose, channel, target, code_hash, max_attempts, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(tenant_id)
        .bind(identity_id)
        .bind(purpose)
        .bind(channel)
        .bind(target)
        .bind(&code_hash)
        .bind(otp.max_attempts as i32)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        let (subject, body) = match purpose {
            "login" => (
                "登录验证码".to_string(),
                format!(
                    "您的登录验证码是 {code}，{} 分钟内有效。请勿泄露给他人。",
                    otp.ttl_secs / 60
                ),
            ),
            "reset_password" => (
                "重置密码验证码".to_string(),
                format!(
                    "您正在重置密码，验证码 {code}，{} 分钟内有效。如非本人操作请忽略。",
                    otp.ttl_secs / 60
                ),
            ),
            "verify_email" | "change_email" => (
                "邮箱验证码".to_string(),
                format!(
                    "您的邮箱验证码是 {code}，{} 分钟内有效。",
                    otp.ttl_secs / 60
                ),
            ),
            "verify_phone" | "change_phone" => (
                "手机验证码".to_string(),
                format!(
                    "您的手机验证码是 {code}，{} 分钟内有效。",
                    otp.ttl_secs / 60
                ),
            ),
            _ => (
                "安全验证码".to_string(),
                format!("您的验证码是 {code}，{} 分钟内有效。", otp.ttl_secs / 60),
            ),
        };
        if channel == "email" {
            self.notifier.send_email(target, &subject, &body).await?;
        } else {
            self.notifier.send_sms(target, &body).await?;
        }
        Ok(())
    }

    /// 校验并消费验证码。返回验证码关联的身份 ID（若存在）。
    pub async fn consume_verification_code(
        &self,
        purpose: &str,
        channel: &str,
        target: &str,
        code: &str,
    ) -> AppResult<Option<Uuid>> {
        let row: Option<(
            Uuid,
            Option<Uuid>,
            String,
            i32,
            i32,
            chrono::DateTime<Utc>,
            Option<chrono::DateTime<Utc>>,
        )> = sqlx::query_as(
            "SELECT id, identity_id, code_hash, attempts, max_attempts, expires_at, consumed_at
                 FROM verification_codes
                 WHERE purpose = $1 AND channel = $2 AND target = $3 AND consumed_at IS NULL
                 ORDER BY created_at DESC LIMIT 1",
        )
        .bind(purpose)
        .bind(channel)
        .bind(target)
        .fetch_optional(&self.pool)
        .await?;
        let Some((id, identity_id, code_hash, attempts, max_attempts, expires_at, _)) = row else {
            return Err(AppError::bad_request("验证码不存在或已使用"));
        };
        if expires_at < now() {
            return Err(AppError::bad_request("验证码已过期"));
        }
        if attempts >= max_attempts {
            sqlx::query("UPDATE verification_codes SET consumed_at = now() WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
            return Err(AppError::too_many_requests(
                "验证码尝试次数过多，请重新获取",
                None,
            ));
        }
        let master = crate::config::decode_master_key(&self.config.security.master_key)
            .map_err(|_| AppError::server_error("主密钥不可用"))?;
        let expected = hash_verification_code(&master, purpose, target, code.trim());
        if !constant_time_eq(expected.as_bytes(), code_hash.as_bytes()) {
            sqlx::query("UPDATE verification_codes SET attempts = attempts + 1 WHERE id = $1")
                .bind(id)
                .execute(&self.pool)
                .await?;
            return Err(AppError::bad_request("验证码不正确"));
        }
        sqlx::query("UPDATE verification_codes SET consumed_at = now() WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(identity_id)
    }

    /// 修改密码（已登录）。
    pub async fn change_password(
        &self,
        identity_id: Uuid,
        current_password: &str,
        new_password: &str,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let identity = self.get_identity(identity_id).await?;
        let row: Option<(String,)> = sqlx::query_as(
            "SELECT secret_hash FROM identity_credentials WHERE identity_id = $1 AND credential_type = 'password'",
        )
        .bind(identity_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some((hash,)) = row else {
            return Err(AppError::conflict(
                "该身份未设置密码，请先通过密码重置流程设置",
            ));
        };
        if !self
            .password
            .verify(current_password.to_string(), hash.clone())
            .await?
        {
            return Err(AppError::unauthorized("当前密码不正确"));
        }
        self.update_password(
            identity_id,
            &identity,
            new_password,
            "password.changed",
            meta,
        )
        .await?;
        self.revoke_all_sessions(identity_id, "password_changed")
            .await?;
        Ok(())
    }

    async fn update_password(
        &self,
        identity_id: Uuid,
        identity: &Identity,
        new_password: &str,
        action: &str,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let mut fragments = vec![normalize_username(&identity.username)];
        if let Some(email) = &identity.email {
            if let Some((local, _)) = email.split_once('@') {
                fragments.push(local.to_string());
            }
        }
        if let Some(phone) = &identity.phone {
            fragments.push(phone.clone());
        }
        let fragment_refs: Vec<&str> = fragments.iter().map(String::as_str).collect();
        validate_password(new_password, &self.config.security.password, &fragment_refs)?;

        let history: Vec<(String,)> = sqlx::query_as(
            "SELECT password_hash FROM password_history WHERE identity_id = $1 ORDER BY created_at DESC LIMIT $2",
        )
        .bind(identity_id)
        .bind(self.password.history_size() as i64)
        .fetch_all(&self.pool)
        .await?;
        for (hash,) in history {
            if self.password.verify(new_password.to_string(), hash).await? {
                return Err(AppError::validation(
                    "new_password",
                    "不能使用最近使用过的密码",
                ));
            }
        }

        let new_hash = self.password.hash(new_password.to_string()).await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE identity_credentials SET secret_hash = $2, updated_at = now(), expires_at = $3
             WHERE identity_id = $1 AND credential_type = 'password'",
        )
        .bind(identity_id)
        .bind(&new_hash)
        .bind(crate::shared::util::password_expires_at(
            self.config.security.password.expiry_days,
        ))
        .execute(&mut *tx)
        .await?;
        sqlx::query("INSERT INTO password_history (identity_id, password_hash) VALUES ($1, $2)")
            .bind(identity_id)
            .bind(&new_hash)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM password_history WHERE identity_id = $1 AND id NOT IN (
                SELECT id FROM password_history WHERE identity_id = $1 ORDER BY created_at DESC LIMIT $2
             )",
        )
        .bind(identity_id)
        .bind(self.password.history_size() as i64)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE identities SET password_updated_at = now(), updated_at = now() WHERE id = $1",
        )
        .bind(identity_id)
        .execute(&mut *tx)
        .await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new(action)
                .tenant(identity.tenant_id)
                .actor(identity_id)
                .resource("identity", identity_id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                ),
        )
        .await?;
        outbox::enqueue(
            &mut tx,
            &DomainEvent::new(
                EVENT_CREDENTIALS_CHANGED,
                "identity",
                identity_id.to_string(),
                json!({ "identity_id": identity_id, "tenant_id": identity.tenant_id, "reason": action }),
            )
            .with_trace(meta.trace_id.clone()),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// 发起密码重置（防枚举：无论账号是否存在都返回成功）。
    pub async fn request_password_reset(&self, tenant_id: Uuid, identifier: &str) -> AppResult<()> {
        let Some(found) = self.identity_by_login(tenant_id, identifier).await? else {
            return Ok(());
        };
        let identity = found.identity;
        let (channel, target) = if let Some(email) = &identity.email {
            ("email", email.clone())
        } else if let Some(phone) = &identity.phone {
            ("sms", phone.clone())
        } else {
            return Ok(());
        };
        self.issue_verification_code(
            tenant_id,
            Some(identity.id),
            "reset_password",
            channel,
            &target,
        )
        .await
    }

    /// 通过验证码重置密码。
    pub async fn reset_password(
        &self,
        tenant_id: Uuid,
        identifier: &str,
        code: &str,
        channel: &str,
        new_password: &str,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let Some(found) = self.identity_by_login(tenant_id, identifier).await? else {
            return Err(AppError::bad_request("验证码不正确"));
        };
        let identity = found.identity;
        let target = match channel {
            "email" => identity.email.clone(),
            "sms" => identity.phone.clone(),
            _ => None,
        }
        .ok_or_else(|| AppError::bad_request("身份没有可用于重置密码的联系方式"))?;
        let linked = self
            .consume_verification_code("reset_password", channel, &target, code)
            .await?;
        if linked != Some(identity.id) {
            return Err(AppError::bad_request("验证码不正确"));
        }

        // 若无密码记录，先补一条占位记录，随后由 update_password 覆盖。
        sqlx::query(
            "INSERT INTO identity_credentials (identity_id, credential_type, secret_hash)
             VALUES ($1, 'password', $2)
             ON CONFLICT (identity_id, credential_type) DO NOTHING",
        )
        .bind(identity.id)
        .bind("$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        .execute(&self.pool)
        .await?;
        self.update_password(identity.id, &identity, new_password, "password.reset", meta)
            .await?;
        self.revoke_all_sessions(identity.id, "password_reset")
            .await?;
        Ok(())
    }

    /// 标记邮箱/手机号已验证。
    pub async fn mark_contact_verified(
        &self,
        identity_id: Uuid,
        channel: &str,
        target: &str,
    ) -> AppResult<()> {
        let identity = self.get_identity(identity_id).await?;
        let mut tx = self.pool.begin().await?;
        match channel {
            "email" => {
                if normalize_email(target) != identity.email.clone().unwrap_or_default() {
                    return Err(AppError::bad_request("验证码目标与当前邮箱不一致"));
                }
                sqlx::query(
                    "UPDATE identities SET email_verified = TRUE, updated_at = now() WHERE id = $1",
                )
                .bind(identity_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query("UPDATE identity_identifiers SET verified_at = now() WHERE identity_id = $1 AND kind = 'email'")
                    .bind(identity_id)
                    .execute(&mut *tx)
                    .await?;
            }
            "sms" => {
                if normalize_phone(target) != identity.phone.clone().unwrap_or_default() {
                    return Err(AppError::bad_request("验证码目标与当前手机号不一致"));
                }
                sqlx::query(
                    "UPDATE identities SET phone_verified = TRUE, updated_at = now() WHERE id = $1",
                )
                .bind(identity_id)
                .execute(&mut *tx)
                .await?;
                sqlx::query("UPDATE identity_identifiers SET verified_at = now() WHERE identity_id = $1 AND kind = 'phone'")
                    .bind(identity_id)
                    .execute(&mut *tx)
                    .await?;
            }
            _ => return Err(AppError::bad_request("不支持的联系方式类型")),
        }
        tx.commit().await?;
        Ok(())
    }

    /// 修改邮箱或手机号：验证码验证通过后再切换标识。
    pub async fn change_contact(
        &self,
        identity_id: Uuid,
        channel: &str,
        new_value: &str,
        code: &str,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let identity = self.get_identity(identity_id).await?;
        let (kind, normalized, purpose) = match channel {
            "email" => {
                let normalized = normalize_email(new_value);
                if !is_valid_email(&normalized) {
                    return Err(AppError::validation("email", "邮箱格式不正确"));
                }
                ("email", normalized, "change_email")
            }
            "sms" | "phone" => {
                let normalized = normalize_phone(new_value);
                if !is_valid_phone(&normalized) {
                    return Err(AppError::validation("phone", "手机号格式不正确"));
                }
                ("phone", normalized, "change_phone")
            }
            _ => return Err(AppError::bad_request("不支持的联系方式类型")),
        };
        if self.identifier_exists(kind, &normalized).await?.is_some() {
            return Err(AppError::conflict("该联系方式已被其他账号使用"));
        }
        self.consume_verification_code(
            purpose,
            if channel == "email" { "email" } else { "sms" },
            &normalized,
            code,
        )
        .await?;

        let mut tx = self.pool.begin().await?;
        if kind == "email" {
            sqlx::query("UPDATE identities SET email = $2, email_verified = TRUE, updated_at = now() WHERE id = $1")
                .bind(identity_id)
                .bind(&normalized)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query("UPDATE identities SET phone = $2, phone_verified = TRUE, updated_at = now() WHERE id = $1")
                .bind(identity_id)
                .bind(&normalized)
                .execute(&mut *tx)
                .await?;
        }
        sqlx::query(
            "INSERT INTO identity_identifiers
                (identity_id, tenant_id, kind, value, normalized_value, verified_at, is_primary)
             VALUES ($1, $2, $3, $4, $4, now(), TRUE)
             ON CONFLICT (kind, normalized_value) DO UPDATE SET verified_at = now()",
        )
        .bind(identity_id)
        .bind(identity.tenant_id)
        .bind(kind)
        .bind(&normalized)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM identity_identifiers WHERE identity_id = $1 AND kind = $2 AND normalized_value <> $3")
            .bind(identity_id)
            .bind(kind)
            .bind(&normalized)
            .execute(&mut *tx)
            .await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("identity.contact_changed")
                .tenant(identity.tenant_id)
                .actor(identity_id)
                .resource("identity", identity_id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                )
                .detail(json!({ "channel": channel })),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// 解绑邮箱或手机号：清除身份上的主联系方式与对应标识记录。
    pub async fn clear_contact(
        &self,
        identity_id: Uuid,
        channel: &str,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let identity = self.get_identity(identity_id).await?;
        let kind = match channel {
            "email" => "email",
            "sms" | "phone" => "phone",
            _ => return Err(AppError::bad_request("不支持的联系方式类型")),
        };
        let mut tx = self.pool.begin().await?;
        if kind == "email" {
            sqlx::query(
                "UPDATE identities SET email = NULL, email_verified = FALSE, updated_at = now() WHERE id = $1",
            )
            .bind(identity_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE identities SET phone = NULL, phone_verified = FALSE, updated_at = now() WHERE id = $1",
            )
            .bind(identity_id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query("DELETE FROM identity_identifiers WHERE identity_id = $1 AND kind = $2")
            .bind(identity_id)
            .bind(kind)
            .execute(&mut *tx)
            .await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("identity.contact_unbound")
                .tenant(identity.tenant_id)
                .actor(identity_id)
                .resource("identity", identity_id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                )
                .detail(json!({ "channel": kind })),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }
}

fn classify_identifier(identifier: &str) -> (&'static str, String) {
    let trimmed = identifier.trim();
    if trimmed.contains('@') {
        ("email", normalize_email(trimmed))
    } else if trimmed.starts_with('+')
        || (trimmed.len() >= 6 && trimmed.chars().all(|c| c.is_ascii_digit()))
    {
        ("phone", normalize_phone(trimmed))
    } else {
        ("username", normalize_username(trimmed))
    }
}

/// 供内部 API 使用：按 ID 查找身份。
pub async fn find_identity(pool: &PgPool, identity_id: Uuid) -> AppResult<Option<Identity>> {
    Ok(
        sqlx::query_as::<_, Identity>("SELECT * FROM identities WHERE id = $1")
            .bind(identity_id)
            .fetch_optional(pool)
            .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_login_identifiers() {
        assert_eq!(classify_identifier("Alice@Example.com").0, "email");
        assert_eq!(classify_identifier("+8613800138000").0, "phone");
        assert_eq!(classify_identifier("alice").0, "username");
    }
}
