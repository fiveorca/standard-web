//! 会话与 Token 生命周期：登录、刷新轮换、登出、设备管理。

use chrono::{Duration, Utc};
use serde::Serialize;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::application::RequestMeta;
use crate::bootstrap::AppState;
use crate::domain::{
    AuthSession, DomainEvent, Identity, MfaPendingClaims, RefreshToken, TokenClaims,
    IDENTITY_ACTIVE, IDENTITY_PENDING,
};
use crate::infrastructure::{outbox, redis};
use crate::shared::{
    constant_time_eq, now, random_token, sha256_hex, unix_secs, AppError, AppResult,
};

pub const DEFAULT_CLIENT_ID: &str = "auth-console";
pub const ACR_PWD: &str = "urn:auth:acr:pwd";
pub const ACR_MFA: &str = "urn:auth:acr:mfa";

/// 登录上下文。
#[derive(Debug, Clone, Default)]
pub struct LoginContext {
    pub tenant_id: Uuid,
    pub client_id: Option<String>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub trace_id: Option<String>,
}

impl LoginContext {
    pub fn client_id(&self) -> String {
        self.client_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_CLIENT_ID.to_string())
    }

    pub fn meta(&self) -> RequestMeta {
        RequestMeta::new(
            self.ip.clone(),
            self.user_agent.clone(),
            self.trace_id.clone(),
        )
    }
}

/// 对外 Token 响应。
#[derive(Debug, Clone, Serialize)]
pub struct TokenBundle {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub scope: String,
    pub session_id: Uuid,
}

impl TokenBundle {
    pub fn csrf_token_placeholder(&self) -> String {
        String::new()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct TokenTtl {
    pub access_secs: i64,
    pub refresh_secs: i64,
    pub id_secs: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginOutcome {
    Authenticated {
        #[serde(flatten)]
        tokens: TokenBundle,
    },
    MfaRequired {
        mfa_token: String,
        factors: Vec<String>,
        expires_in: i64,
    },
}

/// 会话视图（不返回 Token）。
#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    pub id: Uuid,
    pub client_id: Option<String>,
    pub status: String,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub amr: Vec<String>,
    pub acr: String,
    pub created_at: chrono::DateTime<Utc>,
    pub last_seen_at: chrono::DateTime<Utc>,
    pub expires_at: chrono::DateTime<Utc>,
}

impl From<AuthSession> for SessionView {
    fn from(session: AuthSession) -> Self {
        let amr = session.amr_list();
        Self {
            id: session.id,
            client_id: session.client_id,
            status: session.status,
            ip: session.ip,
            user_agent: session.user_agent,
            device_id: session.device_id,
            device_name: session.device_name,
            amr,
            acr: session.acr,
            created_at: session.created_at,
            last_seen_at: session.last_seen_at,
            expires_at: session.expires_at,
        }
    }
}

impl AppState {
    fn default_ttl(&self) -> TokenTtl {
        TokenTtl {
            access_secs: self.config.security.access_token_ttl_secs as i64,
            refresh_secs: self.config.security.refresh_token_ttl_secs as i64,
            id_secs: self.config.security.id_token_ttl_secs as i64,
        }
    }

    /// 创建会话并写入 Redis 活跃标记。
    pub async fn create_session(
        &self,
        identity: &Identity,
        client_id: &str,
        amr: Vec<String>,
        acr: &str,
        ctx: &LoginContext,
    ) -> AppResult<AuthSession> {
        let session_id = Uuid::now_v7();
        let expires_at = now() + Duration::seconds(self.config.security.session_ttl_secs as i64);
        let amr_value = serde_json::to_value(&amr)?;
        sqlx::query(
            "INSERT INTO auth_sessions
                (id, identity_id, tenant_id, client_id, ip, user_agent, device_id, device_name,
                 amr, acr, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(session_id)
        .bind(identity.id)
        .bind(identity.tenant_id)
        .bind(client_id)
        .bind(&ctx.ip)
        .bind(&ctx.user_agent)
        .bind(&ctx.device_id)
        .bind(&ctx.device_name)
        .bind(&amr_value)
        .bind(acr)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        if let Some(redis) = &self.redis {
            redis::set_ex(
                redis,
                &self.session_key(session_id),
                "active",
                self.config.security.session_ttl_secs.max(1),
            )
            .await?;
        }
        self.get_session(session_id).await
    }

    pub async fn get_session(&self, session_id: Uuid) -> AppResult<AuthSession> {
        sqlx::query_as::<_, AuthSession>("SELECT * FROM auth_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| AppError::unauthorized("会话不存在"))
    }

    /// 签发 Access Token / ID Token / Refresh Token。
    pub async fn issue_token_bundle(
        &self,
        identity: &Identity,
        session: &AuthSession,
        client_id: &str,
        scope: &str,
        nonce: Option<String>,
        include_refresh: bool,
        ttl: Option<TokenTtl>,
    ) -> AppResult<TokenBundle> {
        let ttl = ttl.unwrap_or_else(|| self.default_ttl());
        let scopes: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
        let issued_at = unix_secs();
        let expires_at = issued_at + ttl.access_secs.max(60);
        let amr = session.amr_list();
        let access_claims = TokenClaims {
            iss: self.config.issuer(),
            sub: identity.id.to_string(),
            aud: self.access_audience().to_string(),
            exp: expires_at,
            iat: issued_at,
            nbf: issued_at,
            jti: Uuid::now_v7().to_string(),
            tenant_id: identity.tenant_id.to_string(),
            client_id: client_id.to_string(),
            scope: scopes.join(" "),
            sid: session.id.to_string(),
            amr: amr.clone(),
            acr: session.acr.clone(),
            typ: "access".to_string(),
            auth_time: Some(session.created_at.timestamp()),
            nonce: None,
            at_hash: None,
            name: identity.display_name.clone(),
            preferred_username: Some(identity.username.clone()),
            email: if scopes.iter().any(|item| item == "email") {
                identity.email.clone()
            } else {
                None
            },
            email_verified: if scopes.iter().any(|item| item == "email") {
                Some(identity.email_verified)
            } else {
                None
            },
            phone_number: if scopes.iter().any(|item| item == "phone") {
                identity.phone.clone()
            } else {
                None
            },
            phone_number_verified: if scopes.iter().any(|item| item == "phone") {
                Some(identity.phone_verified)
            } else {
                None
            },
            picture: if scopes.iter().any(|item| item == "profile") {
                identity.avatar_url.clone()
            } else {
                None
            },
        };
        let (access_token, _) = self.keys.sign(&access_claims).await?;

        let id_token = if scopes.iter().any(|item| item == "openid") {
            let id_claims = TokenClaims {
                aud: client_id.to_string(),
                jti: Uuid::now_v7().to_string(),
                typ: "id".to_string(),
                nonce: nonce.clone(),
                at_hash: Some(half_hash(&access_token)),
                exp: issued_at + ttl.id_secs.max(60),
                ..access_claims.clone()
            };
            Some(self.keys.sign(&id_claims).await?.0)
        } else {
            None
        };

        let refresh_token = if include_refresh {
            let raw = random_token(48);
            let token_hash = sha256_hex(&raw);
            sqlx::query(
                "INSERT INTO refresh_tokens
                    (session_id, identity_id, tenant_id, client_id, token_hash, family_id, scope,
                     expires_at, ip, user_agent)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
            )
            .bind(session.id)
            .bind(identity.id)
            .bind(identity.tenant_id)
            .bind(client_id)
            .bind(&token_hash)
            .bind(Uuid::now_v7())
            .bind(scopes.join(" "))
            .bind(now() + Duration::seconds(ttl.refresh_secs.max(60)))
            .bind(&session.ip)
            .bind(&session.user_agent)
            .execute(&self.pool)
            .await?;
            Some(raw)
        } else {
            None
        };

        Ok(TokenBundle {
            access_token,
            token_type: "Bearer",
            expires_in: ttl.access_secs,
            id_token,
            refresh_token,
            scope: scopes.join(" "),
            session_id: session.id,
        })
    }

    /// 密码登录。失败时统一返回模糊错误，防止账号枚举。
    pub async fn login_with_password(
        &self,
        tenant_id: Uuid,
        identifier: &str,
        password: &str,
        scope: &str,
        ctx: &LoginContext,
    ) -> AppResult<LoginOutcome> {
        let meta = ctx.meta();
        let found = self.identity_by_login(tenant_id, identifier).await?;
        let Some(found) = found else {
            // 与真实校验耗时接近，降低计时侧信道。
            let _ = self
                .password
                .verify(password.to_string(), self.dummy_password_hash.clone())
                .await?;
            self.audit_login_failure(tenant_id, identifier, ctx, "identity_not_found")
                .await?;
            return Err(AppError::unauthorized("账号或密码不正确"));
        };
        let identity = found.identity;

        if identity.deleted_at.is_some() || identity.status == "deleted" {
            return Err(AppError::unauthorized("账号或密码不正确"));
        }
        if identity.is_locked_now() {
            return Err(AppError::too_many_requests(
                "账号已临时锁定，请稍后再试",
                None,
            ));
        }
        if !matches!(identity.status.as_str(), IDENTITY_ACTIVE | IDENTITY_PENDING) {
            self.audit_login_failure(tenant_id, identifier, ctx, "identity_disabled")
                .await?;
            return Err(AppError::forbidden("账号已被禁用，请联系管理员"));
        }
        let Some(hash) = found.password_hash else {
            self.audit_login_failure(tenant_id, identifier, ctx, "password_not_set")
                .await?;
            return Err(AppError::unauthorized("账号或密码不正确"));
        };
        let valid = self.password.verify(password.to_string(), hash).await?;
        if !valid {
            self.record_failed_login(&identity, ctx).await?;
            return Err(AppError::unauthorized("账号或密码不正确"));
        }

        self.on_login_success(&identity, ctx).await?;
        let factors = self.active_mfa_factor_names(identity.id).await?;
        if !factors.is_empty() || identity.mfa_enforced {
            let mfa_token = self
                .issue_mfa_token(&identity, &ctx.client_id(), scope)
                .await?;
            audit::record(
                &self.pool,
                AuditEntry::new("auth.login.mfa_required")
                    .tenant(tenant_id)
                    .actor(identity.id)
                    .resource("identity", identity.id.to_string())
                    .request_context(meta.ip, meta.user_agent, meta.trace_id)
                    .detail(json!({ "factors": factors })),
            )
            .await?;
            return Ok(LoginOutcome::MfaRequired {
                mfa_token,
                factors,
                expires_in: 300,
            });
        }

        let tokens = self
            .complete_login(
                &identity,
                &ctx.client_id(),
                scope,
                vec!["pwd".to_string()],
                ACR_PWD,
                None,
                ctx,
            )
            .await?;
        Ok(LoginOutcome::Authenticated { tokens })
    }

    /// 验证码登录。
    pub async fn login_with_otp(
        &self,
        tenant_id: Uuid,
        identifier: &str,
        channel: &str,
        code: &str,
        scope: &str,
        ctx: &LoginContext,
    ) -> AppResult<LoginOutcome> {
        let found = self
            .identity_by_login(tenant_id, identifier)
            .await?
            .ok_or_else(|| AppError::unauthorized("验证码不正确"))?;
        let identity = found.identity;
        if !matches!(identity.status.as_str(), IDENTITY_ACTIVE | IDENTITY_PENDING) {
            return Err(AppError::forbidden("账号已被禁用，请联系管理员"));
        }
        let target = match channel {
            "email" => identity.email.clone(),
            "sms" => identity.phone.clone(),
            _ => None,
        }
        .ok_or_else(|| AppError::bad_request("账号未绑定对应的联系方式"))?;
        let linked = self
            .consume_verification_code("login", channel, &target, code)
            .await?;
        if linked != Some(identity.id) {
            return Err(AppError::bad_request("验证码不正确"));
        }
        self.on_login_success(&identity, ctx).await?;
        let factors = self.active_mfa_factor_names(identity.id).await?;
        if !factors.is_empty() || identity.mfa_enforced {
            let mfa_token = self
                .issue_mfa_token(&identity, &ctx.client_id(), scope)
                .await?;
            return Ok(LoginOutcome::MfaRequired {
                mfa_token,
                factors,
                expires_in: 300,
            });
        }
        let tokens = self
            .complete_login(
                &identity,
                &ctx.client_id(),
                scope,
                vec!["otp".to_string()],
                ACR_PWD,
                None,
                ctx,
            )
            .await?;
        Ok(LoginOutcome::Authenticated { tokens })
    }

    /// 完成登录：创建会话、签发 Token、记录审计与事件。
    pub async fn complete_login(
        &self,
        identity: &Identity,
        client_id: &str,
        scope: &str,
        amr: Vec<String>,
        acr: &str,
        nonce: Option<String>,
        ctx: &LoginContext,
    ) -> AppResult<TokenBundle> {
        let session = self
            .create_session(identity, client_id, amr, acr, ctx)
            .await?;
        let bundle = self
            .issue_token_bundle(identity, &session, client_id, scope, nonce, true, None)
            .await?;

        let meta = ctx.meta();
        let mut tx = self.pool.begin().await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("auth.login.succeeded")
                .tenant(identity.tenant_id)
                .actor(identity.id)
                .resource("session", session.id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                )
                .detail(json!({
                    "client_id": client_id,
                    "session_id": session.id,
                    "amr": session.amr_list(),
                    "acr": session.acr,
                })),
        )
        .await?;
        outbox::enqueue(
            &mut tx,
            &DomainEvent::new(
                "auth.session.created",
                "session",
                session.id.to_string(),
                json!({
                    "session_id": session.id,
                    "identity_id": identity.id,
                    "tenant_id": identity.tenant_id,
                    "client_id": client_id,
                    "ip": meta.ip,
                }),
            )
            .with_trace(meta.trace_id.clone()),
        )
        .await?;
        tx.commit().await?;
        Ok(bundle)
    }

    /// 刷新 Token，执行一次性轮换。检测到重放时撤销整个 Token 家族。
    pub async fn refresh_tokens(
        &self,
        refresh_token: &str,
        client_id: Option<&str>,
        ip: Option<String>,
        user_agent: Option<String>,
    ) -> AppResult<TokenBundle> {
        let token_hash = sha256_hex(refresh_token.trim());
        let row =
            sqlx::query_as::<_, RefreshToken>("SELECT * FROM refresh_tokens WHERE token_hash = $1")
                .bind(&token_hash)
                .fetch_optional(&self.pool)
                .await?
                .ok_or_else(|| AppError::invalid_grant("Refresh Token 无效"))?;

        if let Some(client_id) = client_id {
            if client_id != row.client_id {
                return Err(AppError::invalid_grant("Refresh Token 不属于该客户端"));
            }
        }
        if row.status != "active" {
            self.revoke_token_family(row.family_id, "refresh_token_replayed")
                .await?;
            self.revoke_session(row.session_id, "refresh_token_replayed")
                .await?;
            audit::record(
                &self.pool,
                AuditEntry::new("auth.refresh.replayed")
                    .tenant(row.tenant_id)
                    .actor(row.identity_id)
                    .resource("refresh_token", row.id.to_string())
                    .result("denied")
                    .request_context(ip.clone(), user_agent.clone(), None),
            )
            .await?;
            return Err(AppError::invalid_grant("Refresh Token 已失效"));
        }
        if row.expires_at < now() {
            sqlx::query("UPDATE refresh_tokens SET status = 'expired' WHERE id = $1")
                .bind(row.id)
                .execute(&self.pool)
                .await?;
            return Err(AppError::invalid_grant("Refresh Token 已过期"));
        }

        let session = self.get_session(row.session_id).await?;
        if session.status != "active" || session.expires_at < now() {
            return Err(AppError::invalid_grant("会话已失效"));
        }
        let identity = self.get_identity(row.identity_id).await?;
        if !matches!(identity.status.as_str(), IDENTITY_ACTIVE | IDENTITY_PENDING) {
            return Err(AppError::invalid_grant("账号状态不允许刷新"));
        }

        let mut tx = self.pool.begin().await?;
        let updated = sqlx::query(
            "UPDATE refresh_tokens SET status = 'rotated', rotated_at = now()
             WHERE id = $1 AND status = 'active'",
        )
        .bind(row.id)
        .execute(&mut *tx)
        .await?;
        if updated.rows_affected() == 0 {
            tx.rollback().await?;
            self.revoke_token_family(row.family_id, "refresh_token_race")
                .await?;
            return Err(AppError::invalid_grant("Refresh Token 已被使用"));
        }

        let raw = random_token(48);
        let new_hash = sha256_hex(&raw);
        let expires_at =
            now() + Duration::seconds(self.config.security.refresh_token_ttl_secs as i64);
        sqlx::query(
            "INSERT INTO refresh_tokens
                (session_id, identity_id, tenant_id, client_id, token_hash, family_id, previous_id,
                 scope, expires_at, ip, user_agent)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(row.session_id)
        .bind(row.identity_id)
        .bind(row.tenant_id)
        .bind(&row.client_id)
        .bind(&new_hash)
        .bind(row.family_id)
        .bind(row.id)
        .bind(&row.scope)
        .bind(expires_at)
        .bind(&ip)
        .bind(&user_agent)
        .execute(&mut *tx)
        .await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("auth.token.refreshed")
                .tenant(row.tenant_id)
                .actor(row.identity_id)
                .resource("refresh_token", row.id.to_string())
                .request_context(ip.clone(), user_agent.clone(), None)
                .detail(json!({ "session_id": row.session_id, "client_id": row.client_id })),
        )
        .await?;
        tx.commit().await?;

        let bundle = self
            .issue_token_bundle(
                &identity,
                &session,
                &row.client_id,
                &row.scope,
                None,
                false,
                None,
            )
            .await?;
        Ok(TokenBundle {
            refresh_token: Some(raw),
            ..bundle
        })
    }

    /// 撤销单个会话及其 Refresh Token。
    pub async fn revoke_session(&self, session_id: Uuid, reason: &str) -> AppResult<()> {
        sqlx::query(
            "UPDATE auth_sessions SET status = 'revoked', revoked_at = now(), revoke_reason = $2
             WHERE id = $1 AND status = 'active'",
        )
        .bind(session_id)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE refresh_tokens SET status = 'revoked', revoked_at = now()
             WHERE session_id = $1 AND status = 'active'",
        )
        .bind(session_id)
        .execute(&self.pool)
        .await?;
        if let Some(redis) = &self.redis {
            redis::del(redis, &self.session_key(session_id)).await?;
        }
        Ok(())
    }

    /// 撤销某身份的全部会话。
    pub async fn revoke_all_sessions(&self, identity_id: Uuid, reason: &str) -> AppResult<()> {
        let sessions: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM auth_sessions WHERE identity_id = $1 AND status = 'active'",
        )
        .bind(identity_id)
        .fetch_all(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE auth_sessions SET status = 'revoked', revoked_at = now(), revoke_reason = $2
             WHERE identity_id = $1 AND status = 'active'",
        )
        .bind(identity_id)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        sqlx::query(
            "UPDATE refresh_tokens SET status = 'revoked', revoked_at = now()
             WHERE identity_id = $1 AND status = 'active'",
        )
        .bind(identity_id)
        .execute(&self.pool)
        .await?;
        if let Some(redis) = &self.redis {
            for (session_id,) in sessions {
                redis::del(redis, &self.session_key(session_id)).await?;
            }
        }
        Ok(())
    }

    pub async fn revoke_other_sessions(&self, identity_id: Uuid, keep: Uuid) -> AppResult<u64> {
        let sessions: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM auth_sessions WHERE identity_id = $1 AND status = 'active' AND id <> $2",
        )
        .bind(identity_id)
        .bind(keep)
        .fetch_all(&self.pool)
        .await?;
        let mut revoked = 0;
        for (session_id,) in sessions {
            self.revoke_session(session_id, "user_logout_others")
                .await?;
            revoked += 1;
        }
        Ok(revoked)
    }

    pub async fn revoke_by_device(&self, identity_id: Uuid, device_id: &str) -> AppResult<u64> {
        let sessions: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM auth_sessions
             WHERE identity_id = $1 AND device_id = $2 AND status = 'active'",
        )
        .bind(identity_id)
        .bind(device_id)
        .fetch_all(&self.pool)
        .await?;
        let mut revoked = 0;
        for (session_id,) in sessions {
            self.revoke_session(session_id, "device_revoked").await?;
            revoked += 1;
        }
        Ok(revoked)
    }

    /// 登出：撤销会话、Refresh Token，并把当前 Access Token 加入黑名单。
    pub async fn logout(
        &self,
        identity_id: Uuid,
        session_id: Uuid,
        access_jti: &str,
        access_exp: i64,
        all_devices: bool,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        if all_devices {
            self.revoke_all_sessions(identity_id, "user_logout_all")
                .await?;
        } else {
            self.revoke_session(session_id, "user_logout").await?;
        }
        if let Some(redis) = &self.redis {
            let ttl = (access_exp - unix_secs()).max(1) as u64;
            redis::set_ex(redis, &self.access_blacklist_key(access_jti), "1", ttl).await?;
        }
        let tenant: Option<(Uuid,)> =
            sqlx::query_as("SELECT tenant_id FROM identities WHERE id = $1")
                .bind(identity_id)
                .fetch_optional(&self.pool)
                .await?;
        audit::record(
            &self.pool,
            AuditEntry::new("auth.logout")
                .tenant(
                    tenant
                        .map(|row| row.0)
                        .unwrap_or(crate::shared::DEFAULT_TENANT_ID),
                )
                .actor(identity_id)
                .resource("session", session_id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                )
                .detail(json!({ "all_devices": all_devices })),
        )
        .await?;
        Ok(())
    }

    pub async fn list_sessions(
        &self,
        identity_id: Uuid,
        active_only: bool,
    ) -> AppResult<Vec<AuthSession>> {
        let rows = if active_only {
            sqlx::query_as::<_, AuthSession>(
                "SELECT * FROM auth_sessions
                 WHERE identity_id = $1 AND status = 'active' AND expires_at > now()
                 ORDER BY last_seen_at DESC",
            )
            .bind(identity_id)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as::<_, AuthSession>(
                "SELECT * FROM auth_sessions WHERE identity_id = $1 ORDER BY created_at DESC LIMIT 200",
            )
            .bind(identity_id)
            .fetch_all(&self.pool)
            .await?
        };
        Ok(rows)
    }

    pub async fn update_device(
        &self,
        identity_id: Uuid,
        session_id: Uuid,
        device_name: &str,
    ) -> AppResult<AuthSession> {
        let updated = sqlx::query(
            "UPDATE auth_sessions SET device_name = $3 WHERE id = $1 AND identity_id = $2",
        )
        .bind(session_id)
        .bind(identity_id)
        .bind(device_name.chars().take(120).collect::<String>())
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() == 0 {
            return Err(AppError::not_found("会话不存在"));
        }
        self.get_session(session_id).await
    }

    /// 登录历史（基于审计日志）。
    pub async fn login_history(
        &self,
        identity_id: Uuid,
        limit: i64,
    ) -> AppResult<Vec<crate::domain::AuditLog>> {
        let rows = sqlx::query_as::<_, crate::domain::AuditLog>(
            "SELECT id, tenant_id, actor_id, actor_type, action, resource_type, resource_id, result,
                    ip, user_agent, trace_id, detail, prev_hash, hash, created_at
             FROM security_audit_logs
             WHERE actor_id = $1 AND action LIKE 'auth.login.%'
             ORDER BY id DESC LIMIT $2",
        )
        .bind(identity_id)
        .bind(limit.clamp(1, 200))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// 签发 MFA 中间态 Token。
    pub async fn issue_mfa_token(
        &self,
        identity: &Identity,
        client_id: &str,
        scope: &str,
    ) -> AppResult<String> {
        let issued_at = unix_secs();
        let claims = MfaPendingClaims {
            iss: self.config.issuer(),
            sub: identity.id.to_string(),
            aud: self.access_audience().to_string(),
            exp: issued_at + 300,
            iat: issued_at,
            jti: Uuid::now_v7().to_string(),
            tenant_id: identity.tenant_id.to_string(),
            client_id: client_id.to_string(),
            typ: "mfa".to_string(),
            pending_mfa: true,
            scope: scope.to_string(),
        };
        Ok(self.keys.sign(&claims).await?.0)
    }

    pub async fn verify_mfa_token(&self, token: &str) -> AppResult<MfaPendingClaims> {
        let claims: MfaPendingClaims = self
            .keys
            .verify(token, Some(self.access_audience()))
            .await?;
        if claims.typ != "mfa" || !claims.pending_mfa {
            return Err(AppError::unauthorized("MFA Token 类型不正确"));
        }
        Ok(claims)
    }

    /// 完成第二步认证。
    pub async fn complete_mfa_login(
        &self,
        claims: &MfaPendingClaims,
        amr: Vec<String>,
        ctx: &LoginContext,
    ) -> AppResult<TokenBundle> {
        let identity_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::unauthorized("MFA Token 的 subject 非法"))?;
        let identity = self.get_identity(identity_id).await?;
        if !matches!(identity.status.as_str(), IDENTITY_ACTIVE | IDENTITY_PENDING) {
            return Err(AppError::forbidden("账号状态不允许登录"));
        }
        let client_id = claims.client_id.clone();
        let scope = if claims.scope.trim().is_empty() {
            self.config.oauth.default_scope.clone()
        } else {
            claims.scope.clone()
        };
        self.complete_login(&identity, &client_id, &scope, amr, ACR_MFA, None, ctx)
            .await
    }

    pub async fn active_mfa_factor_names(&self, identity_id: Uuid) -> AppResult<Vec<String>> {
        let rows: Vec<(String, String)> = sqlx::query_as(
            "SELECT kind, name FROM mfa_factors WHERE identity_id = $1 AND status = 'active' ORDER BY created_at",
        )
        .bind(identity_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(kind, name)| format!("{kind}:{name}"))
            .collect())
    }

    async fn revoke_token_family(&self, family_id: Uuid, reason: &str) -> AppResult<()> {
        sqlx::query(
            "UPDATE refresh_tokens SET status = 'revoked', revoked_at = now()
             WHERE family_id = $1 AND status IN ('active', 'rotated')",
        )
        .bind(family_id)
        .execute(&self.pool)
        .await?;
        tracing::warn!(%family_id, reason, "refresh token family revoked");
        Ok(())
    }

    async fn on_login_success(&self, identity: &Identity, ctx: &LoginContext) -> AppResult<()> {
        let previous_ip: Option<(Option<String>,)> =
            sqlx::query_as("SELECT last_login_ip FROM identities WHERE id = $1")
                .bind(identity.id)
                .fetch_optional(&self.pool)
                .await?;
        let new_device = previous_ip
            .and_then(|row| row.0)
            .map(|ip| ctx.ip.as_deref() != Some(ip.as_str()))
            .unwrap_or(false);
        sqlx::query(
            "UPDATE identities
             SET failed_attempts = 0, locked_until = NULL,
                 last_login_at = now(), last_login_ip = $2, updated_at = now()
             WHERE id = $1",
        )
        .bind(identity.id)
        .bind(&ctx.ip)
        .execute(&self.pool)
        .await?;
        if new_device {
            let meta = ctx.meta();
            audit::record(
                &self.pool,
                AuditEntry::new("auth.login.new_device")
                    .tenant(identity.tenant_id)
                    .actor(identity.id)
                    .resource("identity", identity.id.to_string())
                    .request_context(meta.ip, meta.user_agent, meta.trace_id)
                    .detail(json!({ "previous_ip_present": true })),
            )
            .await?;
        }
        Ok(())
    }

    async fn record_failed_login(&self, identity: &Identity, ctx: &LoginContext) -> AppResult<()> {
        let max = self.config.security.password.max_failed_attempts as i32;
        let attempts: (i32,) = sqlx::query_as(
            "UPDATE identities SET failed_attempts = failed_attempts + 1, updated_at = now()
             WHERE id = $1 RETURNING failed_attempts",
        )
        .bind(identity.id)
        .fetch_one(&self.pool)
        .await?;
        let mut locked = false;
        if attempts.0 >= max {
            let until =
                now() + Duration::seconds(self.config.security.password.lockout_secs as i64);
            sqlx::query(
                "UPDATE identities SET status = 'locked', locked_until = $2, updated_at = now() WHERE id = $1",
            )
            .bind(identity.id)
            .bind(until)
            .execute(&self.pool)
            .await?;
            locked = true;
        }
        let meta = ctx.meta();
        audit::record(
            &self.pool,
            AuditEntry::new("auth.login.failed")
                .tenant(identity.tenant_id)
                .actor(identity.id)
                .resource("identity", identity.id.to_string())
                .result("failure")
                .request_context(meta.ip, meta.user_agent, meta.trace_id)
                .detail(json!({ "attempts": attempts.0, "locked": locked })),
        )
        .await?;
        if locked {
            let mut tx = self.pool.begin().await?;
            outbox::enqueue(
                &mut tx,
                &DomainEvent::new(
                    "auth.identity.locked",
                    "identity",
                    identity.id.to_string(),
                    json!({
                        "identity_id": identity.id,
                        "tenant_id": identity.tenant_id,
                        "attempts": attempts.0,
                    }),
                ),
            )
            .await?;
            tx.commit().await?;
            self.revoke_all_sessions(identity.id, "account_locked")
                .await?;
        }
        Ok(())
    }

    async fn audit_login_failure(
        &self,
        tenant_id: Uuid,
        identifier: &str,
        ctx: &LoginContext,
        reason: &str,
    ) -> AppResult<()> {
        let meta = ctx.meta();
        audit::record(
            &self.pool,
            AuditEntry::new("auth.login.failed")
                .tenant(tenant_id)
                .result("failure")
                .request_context(meta.ip, meta.user_agent, meta.trace_id)
                .detail(json!({
                    "reason": reason,
                    "identifier_hash": sha256_hex(identifier.trim().to_ascii_lowercase())[..16].to_string(),
                })),
        )
        .await?;
        Ok(())
    }

    /// 校验客户端（供 OAuth 端点复用）。
    pub async fn verify_client_secret(
        &self,
        client_id: &str,
        client_secret: Option<&str>,
    ) -> AppResult<crate::domain::OAuthClient> {
        let client = sqlx::query_as::<_, crate::domain::OAuthClient>(
            "SELECT * FROM oauth_clients WHERE client_id = $1",
        )
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::invalid_client("客户端不存在"))?;
        if client.status != "active" {
            return Err(AppError::invalid_client("客户端已被禁用"));
        }
        if client.is_public() {
            return Ok(client);
        }
        let Some(expected) = &client.client_secret_hash else {
            return Err(AppError::invalid_client("客户端未配置密钥"));
        };
        let provided =
            client_secret.ok_or_else(|| AppError::invalid_client("缺少 client_secret"))?;
        // 使用 Argon2 校验客户端密钥。
        let valid = self
            .password
            .verify(provided.to_string(), expected.clone())
            .await?;
        if !valid {
            return Err(AppError::invalid_client("client_secret 不正确"));
        }
        Ok(client)
    }

    /// 检查会话是否有效（供独立服务 introspection 使用）。
    pub async fn session_is_active(&self, session_id: Uuid) -> bool {
        if let Some(redis) = &self.redis {
            return redis::get(redis, &self.session_key(session_id))
                .await
                .ok()
                .flatten()
                .as_deref()
                == Some("active");
        }
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM auth_sessions WHERE id = $1 AND status = 'active' AND expires_at > now())",
        )
        .bind(session_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false)
    }
}

/// OIDC `at_hash`：哈希后取左半部分并做 base64url。
fn half_hash(token: &str) -> String {
    let digest = crate::shared::sha256_bytes(token);
    crate::shared::b64url_encode(&digest[..digest.len() / 2])
}

/// 供外部调用：常量时间比较未使用告警消除。
pub fn client_secret_matches(provided: &str, expected_hash: &str) -> bool {
    constant_time_eq(provided.as_bytes(), expected_hash.as_bytes())
}

pub async fn count_active_sessions(pool: &PgPool, identity_id: Uuid) -> AppResult<i64> {
    Ok(sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM auth_sessions WHERE identity_id = $1 AND status = 'active' AND expires_at > now()",
    )
    .bind(identity_id)
    .fetch_one(pool)
    .await?)
}

pub fn session_event_payload(session: &AuthSession) -> Value {
    json!({
        "session_id": session.id,
        "identity_id": session.identity_id,
        "tenant_id": session.tenant_id,
        "client_id": session.client_id,
        "status": session.status,
    })
}

/// 供授权码兑换复用：判断 scope 是否请求刷新令牌。
pub fn wants_refresh(scope: &str) -> bool {
    scope
        .split_whitespace()
        .any(|item| item == "offline_access")
}

/// 兼容性辅助：从会话构造 `LoginContext`，用于 OAuth 授权码兑换后的登录审计。
pub fn context_from_session(session: &AuthSession) -> LoginContext {
    LoginContext {
        tenant_id: session.tenant_id,
        client_id: session.client_id.clone(),
        device_id: session.device_id.clone(),
        device_name: session.device_name.clone(),
        ip: session.ip.clone(),
        user_agent: session.user_agent.clone(),
        trace_id: None,
    }
}
