//! MFA：TOTP、WebAuthn/Passkey、恢复码与管理员重置。

use chrono::Duration;
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::application::RequestMeta;
use crate::bootstrap::AppState;
use crate::domain::{DomainEvent, Identity, MfaFactor};
use crate::infrastructure::{outbox, redis};
use crate::security::totp;
use crate::shared::{constant_time_eq, now, AppError, AppResult};

const RECOVERY_CODE_COUNT: usize = 10;

#[derive(Debug, Clone, Serialize)]
pub struct TotpEnrollment {
    pub factor_id: Uuid,
    pub secret: String,
    pub provisioning_uri: String,
    pub issuer: String,
    pub account: String,
    pub digits: u32,
    pub step_secs: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecoveryCodeSet {
    pub codes: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MfaStatus {
    pub mfa_enabled: bool,
    pub mfa_enforced: bool,
    pub factors: Vec<MfaFactor>,
    pub recovery_codes_remaining: i64,
    pub webauthn_available: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebauthnCeremony {
    pub public_key: Value,
    pub ceremony: &'static str,
}

impl AppState {
    fn totp_issuer(&self) -> &str {
        &self.config.security.mfa.totp_issuer
    }

    fn totp_account(identity: &Identity) -> String {
        identity
            .email
            .clone()
            .or_else(|| identity.phone.clone())
            .unwrap_or_else(|| identity.username.clone())
    }

    pub async fn mfa_status(&self, identity: &Identity) -> AppResult<MfaStatus> {
        let factors = sqlx::query_as::<_, MfaFactor>(
            "SELECT * FROM mfa_factors WHERE identity_id = $1 AND status <> 'disabled' ORDER BY created_at",
        )
        .bind(identity.id)
        .fetch_all(&self.pool)
        .await?;
        let remaining = sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM mfa_recovery_codes WHERE identity_id = $1 AND used_at IS NULL",
        )
        .bind(identity.id)
        .fetch_one(&self.pool)
        .await?;
        Ok(MfaStatus {
            mfa_enabled: factors.iter().any(|factor| factor.status == "active"),
            mfa_enforced: identity.mfa_enforced,
            factors,
            recovery_codes_remaining: remaining,
            webauthn_available: self.webauthn.is_some(),
        })
    }

    /// 开始 TOTP 绑定，返回一次性明文密钥（仅本次响应可见）。
    pub async fn start_totp_enrollment(
        &self,
        identity: &Identity,
        name: Option<String>,
    ) -> AppResult<TotpEnrollment> {
        let name = name
            .unwrap_or_else(|| "Authenticator".to_string())
            .chars()
            .take(60)
            .collect::<String>();
        let secret = totp::generate_secret_base32();
        let encrypted = self.crypto.encrypt_str(&secret)?;
        let account = Self::totp_account(identity);
        let issuer = self.totp_issuer().to_string();
        let existing: Option<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM mfa_factors WHERE identity_id = $1 AND kind = 'totp' AND name = $2",
        )
        .bind(identity.id)
        .bind(&name)
        .fetch_optional(&self.pool)
        .await?;
        let factor_id = if let Some((id,)) = existing {
            sqlx::query(
                "UPDATE mfa_factors
                 SET status = 'pending', secret_encrypted = $2, credential = NULL,
                     verified_at = NULL, last_used_step = NULL
                 WHERE id = $1",
            )
            .bind(id)
            .bind(&encrypted)
            .execute(&self.pool)
            .await?;
            id
        } else {
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO mfa_factors (id, identity_id, kind, name, status, secret_encrypted)
                 VALUES ($1, $2, 'totp', $3, 'pending', $4)",
            )
            .bind(id)
            .bind(identity.id)
            .bind(&name)
            .bind(&encrypted)
            .execute(&self.pool)
            .await?;
            id
        };
        let uri = totp::provisioning_uri(&secret, &issuer, &account);
        audit::record(
            &self.pool,
            AuditEntry::new("auth.mfa.totp.enroll_started")
                .tenant(identity.tenant_id)
                .actor(identity.id)
                .resource("mfa_factor", factor_id.to_string()),
        )
        .await?;
        Ok(TotpEnrollment {
            factor_id,
            secret,
            provisioning_uri: uri,
            issuer,
            account,
            digits: 6,
            step_secs: 30,
        })
    }

    /// 确认 TOTP 绑定；首次启用时返回恢复码。
    pub async fn confirm_totp_enrollment(
        &self,
        identity: &Identity,
        factor_id: Uuid,
        code: &str,
    ) -> AppResult<Option<RecoveryCodeSet>> {
        let factor = self.load_factor(identity.id, factor_id).await?;
        if factor.kind != "totp" || factor.status == "disabled" {
            return Err(AppError::bad_request("该 MFA 因素不可用于 TOTP"));
        }
        let secret = self.crypto.decrypt_str(
            factor
                .secret_encrypted
                .as_deref()
                .ok_or_else(|| AppError::bad_request("MFA 因素尚未初始化"))?,
        )?;
        let account = Self::totp_account(identity);
        let step = totp::verify_code(&secret, self.totp_issuer(), &account, code)?
            .ok_or_else(|| AppError::bad_request("动态验证码不正确"))?;
        if factor
            .last_used_step
            .map(|used| step as i64 <= used)
            .unwrap_or(false)
        {
            return Err(AppError::bad_request(
                "动态验证码已被使用，请等待下一个验证码",
            ));
        }
        let was_enabled = self.has_active_factor(identity.id).await?;
        sqlx::query(
            "UPDATE mfa_factors
             SET status = 'active', verified_at = now(), last_used_step = $2,
                 last_used_at = now(), name = CASE WHEN name = '' THEN 'Authenticator' ELSE name END
             WHERE id = $1",
        )
        .bind(factor_id)
        .bind(step as i64)
        .execute(&self.pool)
        .await?;

        let mut tx = self.pool.begin().await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("auth.mfa.totp.enabled")
                .tenant(identity.tenant_id)
                .actor(identity.id)
                .resource("mfa_factor", factor_id.to_string()),
        )
        .await?;
        outbox::enqueue(
            &mut tx,
            &DomainEvent::new(
                "auth.mfa.enabled",
                "identity",
                identity.id.to_string(),
                json!({ "identity_id": identity.id, "kind": "totp", "tenant_id": identity.tenant_id }),
            ),
        )
        .await?;
        tx.commit().await?;

        if was_enabled {
            Ok(None)
        } else {
            Ok(Some(self.issue_recovery_codes(identity).await?))
        }
    }

    pub async fn verify_totp_for_login(&self, identity: &Identity, code: &str) -> AppResult<Uuid> {
        let factors = sqlx::query_as::<_, MfaFactor>(
            "SELECT * FROM mfa_factors WHERE identity_id = $1 AND kind = 'totp' AND status = 'active'",
        )
        .bind(identity.id)
        .fetch_all(&self.pool)
        .await?;
        let account = Self::totp_account(identity);
        for factor in &factors {
            let Some(encrypted) = &factor.secret_encrypted else {
                continue;
            };
            let secret = self.crypto.decrypt_str(encrypted)?;
            if let Some(step) = totp::verify_code(&secret, self.totp_issuer(), &account, code)? {
                if factor
                    .last_used_step
                    .map(|used| step as i64 <= used)
                    .unwrap_or(false)
                {
                    return Err(AppError::bad_request("动态验证码已被使用"));
                }
                sqlx::query(
                    "UPDATE mfa_factors SET last_used_step = $2, last_used_at = now() WHERE id = $1",
                )
                .bind(factor.id)
                .bind(step as i64)
                .execute(&self.pool)
                .await?;
                audit::record(
                    &self.pool,
                    AuditEntry::new("auth.mfa.verified")
                        .tenant(identity.tenant_id)
                        .actor(identity.id)
                        .resource("mfa_factor", factor.id.to_string())
                        .detail(json!({ "kind": "totp" })),
                )
                .await?;
                return Ok(factor.id);
            }
        }
        Err(AppError::bad_request("动态验证码不正确"))
    }

    /// 使用恢复码完成一次 MFA，恢复码立即失效。
    pub async fn verify_recovery_code(&self, identity: &Identity, code: &str) -> AppResult<Uuid> {
        let normalized: String = code
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .map(|ch| ch.to_ascii_uppercase())
            .collect();
        if normalized.len() < 8 {
            return Err(AppError::bad_request("恢复码格式不正确"));
        }
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT id, code_hash FROM mfa_recovery_codes
             WHERE identity_id = $1 AND used_at IS NULL",
        )
        .bind(identity.id)
        .fetch_all(&self.pool)
        .await?;
        for (id, encrypted) in rows {
            let plain = match self.crypto.decrypt_str(&encrypted) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let candidate: String = plain
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .map(|ch| ch.to_ascii_uppercase())
                .collect();
            if constant_time_eq(candidate.as_bytes(), normalized.as_bytes()) {
                sqlx::query("UPDATE mfa_recovery_codes SET used_at = now() WHERE id = $1")
                    .bind(id)
                    .execute(&self.pool)
                    .await?;
                audit::record(
                    &self.pool,
                    AuditEntry::new("auth.mfa.recovery_code_used")
                        .tenant(identity.tenant_id)
                        .actor(identity.id)
                        .resource("recovery_code", id.to_string()),
                )
                .await?;
                return Ok(id);
            }
        }
        Err(AppError::bad_request("恢复码无效或已被使用"))
    }

    pub async fn regenerate_recovery_codes(
        &self,
        identity: &Identity,
    ) -> AppResult<RecoveryCodeSet> {
        if !self.has_active_factor(identity.id).await? {
            return Err(AppError::bad_request("请先绑定至少一种 MFA 认证方式"));
        }
        let set = self.issue_recovery_codes(identity).await?;
        audit::record(
            &self.pool,
            AuditEntry::new("auth.mfa.recovery_codes.regenerated")
                .tenant(identity.tenant_id)
                .actor(identity.id),
        )
        .await?;
        Ok(set)
    }

    async fn issue_recovery_codes(&self, identity: &Identity) -> AppResult<RecoveryCodeSet> {
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE identity_id = $1")
            .bind(identity.id)
            .execute(&self.pool)
            .await?;
        let mut codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        for _ in 0..RECOVERY_CODE_COUNT {
            let raw: String = crate::shared::random_token(12)
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .map(|ch| ch.to_ascii_uppercase())
                .take(10)
                .collect();
            let code = format!("{}-{}", &raw[..5], &raw[5..10]);
            let encrypted = self.crypto.encrypt_str(&code)?;
            sqlx::query("INSERT INTO mfa_recovery_codes (identity_id, code_hash) VALUES ($1, $2)")
                .bind(identity.id)
                .bind(&encrypted)
                .execute(&self.pool)
                .await?;
            codes.push(code);
        }
        Ok(RecoveryCodeSet {
            codes,
            message: "请立即保存恢复码，每个恢复码只能使用一次，页面关闭后无法再次查看".to_string(),
        })
    }

    pub async fn disable_mfa_factor(
        &self,
        identity: &Identity,
        factor_id: Uuid,
        password: Option<&str>,
    ) -> AppResult<()> {
        self.reauthenticate(identity, password).await?;
        let factor = self.load_factor(identity.id, factor_id).await?;
        let active_count = self.active_factor_count(identity.id).await?;
        if identity.mfa_enforced && active_count <= 1 && factor.status == "active" {
            return Err(AppError::conflict(
                "当前安全策略强制启用 MFA，不能移除最后一个认证因素",
            ));
        }
        sqlx::query("DELETE FROM mfa_factors WHERE id = $1 AND identity_id = $2")
            .bind(factor_id)
            .bind(identity.id)
            .execute(&self.pool)
            .await?;
        if self.active_factor_count(identity.id).await? == 0 {
            sqlx::query("DELETE FROM mfa_recovery_codes WHERE identity_id = $1")
                .bind(identity.id)
                .execute(&self.pool)
                .await?;
        }
        let mut tx = self.pool.begin().await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("auth.mfa.factor.removed")
                .tenant(identity.tenant_id)
                .actor(identity.id)
                .resource("mfa_factor", factor_id.to_string())
                .detail(json!({ "kind": factor.kind })),
        )
        .await?;
        outbox::enqueue(
            &mut tx,
            &DomainEvent::new(
                "auth.mfa.disabled",
                "identity",
                identity.id.to_string(),
                json!({ "identity_id": identity.id, "kind": factor.kind, "tenant_id": identity.tenant_id }),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// 管理员重置 MFA（不能绕过审计）。
    pub async fn admin_reset_mfa(
        &self,
        identity_id: Uuid,
        actor_id: Uuid,
        meta: &RequestMeta,
        reason: Option<String>,
    ) -> AppResult<()> {
        let identity = self.get_identity(identity_id).await?;
        sqlx::query("DELETE FROM mfa_factors WHERE identity_id = $1")
            .bind(identity_id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM mfa_recovery_codes WHERE identity_id = $1")
            .bind(identity_id)
            .execute(&self.pool)
            .await?;
        self.revoke_all_sessions(identity_id, "mfa_admin_reset")
            .await?;
        let mut tx = self.pool.begin().await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("auth.mfa.admin_reset")
                .tenant(identity.tenant_id)
                .actor(actor_id)
                .resource("identity", identity_id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                )
                .detail(json!({ "reason": reason })),
        )
        .await?;
        outbox::enqueue(
            &mut tx,
            &DomainEvent::new(
                "auth.mfa.reset",
                "identity",
                identity_id.to_string(),
                json!({ "identity_id": identity_id, "actor_id": actor_id }),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    // ───────────────────────── WebAuthn ─────────────────────────

    pub async fn webauthn_registration_start(
        &self,
        identity: &Identity,
    ) -> AppResult<WebauthnCeremony> {
        let service = self
            .webauthn
            .as_ref()
            .ok_or_else(|| AppError::bad_request("WebAuthn 未启用"))?;
        let display_name = identity
            .display_name
            .clone()
            .unwrap_or_else(|| identity.username.clone());
        let (challenge, state) =
            service.start_registration(identity.id, &identity.username, &display_name)?;
        let redis = self.redis_or_err()?;
        redis::set_json(
            redis,
            &self.cache_key(&["mfa", "webauthn", "reg", &identity.id.to_string()]),
            &serde_json::to_value(&state)?,
            300,
        )
        .await?;
        Ok(WebauthnCeremony {
            public_key: serde_json::to_value(&challenge)?,
            ceremony: "registration",
        })
    }

    pub async fn webauthn_registration_finish(
        &self,
        identity: &Identity,
        response: Value,
        name: Option<String>,
    ) -> AppResult<MfaFactor> {
        let service = self
            .webauthn
            .as_ref()
            .ok_or_else(|| AppError::bad_request("WebAuthn 未启用"))?
            .clone();
        let redis = self.redis_or_err()?;
        let key = self.cache_key(&["mfa", "webauthn", "reg", &identity.id.to_string()]);
        let state: Value = redis::get_json(redis, &key)
            .await?
            .ok_or_else(|| AppError::bad_request("Passkey 注册会话已过期"))?;
        let passkey = service.finish_registration(&response, &state)?;
        redis::del(redis, &key).await?;
        let was_enabled = self.has_active_factor(identity.id).await?;
        let factor_id = Uuid::now_v7();
        let name = name
            .unwrap_or_else(|| "Passkey".to_string())
            .chars()
            .take(60)
            .collect::<String>();
        sqlx::query(
            "INSERT INTO mfa_factors
                (id, identity_id, kind, name, status, credential, verified_at)
             VALUES ($1, $2, 'webauthn', $3, 'active', $4, now())",
        )
        .bind(factor_id)
        .bind(identity.id)
        .bind(&name)
        .bind(serde_json::to_value(&passkey)?)
        .execute(&self.pool)
        .await?;
        if !was_enabled {
            let _ = self.issue_recovery_codes(identity).await?;
        }
        audit::record(
            &self.pool,
            AuditEntry::new("auth.mfa.webauthn.registered")
                .tenant(identity.tenant_id)
                .actor(identity.id)
                .resource("mfa_factor", factor_id.to_string()),
        )
        .await?;
        self.load_factor(identity.id, factor_id).await
    }

    pub async fn webauthn_login_start(&self, identity: &Identity) -> AppResult<WebauthnCeremony> {
        let service = self
            .webauthn
            .as_ref()
            .ok_or_else(|| AppError::bad_request("WebAuthn 未启用"))?
            .clone();
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT credential::text FROM mfa_factors
             WHERE identity_id = $1 AND kind = 'webauthn' AND status = 'active' AND credential IS NOT NULL",
        )
        .bind(identity.id)
        .fetch_all(&self.pool)
        .await?;
        let mut passkeys = Vec::new();
        for (raw,) in rows {
            let value: Value = serde_json::from_str(&raw)?;
            passkeys.push(crate::security::webauthn::passkey_from_json(&value)?);
        }
        let (challenge, state) = service.start_authentication(&passkeys)?;
        let redis = self.redis_or_err()?;
        redis::set_json(
            redis,
            &self.cache_key(&["mfa", "webauthn", "auth", &identity.id.to_string()]),
            &serde_json::to_value(&state)?,
            300,
        )
        .await?;
        Ok(WebauthnCeremony {
            public_key: serde_json::to_value(&challenge)?,
            ceremony: "authentication",
        })
    }

    pub async fn webauthn_login_finish(
        &self,
        identity: &Identity,
        response: Value,
    ) -> AppResult<Uuid> {
        let service = self
            .webauthn
            .as_ref()
            .ok_or_else(|| AppError::bad_request("WebAuthn 未启用"))?
            .clone();
        let redis = self.redis_or_err()?;
        let key = self.cache_key(&["mfa", "webauthn", "auth", &identity.id.to_string()]);
        let state: Value = redis::get_json(redis, &key)
            .await?
            .ok_or_else(|| AppError::bad_request("Passkey 认证会话已过期"))?;
        let result = service.finish_authentication(&response, &state)?;
        redis::del(redis, &key).await?;
        let credential_id = serde_json::to_value(result.cred_id())?;
        let factors = sqlx::query_as::<_, MfaFactor>(
            "SELECT * FROM mfa_factors
             WHERE identity_id = $1 AND kind = 'webauthn' AND status = 'active'",
        )
        .bind(identity.id)
        .fetch_all(&self.pool)
        .await?;
        for factor in factors {
            let Some(credential) = factor.credential.clone() else {
                continue;
            };
            if credential.get("cred_id") == Some(&credential_id) {
                sqlx::query(
                    "UPDATE mfa_factors SET sign_count = $2, last_used_at = now() WHERE id = $1",
                )
                .bind(factor.id)
                .bind(result.counter() as i64)
                .execute(&self.pool)
                .await?;
                audit::record(
                    &self.pool,
                    AuditEntry::new("auth.mfa.verified")
                        .tenant(identity.tenant_id)
                        .actor(identity.id)
                        .resource("mfa_factor", factor.id.to_string())
                        .detail(json!({ "kind": "webauthn" })),
                )
                .await?;
                return Ok(factor.id);
            }
        }
        Err(AppError::bad_request("Passkey 不属于该用户"))
    }

    // ───────────────────────── 辅助 ─────────────────────────

    async fn load_factor(&self, identity_id: Uuid, factor_id: Uuid) -> AppResult<MfaFactor> {
        sqlx::query_as::<_, MfaFactor>(
            "SELECT * FROM mfa_factors WHERE id = $1 AND identity_id = $2",
        )
        .bind(factor_id)
        .bind(identity_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("MFA 因素不存在"))
    }

    async fn active_factor_count(&self, identity_id: Uuid) -> AppResult<i64> {
        Ok(sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM mfa_factors WHERE identity_id = $1 AND status = 'active'",
        )
        .bind(identity_id)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn has_active_factor(&self, identity_id: Uuid) -> AppResult<bool> {
        Ok(self.active_factor_count(identity_id).await? > 0)
    }

    /// 高风险操作二次确认。
    pub async fn reauthenticate(
        &self,
        identity: &Identity,
        password: Option<&str>,
    ) -> AppResult<()> {
        let password =
            password.ok_or_else(|| AppError::bad_request("高风险操作需要重新验证密码"))?;
        let hash: Option<(String,)> = sqlx::query_as(
            "SELECT secret_hash FROM identity_credentials
             WHERE identity_id = $1 AND credential_type = 'password' AND revoked_at IS NULL",
        )
        .bind(identity.id)
        .fetch_optional(&self.pool)
        .await?;
        let Some((hash,)) = hash else {
            return Err(AppError::bad_request("账号未设置密码"));
        };
        let valid = self.password.verify(password.to_string(), hash).await?;
        if !valid {
            return Err(AppError::unauthorized("密码不正确"));
        }
        // 会话最近 5 分钟内通过 MFA 时不重复校验，避免过度打扰。
        let recent: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
            "SELECT last_used_at FROM mfa_factors
             WHERE identity_id = $1 AND last_used_at IS NOT NULL ORDER BY last_used_at DESC LIMIT 1",
        )
        .bind(identity.id)
        .fetch_optional(&self.pool)
        .await?;
        if let Some((used_at,)) = recent {
            if used_at > now() - Duration::minutes(5) {
                return Ok(());
            }
        }
        Ok(())
    }
}
