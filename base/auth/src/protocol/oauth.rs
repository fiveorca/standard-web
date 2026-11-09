//! OAuth 2.0 / OpenID Connect 1.0 授权服务器实现。

use chrono::Duration;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::application::session::{TokenBundle, TokenTtl, DEFAULT_CLIENT_ID};
use crate::bootstrap::AppState;
use crate::domain::{
    AuthContext, AuthorizationCode, DomainEvent, Identity, OAuthClient, OAuthConsent,
};
use crate::infrastructure::{outbox, redis};
use crate::security::pkce;
use crate::shared::{now, random_token, sha256_hex, unix_secs, AppError, AppResult};

const AUTHORIZATION_CODE_TTL_SECS: i64 = 300;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthorizeParams {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub prompt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingAuthorize {
    identity_id: Uuid,
    tenant_id: Uuid,
    client_id: String,
    redirect_uri: String,
    scope: String,
    state: Option<String>,
    nonce: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    session_id: Uuid,
    amr: Vec<String>,
    acr: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum AuthorizeOutcome {
    Redirect {
        location: String,
    },
    ConsentRequired {
        request_id: String,
        client_id: String,
        client_name: String,
        scopes: Vec<String>,
        redirect_uri: String,
        state: Option<String>,
        csrf_token: String,
    },
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: &'static str,
    pub expires_in: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    pub scope: String,
}

impl From<TokenBundle> for TokenResponse {
    fn from(bundle: TokenBundle) -> Self {
        Self {
            access_token: bundle.access_token,
            token_type: bundle.token_type,
            expires_in: bundle.expires_in,
            refresh_token: bundle.refresh_token,
            id_token: bundle.id_token,
            scope: bundle.scope,
        }
    }
}

impl AppState {
    pub async fn authorize(
        &self,
        ctx: &AuthContext,
        params: AuthorizeParams,
    ) -> AppResult<AuthorizeOutcome> {
        if !self.config.oauth.enabled {
            return Err(AppError::not_found("OAuth2 授权服务未启用"));
        }
        if params.response_type.as_deref() != Some("code") {
            return Err(AppError::bad_request("仅支持 response_type=code"));
        }
        let client_id = params
            .client_id
            .as_deref()
            .ok_or_else(|| AppError::bad_request("缺少 client_id"))?;
        let client = self.load_client(client_id).await?;
        if client.tenant_id != ctx.tenant_id {
            return Err(AppError::forbidden("客户端不属于当前租户"));
        }
        if !client.has_grant("authorization_code") {
            return Err(AppError::bad_request("客户端未启用 authorization_code"));
        }
        let redirect_uri = params
            .redirect_uri
            .as_deref()
            .ok_or_else(|| AppError::bad_request("缺少 redirect_uri"))?;
        if !client.redirect_uri_allowed(redirect_uri) {
            return Err(AppError::bad_request("redirect_uri 未注册或与注册值不匹配"));
        }
        let requested: Vec<String> = params
            .scope
            .as_deref()
            .unwrap_or(&self.config.oauth.default_scope)
            .split_whitespace()
            .map(str::to_string)
            .collect();
        for scope in &requested {
            if !client.allows_scope(scope) {
                return Err(AppError::bad_request(format!(
                    "客户端未被授予 scope: {scope}"
                )));
            }
        }
        let (challenge, method) = match (
            params.code_challenge.as_deref(),
            params.code_challenge_method.as_deref(),
        ) {
            (Some(challenge), Some(method)) => {
                if method != "S256" {
                    return Err(AppError::bad_request("仅支持 PKCE S256"));
                }
                (Some(challenge.to_string()), Some(method.to_string()))
            }
            (Some(challenge), None) => (Some(challenge.to_string()), Some("plain".to_string())),
            _ => (None, None),
        };
        if (client.require_pkce || client.is_public()) && challenge.is_none() {
            return Err(AppError::bad_request("该客户端必须使用 PKCE"));
        }
        let scope = requested.join(" ");

        let needs_consent = self
            .consent_required(ctx.identity_id, &client.client_id, &requested)
            .await?;
        if needs_consent || params.prompt.as_deref() == Some("consent") {
            let pending = PendingAuthorize {
                identity_id: ctx.identity_id,
                tenant_id: ctx.tenant_id,
                client_id: client.client_id.clone(),
                redirect_uri: redirect_uri.to_string(),
                scope: scope.clone(),
                state: params.state.clone(),
                nonce: params.nonce.clone(),
                code_challenge: challenge,
                code_challenge_method: method,
                session_id: ctx
                    .session_id
                    .ok_or_else(|| AppError::unauthorized("缺少会话"))?,
                amr: ctx.amr.clone(),
                acr: ctx.acr.clone(),
            };
            let request_id = random_token(24);
            let redis = self
                .redis
                .as_ref()
                .ok_or_else(|| AppError::unavailable("授权会话需要 Redis 支持"))?;
            let csrf = random_token(24);
            redis::set_json(
                redis,
                &self.cache_key(&["oauth", "pending", &request_id]),
                &json!({ "request": pending, "csrf": csrf }),
                600,
            )
            .await?;
            return Ok(AuthorizeOutcome::ConsentRequired {
                request_id,
                client_id: client.client_id.clone(),
                client_name: client.name.clone(),
                scopes: requested,
                redirect_uri: redirect_uri.to_string(),
                state: params.state.clone(),
                csrf_token: csrf,
            });
        }

        let location = self
            .issue_authorization_code(
                ctx.identity_id,
                ctx.tenant_id,
                ctx.session_id
                    .ok_or_else(|| AppError::unauthorized("缺少会话"))?,
                &client,
                redirect_uri,
                &scope,
                params.nonce,
                params.state,
                challenge,
                method,
                ctx.amr.clone(),
                ctx.acr.clone(),
            )
            .await?;
        Ok(AuthorizeOutcome::Redirect { location })
    }

    pub async fn submit_consent(
        &self,
        ctx: &AuthContext,
        request_id: &str,
        csrf_token: &str,
        approve: bool,
    ) -> AppResult<String> {
        let redis = self
            .redis
            .as_ref()
            .ok_or_else(|| AppError::unavailable("授权会话需要 Redis 支持"))?;
        let key = self.cache_key(&["oauth", "pending", request_id]);
        let stored: Value = redis::get_json(redis, &key)
            .await?
            .ok_or_else(|| AppError::bad_request("授权请求已过期"))?;
        let csrf = stored
            .get("csrf")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !crate::shared::constant_time_eq(csrf.as_bytes(), csrf_token.as_bytes()) {
            return Err(AppError::forbidden("授权表单校验失败"));
        }
        let pending: PendingAuthorize = serde_json::from_value(
            stored
                .get("request")
                .cloned()
                .ok_or_else(|| AppError::bad_request("授权请求无效"))?,
        )?;
        if pending.identity_id != ctx.identity_id {
            return Err(AppError::forbidden("授权请求不属于当前用户"));
        }
        redis::del(redis, &key).await?;
        let client = self.load_client(&pending.client_id).await?;
        if !approve {
            audit::record(
                &self.pool,
                AuditEntry::new("auth.oauth.consent_denied")
                    .tenant(ctx.tenant_id)
                    .actor(ctx.identity_id)
                    .resource("oauth_client", client.client_id.clone()),
            )
            .await?;
            return Ok(append_query(
                &pending.redirect_uri,
                &[
                    ("error", "access_denied"),
                    ("error_description", "用户拒绝授权"),
                    ("state", pending.state.as_deref().unwrap_or("")),
                ],
            ));
        }
        let scopes: Vec<String> = pending
            .scope
            .split_whitespace()
            .map(str::to_string)
            .collect();
        sqlx::query(
            "INSERT INTO oauth_consents (identity_id, client_id, tenant_id, scopes, status)
             VALUES ($1, $2, $3, $4, 'active')
             ON CONFLICT (identity_id, client_id) WHERE status = 'active'
             DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = now()",
        )
        .bind(ctx.identity_id)
        .bind(&client.client_id)
        .bind(ctx.tenant_id)
        .bind(serde_json::to_value(&scopes)?)
        .execute(&self.pool)
        .await?;
        audit::record(
            &self.pool,
            AuditEntry::new("auth.oauth.consent_granted")
                .tenant(ctx.tenant_id)
                .actor(ctx.identity_id)
                .resource("oauth_client", client.client_id.clone())
                .detail(json!({ "scopes": scopes })),
        )
        .await?;
        self.issue_authorization_code(
            ctx.identity_id,
            ctx.tenant_id,
            pending.session_id,
            &client,
            &pending.redirect_uri,
            &pending.scope,
            pending.nonce,
            pending.state,
            pending.code_challenge,
            pending.code_challenge_method,
            pending.amr,
            pending.acr,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn issue_authorization_code(
        &self,
        identity_id: Uuid,
        tenant_id: Uuid,
        session_id: Uuid,
        client: &OAuthClient,
        redirect_uri: &str,
        scope: &str,
        nonce: Option<String>,
        state: Option<String>,
        challenge: Option<String>,
        method: Option<String>,
        amr: Vec<String>,
        acr: String,
    ) -> AppResult<String> {
        let raw = random_token(32);
        let code_hash = sha256_hex(&raw);
        sqlx::query(
            "INSERT INTO authorization_codes
                (code_hash, client_id, tenant_id, identity_id, session_id, redirect_uri, scope,
                 nonce, state, code_challenge, code_challenge_method, amr, acr, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
        )
        .bind(&code_hash)
        .bind(&client.client_id)
        .bind(tenant_id)
        .bind(identity_id)
        .bind(session_id)
        .bind(redirect_uri)
        .bind(scope)
        .bind(&nonce)
        .bind(&state)
        .bind(&challenge)
        .bind(&method)
        .bind(serde_json::to_value(&amr)?)
        .bind(&acr)
        .bind(now() + Duration::seconds(AUTHORIZATION_CODE_TTL_SECS))
        .execute(&self.pool)
        .await?;
        let mut params: Vec<(&str, &str)> = vec![("code", raw.as_str())];
        if let Some(state) = &state {
            params.push(("state", state.as_str()));
        }
        Ok(append_query(redirect_uri, &params))
    }

    /// Token 端点。`basic` 为 HTTP Basic 客户端认证结果。
    pub async fn exchange_token(
        &self,
        request: TokenRequest,
        basic: Option<(String, String)>,
    ) -> AppResult<Value> {
        let grant_type = request
            .grant_type
            .as_deref()
            .ok_or_else(|| AppError::bad_request("缺少 grant_type"))?;
        match grant_type {
            "authorization_code" => {
                let value = self.exchange_authorization_code(&request, basic).await?;
                Ok(value)
            }
            "refresh_token" => {
                let refresh = request
                    .refresh_token
                    .as_deref()
                    .ok_or_else(|| AppError::invalid_grant("缺少 refresh_token"))?;
                let client = self.authenticate_client(&request, basic).await?;
                if !client.has_grant("refresh_token") {
                    return Err(AppError::invalid_grant("客户端未启用 refresh_token"));
                }
                let bundle = self
                    .refresh_tokens(refresh, Some(&client.client_id), None, None)
                    .await?;
                Ok(serde_json::to_value(TokenResponse::from(bundle))?)
            }
            "client_credentials" => {
                if !self.config.oauth.allow_client_credentials {
                    return Err(AppError::unsupported_grant_type(
                        "client_credentials 已禁用",
                    ));
                }
                let client = self.authenticate_client(&request, basic).await?;
                if client.is_public() {
                    return Err(AppError::invalid_client(
                        "公共客户端不能使用 client_credentials",
                    ));
                }
                if !client.has_grant("client_credentials") {
                    return Err(AppError::invalid_grant("客户端未启用 client_credentials"));
                }
                let scope = self
                    .validate_requested_scope(&client, request.scope.as_deref())
                    .await?;
                let identity = self.service_identity(&client).await?;
                let session = self
                    .create_session(
                        &identity,
                        &client.client_id,
                        vec!["client_credentials".to_string()],
                        "urn:auth:acr:client",
                        &crate::application::session::LoginContext {
                            tenant_id: client.tenant_id,
                            client_id: Some(client.client_id.clone()),
                            ..Default::default()
                        },
                    )
                    .await?;
                let ttl = TokenTtl {
                    access_secs: client
                        .access_token_ttl_secs
                        .map(i64::from)
                        .unwrap_or(self.config.security.access_token_ttl_secs as i64),
                    refresh_secs: client
                        .refresh_token_ttl_secs
                        .map(i64::from)
                        .unwrap_or(self.config.security.refresh_token_ttl_secs as i64),
                    id_secs: client
                        .id_token_ttl_secs
                        .map(i64::from)
                        .unwrap_or(self.config.security.id_token_ttl_secs as i64),
                };
                let bundle = self
                    .issue_token_bundle(
                        &identity,
                        &session,
                        &client.client_id,
                        &scope,
                        None,
                        false,
                        Some(ttl),
                    )
                    .await?;
                audit::record(
                    &self.pool,
                    AuditEntry::new("auth.oauth.client_credentials")
                        .tenant(client.tenant_id)
                        .actor(identity.id)
                        .resource("oauth_client", client.client_id.clone())
                        .detail(json!({ "scope": scope })),
                )
                .await?;
                Ok(serde_json::to_value(TokenResponse::from(bundle))?)
            }
            other => Err(AppError::unsupported_grant_type(format!(
                "不支持的 grant_type: {other}"
            ))),
        }
    }

    async fn exchange_authorization_code(
        &self,
        request: &TokenRequest,
        basic: Option<(String, String)>,
    ) -> AppResult<Value> {
        let client = self.authenticate_client(request, basic).await?;
        let code_raw = request
            .code
            .as_deref()
            .ok_or_else(|| AppError::invalid_grant("缺少 code"))?;
        let code_hash = sha256_hex(code_raw);
        let code = sqlx::query_as::<_, AuthorizationCode>(
            "SELECT * FROM authorization_codes WHERE code_hash = $1",
        )
        .bind(&code_hash)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::invalid_grant("授权码无效"))?;
        if code.client_id != client.client_id {
            return Err(AppError::invalid_grant("授权码不属于该客户端"));
        }
        if code.consumed_at.is_some() {
            return Err(AppError::invalid_grant("授权码已被使用"));
        }
        if code.expires_at < now() {
            return Err(AppError::invalid_grant("授权码已过期"));
        }
        let redirect_uri = request
            .redirect_uri
            .as_deref()
            .ok_or_else(|| AppError::invalid_grant("缺少 redirect_uri"))?;
        if redirect_uri != code.redirect_uri {
            return Err(AppError::invalid_grant("redirect_uri 与授权请求不一致"));
        }
        match (&code.code_challenge, &code.code_challenge_method) {
            (Some(challenge), Some(method)) => {
                let verifier = request
                    .code_verifier
                    .as_deref()
                    .ok_or_else(|| AppError::invalid_grant("缺少 code_verifier"))?;
                if !pkce::verify(verifier, challenge, method) {
                    return Err(AppError::invalid_grant("PKCE 校验失败"));
                }
            }
            _ => {
                if client.require_pkce || client.is_public() {
                    return Err(AppError::invalid_grant("缺少 PKCE"));
                }
            }
        }
        let consumed = sqlx::query(
            "UPDATE authorization_codes SET consumed_at = now()
             WHERE id = $1 AND consumed_at IS NULL",
        )
        .bind(code.id)
        .execute(&self.pool)
        .await?;
        if consumed.rows_affected() == 0 {
            return Err(AppError::invalid_grant("授权码已被使用"));
        }

        let session = self.get_session(code.session_id).await?;
        if session.status != "active" || session.expires_at < now() {
            return Err(AppError::invalid_grant("会话已失效"));
        }
        let identity = self.get_identity(code.identity_id).await?;
        let mut token_session = session.clone();
        token_session.amr = code.amr.clone();
        token_session.acr = code.acr.clone();
        let scopes: Vec<String> = code.scope.split_whitespace().map(str::to_string).collect();
        let include_refresh =
            scopes.iter().any(|item| item == "offline_access") && client.has_grant("refresh_token");
        let ttl = TokenTtl {
            access_secs: client
                .access_token_ttl_secs
                .map(i64::from)
                .unwrap_or(self.config.security.access_token_ttl_secs as i64),
            refresh_secs: client
                .refresh_token_ttl_secs
                .map(i64::from)
                .unwrap_or(self.config.security.refresh_token_ttl_secs as i64),
            id_secs: client
                .id_token_ttl_secs
                .map(i64::from)
                .unwrap_or(self.config.security.id_token_ttl_secs as i64),
        };
        let bundle = self
            .issue_token_bundle(
                &identity,
                &token_session,
                &client.client_id,
                &code.scope,
                code.nonce.clone(),
                include_refresh,
                Some(ttl),
            )
            .await?;
        let mut tx = self.pool.begin().await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("auth.oauth.token_issued")
                .tenant(code.tenant_id)
                .actor(code.identity_id)
                .resource("oauth_client", client.client_id.clone())
                .detail(json!({ "grant_type": "authorization_code", "scope": code.scope })),
        )
        .await?;
        outbox::enqueue(
            &mut tx,
            &DomainEvent::new(
                "auth.oauth.token_issued",
                "identity",
                code.identity_id.to_string(),
                json!({
                    "identity_id": code.identity_id,
                    "client_id": client.client_id,
                    "tenant_id": code.tenant_id,
                    "grant_type": "authorization_code",
                }),
            ),
        )
        .await?;
        tx.commit().await?;
        Ok(serde_json::to_value(TokenResponse::from(bundle))?)
    }

    pub async fn introspect(
        &self,
        token: &str,
        token_type_hint: Option<&str>,
        basic: Option<(String, String)>,
    ) -> AppResult<Value> {
        self.authenticate_client(&TokenRequest::default(), basic)
            .await?;
        if token_type_hint != Some("refresh_token") {
            if let Ok(claims) = self
                .keys
                .verify::<crate::domain::TokenClaims>(token, Some(self.access_audience()))
                .await
            {
                if claims.typ != "access" {
                    return Ok(json!({ "active": false }));
                }
                let session_active = self
                    .session_is_active(Uuid::parse_str(&claims.sid).unwrap_or(Uuid::nil()))
                    .await;
                let revoked = match &self.redis {
                    Some(redis) => redis::get(redis, &self.access_blacklist_key(&claims.jti))
                        .await?
                        .is_some(),
                    None => false,
                };
                if !session_active || revoked {
                    return Ok(json!({ "active": false }));
                }
                return Ok(json!({
                    "active": true,
                    "token_type": "access_token",
                    "sub": claims.sub,
                    "aud": claims.aud,
                    "iss": claims.iss,
                    "exp": claims.exp,
                    "iat": claims.iat,
                    "nbf": claims.nbf,
                    "jti": claims.jti,
                    "client_id": claims.client_id,
                    "scope": claims.scope,
                    "tenant_id": claims.tenant_id,
                    "sid": claims.sid,
                    "amr": claims.amr,
                    "acr": claims.acr,
                    "username": claims.preferred_username,
                }));
            }
        }
        let hash = sha256_hex(token.trim());
        let row: Option<(
            Uuid,
            String,
            String,
            String,
            chrono::DateTime<chrono::Utc>,
            String,
            String,
        )> = sqlx::query_as(
            "SELECT identity_id, client_id, tenant_id, scope, expires_at, session_id, status
                 FROM refresh_tokens WHERE token_hash = $1",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await?;
        let Some((identity_id, client_id, tenant_id, scope, expires_at, session_id, status)) = row
        else {
            return Ok(json!({ "active": false }));
        };
        if status != "active" || expires_at < now() {
            return Ok(json!({ "active": false }));
        }
        let session_active = self
            .session_is_active(Uuid::parse_str(&session_id).unwrap_or(Uuid::nil()))
            .await;
        Ok(json!({
            "active": session_active,
            "token_type": "refresh_token",
            "sub": identity_id,
            "client_id": client_id,
            "tenant_id": tenant_id,
            "scope": scope,
            "exp": expires_at.timestamp(),
            "session_id": session_id,
        }))
    }

    pub async fn revoke_token(
        &self,
        token: &str,
        basic: Option<(String, String)>,
    ) -> AppResult<()> {
        let client = self
            .authenticate_client(&TokenRequest::default(), basic)
            .await?;
        if let Ok(claims) = self
            .keys
            .verify::<crate::domain::TokenClaims>(token, Some(self.access_audience()))
            .await
        {
            if claims.client_id == client.client_id {
                if let Some(redis) = &self.redis {
                    let ttl = (claims.exp - unix_secs()).max(1) as u64;
                    redis::set_ex(redis, &self.access_blacklist_key(&claims.jti), "1", ttl).await?;
                }
                audit::record(
                    &self.pool,
                    AuditEntry::new("auth.token.revoked")
                        .actor(Uuid::parse_str(&claims.sub).unwrap_or(Uuid::nil()))
                        .resource("access_token", claims.jti.clone())
                        .detail(json!({ "client_id": client.client_id })),
                )
                .await?;
                return Ok(());
            }
        }
        let hash = sha256_hex(token.trim());
        let row: Option<(Uuid, Uuid, String)> = sqlx::query_as(
            "SELECT id, session_id, client_id FROM refresh_tokens WHERE token_hash = $1",
        )
        .bind(&hash)
        .fetch_optional(&self.pool)
        .await?;
        if let Some((id, session_id, token_client)) = row {
            if token_client == client.client_id {
                sqlx::query(
                    "UPDATE refresh_tokens SET status = 'revoked', revoked_at = now()
                     WHERE family_id = (SELECT family_id FROM refresh_tokens WHERE id = $1)",
                )
                .bind(id)
                .execute(&self.pool)
                .await?;
                self.revoke_session(session_id, "token_revoked").await?;
            }
        }
        Ok(())
    }

    pub async fn userinfo(&self, ctx: &AuthContext) -> AppResult<Value> {
        if !ctx.scopes.iter().any(|scope| scope == "openid") {
            return Err(AppError::forbidden("Token 缺少 openid scope"));
        }
        let identity = self.get_identity(ctx.identity_id).await?;
        let mut value = json!({
            "sub": identity.id.to_string(),
            "preferred_username": identity.username,
            "name": identity.display_name.clone().unwrap_or_else(|| identity.username.clone()),
            "updated_at": identity.updated_at.timestamp(),
        });
        if ctx.scopes.iter().any(|scope| scope == "profile") {
            value["picture"] = json!(identity.avatar_url);
            value["locale"] = json!(identity.metadata.get("locale"));
            value["zoneinfo"] = json!(identity.metadata.get("timezone"));
        }
        if ctx.scopes.iter().any(|scope| scope == "email") {
            value["email"] = json!(identity.email);
            value["email_verified"] = json!(identity.email_verified);
        }
        if ctx.scopes.iter().any(|scope| scope == "phone") {
            value["phone_number"] = json!(identity.phone);
            value["phone_number_verified"] = json!(identity.phone_verified);
        }
        Ok(value)
    }

    pub fn discovery_document(&self) -> Value {
        let base = self.config.base_url();
        json!({
            "issuer": self.config.issuer(),
            "authorization_endpoint": format!("{base}/oauth2/authorize"),
            "token_endpoint": format!("{base}/oauth2/token"),
            "userinfo_endpoint": format!("{base}/oauth2/userinfo"),
            "jwks_uri": format!("{base}/oauth2/jwks"),
            "end_session_endpoint": format!("{base}/oauth2/logout"),
            "introspection_endpoint": format!("{base}/oauth2/introspect"),
            "revocation_endpoint": format!("{base}/oauth2/revoke"),
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": [self.config.security.signing_algorithm],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": ["openid", "profile", "email", "phone", "offline_access"],
            "claims_supported": [
                "iss", "sub", "aud", "exp", "iat", "nbf", "auth_time", "nonce", "acr", "amr",
                "name", "preferred_username", "email", "email_verified",
                "phone_number", "phone_number_verified", "picture", "sid"
            ],
            "claims_parameter_supported": false,
            "request_parameter_supported": false,
            "require_pkce": true,
        })
    }

    pub async fn end_session(
        &self,
        id_token_hint: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        state: Option<&str>,
        ctx: Option<&AuthContext>,
    ) -> AppResult<Option<String>> {
        let mut identity_id = ctx.map(|context| context.identity_id);
        let mut session_id = ctx.and_then(|context| context.session_id);
        let mut client_id: Option<String> = None;
        if let Some(hint) = id_token_hint {
            if let Ok(claims) = self
                .keys
                .verify::<crate::domain::TokenClaims>(hint, None)
                .await
            {
                if claims.typ == "id" {
                    identity_id = Uuid::parse_str(&claims.sub).ok();
                    session_id = Uuid::parse_str(&claims.sid).ok();
                    client_id = Some(claims.client_id.clone());
                }
            }
        }
        if let (Some(identity_id), Some(session_id)) = (identity_id, session_id) {
            self.revoke_session(session_id, "oidc_logout").await?;
            audit::record(
                &self.pool,
                AuditEntry::new("auth.logout")
                    .actor(identity_id)
                    .resource("session", session_id.to_string())
                    .detail(json!({ "protocol": "oidc" })),
            )
            .await?;
        }
        let Some(redirect) = post_logout_redirect_uri else {
            return Ok(None);
        };
        let client = match client_id {
            Some(client_id) => self.load_client(&client_id).await.ok(),
            None => None,
        };
        let allowed = match &client {
            Some(client) => client.post_logout_redirect_allowed(redirect),
            None => false,
        };
        if !allowed {
            return Err(AppError::bad_request("post_logout_redirect_uri 未注册"));
        }
        let location = match state {
            Some(state) => append_query(redirect, &[("state", state)]),
            None => redirect.to_string(),
        };
        Ok(Some(location))
    }

    pub async fn list_user_consents(&self, identity_id: Uuid) -> AppResult<Vec<OAuthConsent>> {
        Ok(sqlx::query_as::<_, OAuthConsent>(
            "SELECT * FROM oauth_consents WHERE identity_id = $1 AND status = 'active'
             ORDER BY updated_at DESC",
        )
        .bind(identity_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn revoke_user_consent(&self, identity_id: Uuid, client_id: &str) -> AppResult<()> {
        sqlx::query(
            "UPDATE oauth_consents SET status = 'revoked', revoked_at = now(), updated_at = now()
             WHERE identity_id = $1 AND client_id = $2 AND status = 'active'",
        )
        .bind(identity_id)
        .bind(client_id)
        .execute(&self.pool)
        .await?;
        audit::record(
            &self.pool,
            AuditEntry::new("auth.oauth.consent_revoked")
                .actor(identity_id)
                .resource("oauth_client", client_id.to_string()),
        )
        .await?;
        Ok(())
    }

    pub async fn load_client(&self, client_id: &str) -> AppResult<OAuthClient> {
        sqlx::query_as::<_, OAuthClient>("SELECT * FROM oauth_clients WHERE client_id = $1")
            .bind(client_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| AppError::invalid_client("客户端不存在"))
    }

    /// 从表单参数或 HTTP Basic 中认证客户端。
    pub async fn authenticate_client(
        &self,
        request: &TokenRequest,
        basic: Option<(String, String)>,
    ) -> AppResult<OAuthClient> {
        let (client_id, secret) = if let Some((id, secret)) = basic {
            (id, Some(secret))
        } else {
            (
                request
                    .client_id
                    .clone()
                    .ok_or_else(|| AppError::invalid_client("缺少 client_id"))?,
                request.client_secret.clone(),
            )
        };
        self.verify_client_secret(&client_id, secret.as_deref())
            .await
    }

    async fn consent_required(
        &self,
        identity_id: Uuid,
        client_id: &str,
        requested: &[String],
    ) -> AppResult<bool> {
        if !self.config.oauth.require_consent {
            return Ok(false);
        }
        let consent: Option<(Value,)> = sqlx::query_as(
            "SELECT scopes FROM oauth_consents
             WHERE identity_id = $1 AND client_id = $2 AND status = 'active'",
        )
        .bind(identity_id)
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await?;
        let Some((scopes,)) = consent else {
            return Ok(true);
        };
        let granted: Vec<String> = scopes
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        Ok(requested.iter().any(|scope| !granted.contains(scope)))
    }

    async fn validate_requested_scope(
        &self,
        client: &OAuthClient,
        requested: Option<&str>,
    ) -> AppResult<String> {
        let scope = requested.unwrap_or(&self.config.oauth.default_scope);
        let list: Vec<String> = scope.split_whitespace().map(str::to_string).collect();
        if list.is_empty() {
            return Err(AppError::invalid_scope("scope 不能为空"));
        }
        for item in &list {
            if !client.allows_scope(item) {
                return Err(AppError::invalid_scope(format!(
                    "客户端未被授予 scope: {item}"
                )));
            }
        }
        Ok(list.join(" "))
    }

    async fn service_identity(&self, client: &OAuthClient) -> AppResult<Identity> {
        if let Some(id) = client
            .metadata
            .get("service_identity_id")
            .and_then(Value::as_str)
            .and_then(|value| Uuid::parse_str(value).ok())
        {
            if let Ok(identity) = self.get_identity(id).await {
                return Ok(identity);
            }
        }
        let username = format!("svc_{}", client.client_id);
        if let Some(found) = self.identity_by_login(client.tenant_id, &username).await? {
            return Ok(found.identity);
        }
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO identities (id, tenant_id, username, display_name, status, metadata)
             VALUES ($1, $2, $3, $4, 'active', $5)",
        )
        .bind(id)
        .bind(client.tenant_id)
        .bind(&username)
        .bind(&client.name)
        .bind(json!({ "oauth_client_id": client.client_id, "managed": true }))
        .execute(&self.pool)
        .await
        .map_err(|error| {
            if let sqlx::Error::Database(db_error) = &error {
                if db_error.code().as_deref() == Some("23505") {
                    return AppError::conflict("服务身份已存在");
                }
            }
            error.into()
        })?;
        sqlx::query(
            "UPDATE oauth_clients SET metadata = metadata || jsonb_build_object('service_identity_id', $2::text)
             WHERE id = $1",
        )
        .bind(client.id)
        .bind(id.to_string())
        .execute(&self.pool)
        .await?;
        self.get_identity(id).await
    }
}

/// 在 URL 后追加查询参数（保留已有参数）。
pub fn append_query(base: &str, params: &[(&str, &str)]) -> String {
    let Ok(mut url) = url::Url::parse(base) else {
        return base.to_string();
    };
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in params {
            if value.is_empty() && *key == "state" {
                continue;
            }
            pairs.append_pair(key, value);
        }
    }
    url.to_string()
}

/// 解析 HTTP Basic 客户端认证。
pub fn parse_basic_auth(headers: &axum::http::HeaderMap) -> Option<(String, String)> {
    use base64::Engine;
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())?;
    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let text = String::from_utf8(decoded).ok()?;
    let (client_id, secret) = text.split_once(':')?;
    Some((client_id.to_string(), secret.to_string()))
}

/// OAuth 协议错误响应（RFC 6749 §5.2）。
pub fn oauth_error_response(error: &AppError) -> axum::response::Response {
    use axum::response::IntoResponse;
    let (status, code) = match error.code.as_str() {
        "invalid_client" => (axum::http::StatusCode::UNAUTHORIZED, "invalid_client"),
        "invalid_grant" => (axum::http::StatusCode::BAD_REQUEST, "invalid_grant"),
        "invalid_scope" => (axum::http::StatusCode::BAD_REQUEST, "invalid_scope"),
        "unsupported_grant_type" => (
            axum::http::StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
        ),
        "invalid_request" | "bad_request" | "validation_error" => {
            (axum::http::StatusCode::BAD_REQUEST, "invalid_request")
        }
        _ => (error.status, "server_error"),
    };
    let mut response = (
        status,
        axum::Json(json!({
            "error": code,
            "error_description": error.message,
        })),
    )
        .into_response();
    if code == "invalid_client" {
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static("Basic realm=\"oauth2\""),
        );
    }
    response
}

/// 默认第一方客户端 ID（SSO 控制台使用）。
pub fn default_client_id() -> &'static str {
    DEFAULT_CLIENT_ID
}
