//! 身份联邦：Google / GitHub / Microsoft / Apple / 通用 OIDC / OAuth2。
//!
//! 所有回调状态（state、PKCE verifier、nonce、绑定模式）存于 Redis，
//! 一次性消费；出站请求统一做 HTTPS/内网地址校验以规避 SSRF。

use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::application::identity::CreateIdentityInput;
use crate::application::session::{ACR_PWD, DEFAULT_CLIENT_ID};
use crate::application::RequestMeta;
use crate::bootstrap::AppState;
use crate::domain::{Identity, IdentityProvider};
use crate::shared::{normalize_email, random_token, sha256_base64url, AppError, AppResult};

/// 提供商创建/更新输入。
#[derive(Debug, Clone, Deserialize)]
pub struct FederationProviderInput {
    pub code: String,
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub authorization_endpoint: Option<String>,
    #[serde(default)]
    pub token_endpoint: Option<String>,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
    #[serde(default)]
    pub private_key: Option<String>,
    #[serde(default)]
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub scopes: Option<Vec<String>>,
    #[serde(default)]
    pub attribute_mapping: Option<Value>,
    #[serde(default)]
    pub auto_register: Option<bool>,
    #[serde(default)]
    pub link_by_verified_email: Option<bool>,
    #[serde(default)]
    pub config: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FederationStart {
    pub authorization_url: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FederationCallbackOutcome {
    pub identity: Identity,
    pub tokens: Option<crate::application::session::TokenBundle>,
    pub linked: bool,
    pub redirect_after: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FederationLinkView {
    pub provider_id: Uuid,
    pub provider_code: String,
    pub provider_name: String,
    pub subject: String,
    pub email: Option<String>,
    pub linked_at: chrono::DateTime<Utc>,
    pub last_login_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FederationState {
    tenant_id: Uuid,
    provider_id: Uuid,
    provider_code: String,
    mode: String,
    identity_id: Option<Uuid>,
    code_verifier: String,
    nonce: String,
    redirect_after: Option<String>,
    created_at: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FederationCallbackParams {
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub error_description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ExternalProfile {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
    pub name: Option<String>,
    pub avatar: Option<String>,
    pub raw: Value,
}

impl ExternalProfile {
    /// 由 SAML 断言构造外部档案。
    pub fn from_saml(
        subject: String,
        email: Option<String>,
        name: Option<String>,
        raw: Value,
    ) -> Self {
        let email_verified = email.is_some();
        Self {
            subject,
            email,
            email_verified,
            name,
            avatar: None,
            raw,
        }
    }
}

struct ProviderEndpoints {
    authorization: String,
    token: String,
    userinfo: Option<String>,
    jwks: Option<String>,
    issuer: Option<String>,
    scopes: Vec<String>,
}

impl AppState {
    // ─────────────────────── 提供商管理 ───────────────────────

    pub async fn federation_list_providers(
        &self,
        tenant_id: Uuid,
    ) -> AppResult<Vec<IdentityProvider>> {
        Ok(sqlx::query_as::<_, IdentityProvider>(
            "SELECT * FROM identity_providers WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn federation_provider(
        &self,
        tenant_id: Uuid,
        code: &str,
    ) -> AppResult<IdentityProvider> {
        sqlx::query_as::<_, IdentityProvider>(
            "SELECT * FROM identity_providers WHERE tenant_id = $1 AND code = $2",
        )
        .bind(tenant_id)
        .bind(code)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("身份提供商不存在"))
    }

    pub async fn federation_upsert_provider(
        &self,
        tenant_id: Uuid,
        input: FederationProviderInput,
    ) -> AppResult<IdentityProvider> {
        self.ensure_tenant(tenant_id).await?;
        let kind = input.kind.trim().to_ascii_lowercase();
        if !matches!(
            kind.as_str(),
            "oidc" | "oauth2" | "github" | "apple" | "saml"
        ) {
            return Err(AppError::validation("kind", "不支持的提供商类型"));
        }
        if input.code.trim().is_empty() {
            return Err(AppError::validation("code", "提供商编码不能为空"));
        }
        let defaults = provider_defaults(&kind);
        let issuer = normalize_optional(input.issuer);
        let authorization_endpoint = normalize_optional(input.authorization_endpoint);
        let token_endpoint = normalize_optional(input.token_endpoint);
        let userinfo_endpoint = normalize_optional(input.userinfo_endpoint);
        let jwks_uri = normalize_optional(input.jwks_uri);

        let mut resolved = ProviderEndpoints {
            authorization: authorization_endpoint
                .clone()
                .unwrap_or_else(|| defaults.authorization.to_string()),
            token: token_endpoint
                .clone()
                .unwrap_or_else(|| defaults.token.to_string()),
            userinfo: userinfo_endpoint
                .clone()
                .or_else(|| defaults.userinfo.map(str::to_string)),
            jwks: jwks_uri
                .clone()
                .or_else(|| defaults.jwks.map(str::to_string)),
            issuer: issuer
                .clone()
                .or_else(|| defaults.issuer.map(str::to_string)),
            scopes: input
                .scopes
                .clone()
                .unwrap_or_else(|| defaults.scopes.iter().map(|s| s.to_string()).collect()),
        };
        if kind == "oidc" {
            self.discover_oidc(&mut resolved).await?;
        }
        for url in [
            Some(resolved.authorization.as_str()),
            Some(resolved.token.as_str()),
            resolved.userinfo.as_deref(),
            resolved.jwks.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            self.validate_provider_url(url)?;
        }

        let secret_encrypted = match input.client_secret.filter(|v| !v.is_empty()) {
            Some(secret) => Some(self.crypto.encrypt_str(&secret)?),
            None => None,
        };
        let private_key_encrypted = match input.private_key.filter(|v| !v.is_empty()) {
            Some(key) => Some(self.crypto.encrypt_str(&key)?),
            None => None,
        };
        let redirect_uri = input
            .redirect_uri
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| {
                format!(
                    "{}/api/v1/auth/federated/{}/callback",
                    self.config.base_url(),
                    input.code.trim()
                )
            });
        self.validate_provider_url(&redirect_uri)?;
        let mapping = input.attribute_mapping.unwrap_or_else(|| json!({}));
        let config = input.config.unwrap_or_else(|| json!({}));

        let provider = sqlx::query_as::<_, IdentityProvider>(
            "INSERT INTO identity_providers
                (tenant_id, code, name, kind, enabled, issuer, authorization_endpoint, token_endpoint,
                 userinfo_endpoint, jwks_uri, client_id, client_secret_encrypted, private_key_encrypted,
                 redirect_uri, scopes, attribute_mapping, auto_register, link_by_verified_email, config)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
             ON CONFLICT (tenant_id, code) DO UPDATE SET
                 name = EXCLUDED.name,
                 kind = EXCLUDED.kind,
                 enabled = EXCLUDED.enabled,
                 issuer = EXCLUDED.issuer,
                 authorization_endpoint = EXCLUDED.authorization_endpoint,
                 token_endpoint = EXCLUDED.token_endpoint,
                 userinfo_endpoint = EXCLUDED.userinfo_endpoint,
                 jwks_uri = EXCLUDED.jwks_uri,
                 client_id = EXCLUDED.client_id,
                 client_secret_encrypted = COALESCE(EXCLUDED.client_secret_encrypted, identity_providers.client_secret_encrypted),
                 private_key_encrypted = COALESCE(EXCLUDED.private_key_encrypted, identity_providers.private_key_encrypted),
                 redirect_uri = EXCLUDED.redirect_uri,
                 scopes = EXCLUDED.scopes,
                 attribute_mapping = EXCLUDED.attribute_mapping,
                 auto_register = EXCLUDED.auto_register,
                 link_by_verified_email = EXCLUDED.link_by_verified_email,
                 config = EXCLUDED.config,
                 updated_at = now()
             RETURNING *",
        )
        .bind(tenant_id)
        .bind(input.code.trim())
        .bind(&input.name)
        .bind(&kind)
        .bind(input.enabled.unwrap_or(true))
        .bind(&resolved.issuer)
        .bind(&resolved.authorization)
        .bind(&resolved.token)
        .bind(&resolved.userinfo)
        .bind(&resolved.jwks)
        .bind(input.client_id.filter(|v| !v.is_empty()))
        .bind(&secret_encrypted)
        .bind(&private_key_encrypted)
        .bind(&redirect_uri)
        .bind(json!(resolved.scopes))
        .bind(&mapping)
        .bind(input.auto_register.unwrap_or(false))
        .bind(input.link_by_verified_email.unwrap_or(false))
        .bind(&config)
        .fetch_one(&self.pool)
        .await?;
        Ok(provider)
    }

    pub async fn federation_delete_provider(&self, tenant_id: Uuid, code: &str) -> AppResult<()> {
        let result =
            sqlx::query("DELETE FROM identity_providers WHERE tenant_id = $1 AND code = $2")
                .bind(tenant_id)
                .bind(code)
                .execute(&self.pool)
                .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::not_found("身份提供商不存在"));
        }
        Ok(())
    }

    async fn discover_oidc(&self, endpoints: &mut ProviderEndpoints) -> AppResult<()> {
        let Some(issuer) = endpoints.issuer.clone() else {
            return Ok(());
        };
        if endpoints.authorization.is_empty() || endpoints.token.is_empty() {
            let url = format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            );
            self.validate_provider_url(&url)?;
            let response = self
                .http
                .get(&url)
                .timeout(Duration::from_secs(10))
                .send()
                .await
                .map_err(|error| AppError::bad_request(format!("OIDC Discovery 失败: {error}")))?;
            if !response.status().is_success() {
                return Err(AppError::bad_request("OIDC Discovery 返回错误状态"));
            }
            let discovery: Value = response.json().await.map_err(|error| {
                AppError::bad_request(format!("OIDC Discovery 解析失败: {error}"))
            })?;
            endpoints.authorization = discovery
                .get("authorization_endpoint")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            endpoints.token = discovery
                .get("token_endpoint")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            endpoints.userinfo = discovery
                .get("userinfo_endpoint")
                .and_then(Value::as_str)
                .map(str::to_string);
            endpoints.jwks = discovery
                .get("jwks_uri")
                .and_then(Value::as_str)
                .map(str::to_string);
            if let Some(issuer) = discovery.get("issuer").and_then(Value::as_str) {
                endpoints.issuer = Some(issuer.to_string());
            }
        }
        if endpoints.authorization.is_empty() || endpoints.token.is_empty() {
            return Err(AppError::validation(
                "issuer",
                "OIDC Discovery 缺少必要端点",
            ));
        }
        Ok(())
    }

    fn validate_provider_url(&self, value: &str) -> AppResult<()> {
        let parsed = url::Url::parse(value)
            .map_err(|_| AppError::validation("url", "提供商 URL 格式不合法"))?;
        match parsed.scheme() {
            "https" => {}
            "http" if self.config.federation.allow_http_providers => {}
            _ => return Err(AppError::validation("url", "提供商 URL 必须使用 HTTPS")),
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| AppError::validation("url", "URL 缺少主机名"))?;
        if is_private_host(host) {
            return Err(AppError::validation("url", "禁止使用内网地址"));
        }
        Ok(())
    }

    // ─────────────────────── 发起授权 ───────────────────────

    /// 生成授权跳转 URL 并将状态写入 Redis。
    pub async fn federation_start(
        &self,
        tenant_id: Uuid,
        code: &str,
        link_identity: Option<Uuid>,
        redirect_after: Option<String>,
    ) -> AppResult<FederationStart> {
        let provider = self.federation_provider(tenant_id, code).await?;
        if !provider.enabled {
            return Err(AppError::forbidden("身份提供商已禁用"));
        }
        let redis = self.redis_or_err()?;
        let client_id = provider
            .client_id
            .clone()
            .ok_or_else(|| AppError::validation("client_id", "提供商缺少 client_id"))?;
        let state_token = random_token(32);
        let verifier = random_token(48);
        let nonce = random_token(24);
        let mode = if link_identity.is_some() {
            "link"
        } else {
            "login"
        };
        let state = FederationState {
            tenant_id,
            provider_id: provider.id,
            provider_code: provider.code.clone(),
            mode: mode.to_string(),
            identity_id: link_identity,
            code_verifier: verifier.clone(),
            nonce: nonce.clone(),
            redirect_after,
            created_at: Utc::now().timestamp(),
        };
        crate::infrastructure::redis::set_json(
            redis,
            &self.cache_key(&["federation", "state", &state_token]),
            &state,
            self.config.federation.state_ttl_secs,
        )
        .await?;

        let endpoints = endpoints_of(&provider);
        let mut url = url::Url::parse(&endpoints.authorization)
            .map_err(|_| AppError::validation("authorization_endpoint", "授权地址不合法"))?;
        {
            let mut pairs = url.query_pairs_mut();
            pairs.append_pair("response_type", "code");
            pairs.append_pair("client_id", &client_id);
            pairs.append_pair(
                "redirect_uri",
                provider.redirect_uri.as_deref().unwrap_or_default(),
            );
            pairs.append_pair("scope", &endpoints.scopes.join(" "));
            pairs.append_pair("state", &state_token);
            pairs.append_pair("nonce", &nonce);
            pairs.append_pair("code_challenge", &sha256_base64url(verifier.as_bytes()));
            pairs.append_pair("code_challenge_method", "S256");
            if provider.kind == "apple" {
                pairs.append_pair("response_mode", "form_post");
            }
        }
        Ok(FederationStart {
            authorization_url: url.to_string(),
            state: state_token,
        })
    }

    // ─────────────────────── 回调处理 ───────────────────────

    pub async fn federation_callback(
        &self,
        tenant_id: Uuid,
        provider_code: &str,
        params: FederationCallbackParams,
        meta: &RequestMeta,
    ) -> AppResult<FederationCallbackOutcome> {
        if let Some(error) = params.error {
            return Err(AppError::bad_request(format!(
                "身份提供商返回错误: {}{}",
                error,
                params
                    .error_description
                    .map(|description| format!(" ({description})"))
                    .unwrap_or_default()
            )));
        }
        let state_token = params
            .state
            .ok_or_else(|| AppError::validation("state", "缺少 state 参数"))?;
        let authorization_code = params
            .code
            .ok_or_else(|| AppError::validation("code", "缺少授权码"))?;
        let redis = self.redis_or_err()?;
        let key = self.cache_key(&["federation", "state", &state_token]);
        let state: FederationState = crate::infrastructure::redis::get_json(redis, &key)
            .await?
            .ok_or_else(|| AppError::bad_request("state 无效或已过期"))?;
        crate::infrastructure::redis::del(redis, &key).await?;
        if state.tenant_id != tenant_id || state.provider_code != provider_code {
            return Err(AppError::bad_request("state 与提供商不匹配"));
        }

        let provider = self
            .federation_provider(tenant_id, &state.provider_code)
            .await?;
        if !provider.enabled {
            return Err(AppError::forbidden("身份提供商已禁用"));
        }
        let token_response = self
            .federation_exchange_token(&provider, &authorization_code, &state.code_verifier)
            .await?;
        let profile = self
            .federation_fetch_profile(&provider, &token_response, &state.nonce)
            .await?;

        let (identity, linked) = if state.mode == "link" {
            let identity_id = state
                .identity_id
                .ok_or_else(|| AppError::bad_request("绑定模式缺少目标身份"))?;
            let identity = self.get_identity(identity_id).await?;
            self.federation_link_identity(&provider, &identity, &profile)
                .await?;
            (identity, true)
        } else {
            self.federation_resolve_identity(&provider, &profile, meta)
                .await?
        };

        let tokens = if state.mode == "link" {
            None
        } else {
            let ctx = crate::application::session::LoginContext {
                tenant_id,
                client_id: Some(DEFAULT_CLIENT_ID.to_string()),
                device_id: None,
                device_name: None,
                ip: meta.ip.clone(),
                user_agent: meta.user_agent.clone(),
                trace_id: meta.trace_id.clone(),
            };
            Some(
                self.complete_login(
                    &identity,
                    DEFAULT_CLIENT_ID,
                    "openid profile email offline_access",
                    vec!["federated".to_string(), provider.kind.clone()],
                    ACR_PWD,
                    None,
                    &ctx,
                )
                .await?,
            )
        };

        crate::application::audit::record(
            &self.pool,
            crate::application::audit::AuditEntry::new(if state.mode == "link" {
                "federation.link"
            } else {
                "federation.login"
            })
            .tenant(tenant_id)
            .actor(identity.id)
            .resource("identity_provider", provider.code.clone())
            .request_context(
                meta.ip.clone(),
                meta.user_agent.clone(),
                meta.trace_id.clone(),
            )
            .detail(json!({ "email": profile.email, "subject": profile.subject })),
        )
        .await?;

        Ok(FederationCallbackOutcome {
            identity,
            tokens,
            linked,
            redirect_after: state.redirect_after,
        })
    }

    async fn federation_exchange_token(
        &self,
        provider: &IdentityProvider,
        code: &str,
        verifier: &str,
    ) -> AppResult<Value> {
        let endpoints = endpoints_of(provider);
        let client_id = provider
            .client_id
            .clone()
            .ok_or_else(|| AppError::validation("client_id", "提供商缺少 client_id"))?;
        let mut form: Vec<(String, String)> = vec![
            ("grant_type".into(), "authorization_code".into()),
            ("code".into(), code.to_string()),
            (
                "redirect_uri".into(),
                provider.redirect_uri.clone().unwrap_or_default(),
            ),
            ("client_id".into(), client_id.clone()),
            ("code_verifier".into(), verifier.to_string()),
        ];
        if provider.kind == "apple" {
            form.push((
                "client_secret".into(),
                self.apple_client_secret(provider).await?,
            ));
        } else if let Some(secret) = provider.client_secret_encrypted.as_deref() {
            form.push(("client_secret".into(), self.crypto.decrypt_str(secret)?));
        }

        let response = self
            .http
            .post(&endpoints.token)
            .header("accept", "application/json")
            .form(&form)
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|error| AppError::bad_request(format!("换取令牌失败: {error}")))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            tracing::warn!(status = %status, body = %text, "身份联邦换取令牌失败");
            return Err(AppError::bad_request("身份提供商拒绝换取令牌"));
        }
        serde_json::from_str::<Value>(&text)
            .map_err(|error| AppError::bad_request(format!("令牌响应解析失败: {error}")))
    }

    async fn federation_fetch_profile(
        &self,
        provider: &IdentityProvider,
        token_response: &Value,
        nonce: &str,
    ) -> AppResult<ExternalProfile> {
        let endpoints = endpoints_of(provider);
        if let (Some(id_token), Some(jwks_uri)) = (
            token_response.get("id_token").and_then(Value::as_str),
            endpoints.jwks.as_deref(),
        ) {
            if let Ok(profile) = self
                .verify_id_token(provider, id_token, jwks_uri, nonce)
                .await
            {
                return Ok(profile);
            }
        }
        let access_token = token_response
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::bad_request("令牌响应缺少 access_token"))?;
        let userinfo = endpoints
            .userinfo
            .as_deref()
            .ok_or_else(|| AppError::bad_request("提供商缺少 userinfo 端点"))?;
        let response = self
            .http
            .get(userinfo)
            .bearer_auth(access_token)
            .header("accept", "application/json")
            .header("user-agent", "auth-center")
            .timeout(Duration::from_secs(15))
            .send()
            .await
            .map_err(|error| AppError::bad_request(format!("获取用户信息失败: {error}")))?;
        if !response.status().is_success() {
            return Err(AppError::bad_request("身份提供商返回用户信息错误"));
        }
        let raw: Value = response
            .json()
            .await
            .map_err(|error| AppError::bad_request(format!("用户信息解析失败: {error}")))?;

        if provider.kind == "github" {
            return self.github_profile(provider, raw, access_token).await;
        }
        Ok(map_profile(provider, &raw))
    }

    async fn verify_id_token(
        &self,
        provider: &IdentityProvider,
        id_token: &str,
        jwks_uri: &str,
        nonce: &str,
    ) -> AppResult<ExternalProfile> {
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|error| AppError::bad_request(format!("id_token 头部解析失败: {error}")))?;
        let jwks: jsonwebtoken::jwk::JwkSet = self
            .http
            .get(jwks_uri)
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|error| AppError::bad_request(format!("获取 JWKS 失败: {error}")))?
            .json()
            .await
            .map_err(|error| AppError::bad_request(format!("JWKS 解析失败: {error}")))?;
        let jwk = match header.kid.as_deref().and_then(|kid| jwks.find(kid)) {
            Some(jwk) => jwk,
            None => jwks
                .keys
                .first()
                .ok_or_else(|| AppError::bad_request("JWKS 为空"))?,
        };
        let key = jsonwebtoken::DecodingKey::from_jwk(jwk)
            .map_err(|error| AppError::bad_request(format!("JWK 解析失败: {error}")))?;
        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.leeway = 30;
        if let Some(client_id) = provider.client_id.as_deref() {
            validation.set_audience(&[client_id]);
        }
        if let Some(issuer) = provider.issuer.as_deref() {
            validation.set_issuer(&[issuer]);
        }
        let data = jsonwebtoken::decode::<Value>(id_token, &key, &validation)
            .map_err(|error| AppError::bad_request(format!("id_token 校验失败: {error}")))?;
        if let Some(claim_nonce) = data.claims.get("nonce").and_then(Value::as_str) {
            if !crate::shared::util::constant_time_eq(claim_nonce.as_bytes(), nonce.as_bytes()) {
                return Err(AppError::bad_request("id_token nonce 不匹配"));
            }
        }
        Ok(map_profile(provider, &data.claims))
    }

    async fn github_profile(
        &self,
        provider: &IdentityProvider,
        raw: Value,
        access_token: &str,
    ) -> AppResult<ExternalProfile> {
        let subject = raw
            .get("id")
            .and_then(|value| {
                value
                    .as_i64()
                    .map(|v| v.to_string())
                    .or_else(|| value.as_str().map(str::to_string))
            })
            .ok_or_else(|| AppError::bad_request("GitHub 用户信息缺少 id"))?;
        let mut email = raw.get("email").and_then(Value::as_str).map(str::to_string);
        let mut verified = false;
        if email.is_none() {
            let endpoint = provider
                .config
                .get("emails_endpoint")
                .and_then(Value::as_str)
                .unwrap_or("https://api.github.com/user/emails");
            if let Ok(response) = self
                .http
                .get(endpoint)
                .bearer_auth(access_token)
                .header("accept", "application/json")
                .header("user-agent", "auth-center")
                .timeout(Duration::from_secs(10))
                .send()
                .await
            {
                if let Ok(Value::Array(items)) = response.json::<Value>().await {
                    let chosen = items
                        .iter()
                        .find(|item| {
                            item.get("primary").and_then(Value::as_bool) == Some(true)
                                && item.get("verified").and_then(Value::as_bool) == Some(true)
                        })
                        .or_else(|| {
                            items.iter().find(|item| {
                                item.get("verified").and_then(Value::as_bool) == Some(true)
                            })
                        });
                    if let Some(item) = chosen {
                        email = item
                            .get("email")
                            .and_then(Value::as_str)
                            .map(str::to_string);
                        verified = true;
                    }
                }
            }
        } else {
            verified = true;
        }
        Ok(ExternalProfile {
            subject,
            email,
            email_verified: verified,
            name: raw
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| raw.get("login").and_then(Value::as_str))
                .map(str::to_string),
            avatar: raw
                .get("avatar_url")
                .and_then(Value::as_str)
                .map(str::to_string),
            raw,
        })
    }

    async fn apple_client_secret(&self, provider: &IdentityProvider) -> AppResult<String> {
        let key = provider
            .private_key_encrypted
            .as_deref()
            .ok_or_else(|| AppError::validation("private_key", "Apple 提供商缺少私钥"))?;
        let pem = self.crypto.decrypt_str(key)?;
        let team_id = provider
            .config
            .get("team_id")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::validation("team_id", "Apple 提供商缺少 team_id"))?;
        let key_id = provider
            .config
            .get("key_id")
            .and_then(Value::as_str)
            .ok_or_else(|| AppError::validation("key_id", "Apple 提供商缺少 key_id"))?;
        let client_id = provider
            .client_id
            .as_deref()
            .ok_or_else(|| AppError::validation("client_id", "Apple 提供商缺少 client_id"))?;
        #[derive(Serialize)]
        struct Claims<'a> {
            iss: &'a str,
            iat: i64,
            exp: i64,
            aud: &'a str,
            sub: &'a str,
        }
        let now = Utc::now().timestamp();
        let claims = Claims {
            iss: team_id,
            iat: now,
            exp: now + 3600,
            aud: "https://appleid.apple.com",
            sub: client_id,
        };
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(key_id.to_string());
        let key = jsonwebtoken::EncodingKey::from_ec_pem(pem.as_bytes())
            .map_err(|error| AppError::server_error(format!("Apple 私钥无效: {error}")))?;
        jsonwebtoken::encode(&header, &claims, &key).map_err(|error| {
            AppError::server_error(format!("生成 Apple client_secret 失败: {error}"))
        })
    }

    pub async fn federation_resolve_identity(
        &self,
        provider: &IdentityProvider,
        profile: &ExternalProfile,
        meta: &RequestMeta,
    ) -> AppResult<(Identity, bool)> {
        if let Some(existing) = sqlx::query_as::<_, (Uuid,)>(
            "SELECT identity_id FROM external_identities WHERE provider_id = $1 AND subject = $2",
        )
        .bind(provider.id)
        .bind(&profile.subject)
        .fetch_optional(&self.pool)
        .await?
        {
            let identity = self.get_identity(existing.0).await?;
            if !identity.is_login_allowed() {
                return Err(AppError::forbidden("关联身份已被禁用"));
            }
            self.touch_external_identity(provider.id, &profile.subject, profile)
                .await?;
            return Ok((identity, false));
        }

        if let Some(email) = profile.email.as_deref().map(normalize_email) {
            if profile.email_verified {
                if let Some(existing) = sqlx::query_as::<_, (Uuid,)>(
                    "SELECT id FROM identities WHERE lower(email) = $1 AND deleted_at IS NULL",
                )
                .bind(&email)
                .fetch_optional(&self.pool)
                .await?
                {
                    if provider.link_by_verified_email {
                        let identity = self.get_identity(existing.0).await?;
                        self.federation_link_identity(provider, &identity, profile)
                            .await?;
                        return Ok((identity, true));
                    }
                    return Err(AppError::conflict(
                        "该邮箱已存在账户，请先登录后绑定第三方账号",
                    ));
                }
            }
        }

        if !(provider.auto_register && self.config.federation.allow_auto_register) {
            return Err(AppError::forbidden("该第三方账号尚未绑定任何用户"));
        }
        let username = self.unique_federated_username(provider, profile).await?;
        let identity = self
            .create_identity(
                CreateIdentityInput {
                    tenant_id: provider.tenant_id,
                    username,
                    email: profile.email.clone().map(|email| normalize_email(&email)),
                    phone: None,
                    password: None,
                    display_name: profile.name.clone(),
                    avatar_url: profile.avatar.clone(),
                    status: Some("active".to_string()),
                    email_verified: profile.email_verified,
                    phone_verified: false,
                    metadata: json!({ "source": format!("federated:{}", provider.code) }),
                    require_email_verification: false,
                    source: format!("federated:{}", provider.code),
                },
                meta,
            )
            .await?;
        self.federation_link_identity(provider, &identity, profile)
            .await?;
        Ok((identity, true))
    }

    async fn unique_federated_username(
        &self,
        provider: &IdentityProvider,
        profile: &ExternalProfile,
    ) -> AppResult<String> {
        let base = profile
            .email
            .as_deref()
            .and_then(|email| email.split_once('@').map(|(local, _)| local.to_string()))
            .unwrap_or_else(|| format!("{}{}", provider.code, &profile.subject));
        let sanitized: String = base
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .take(48)
            .collect();
        let base = if sanitized.len() >= 3 {
            sanitized
        } else {
            format!("user{}", &profile.subject)
        };
        for attempt in 0..6 {
            let candidate = if attempt == 0 {
                base.clone()
            } else {
                format!("{}{}", base, &random_token(3).to_ascii_lowercase())
            };
            let exists: Option<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM identities WHERE tenant_id = $1 AND lower(username) = lower($2) AND deleted_at IS NULL",
            )
            .bind(provider.tenant_id)
            .bind(&candidate)
            .fetch_optional(&self.pool)
            .await?;
            if exists.is_none() {
                return Ok(candidate);
            }
        }
        Ok(format!("{}{}", base, Uuid::now_v7().simple()))
    }

    async fn federation_link_identity(
        &self,
        provider: &IdentityProvider,
        identity: &Identity,
        profile: &ExternalProfile,
    ) -> AppResult<()> {
        let existing: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT id, identity_id FROM external_identities WHERE provider_id = $1 AND subject = $2",
        )
        .bind(provider.id)
        .bind(&profile.subject)
        .fetch_optional(&self.pool)
        .await?;
        if let Some((_, owner)) = existing {
            if owner != identity.id {
                return Err(AppError::conflict("该第三方账号已绑定其他用户"));
            }
        }
        sqlx::query(
            "INSERT INTO external_identities
                (identity_id, provider_id, provider_code, subject, email, display_name, raw, last_login_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, now())
             ON CONFLICT (provider_id, subject) DO UPDATE SET
                 email = EXCLUDED.email,
                 display_name = EXCLUDED.display_name,
                 raw = EXCLUDED.raw,
                 last_login_at = now()",
        )
        .bind(identity.id)
        .bind(provider.id)
        .bind(&provider.code)
        .bind(&profile.subject)
        .bind(&profile.email)
        .bind(&profile.name)
        .bind(&profile.raw)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn touch_external_identity(
        &self,
        provider_id: Uuid,
        subject: &str,
        profile: &ExternalProfile,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE external_identities
             SET last_login_at = now(), email = COALESCE($3, email), display_name = COALESCE($4, display_name)
             WHERE provider_id = $1 AND subject = $2",
        )
        .bind(provider_id)
        .bind(subject)
        .bind(&profile.email)
        .bind(&profile.name)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn federation_list_links(
        &self,
        identity_id: Uuid,
    ) -> AppResult<Vec<FederationLinkView>> {
        let rows = sqlx::query_as::<
            _,
            (
                Uuid,
                String,
                String,
                String,
                Option<String>,
                chrono::DateTime<Utc>,
                Option<chrono::DateTime<Utc>>,
            ),
        >(
            "SELECT e.provider_id, e.provider_code, p.name, e.subject, e.email, e.linked_at, e.last_login_at
             FROM external_identities e
             JOIN identity_providers p ON p.id = e.provider_id
             WHERE e.identity_id = $1
             ORDER BY e.linked_at DESC",
        )
        .bind(identity_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(
                |(
                    provider_id,
                    provider_code,
                    provider_name,
                    subject,
                    email,
                    linked_at,
                    last_login_at,
                )| {
                    FederationLinkView {
                        provider_id,
                        provider_code,
                        provider_name,
                        subject,
                        email,
                        linked_at,
                        last_login_at,
                    }
                },
            )
            .collect())
    }

    pub async fn federation_unlink(&self, identity_id: Uuid, provider_code: &str) -> AppResult<()> {
        let result = sqlx::query(
            "DELETE FROM external_identities WHERE identity_id = $1 AND provider_code = $2",
        )
        .bind(identity_id)
        .bind(provider_code)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::not_found("未找到绑定关系"));
        }
        Ok(())
    }
}

struct ProviderDefaults {
    authorization: &'static str,
    token: &'static str,
    userinfo: Option<&'static str>,
    jwks: Option<&'static str>,
    issuer: Option<&'static str>,
    scopes: &'static [&'static str],
}

fn provider_defaults(kind: &str) -> ProviderDefaults {
    match kind {
        "github" => ProviderDefaults {
            authorization: "https://github.com/login/oauth/authorize",
            token: "https://github.com/login/oauth/access_token",
            userinfo: Some("https://api.github.com/user"),
            jwks: None,
            issuer: None,
            scopes: &["read:user", "user:email"],
        },
        "apple" => ProviderDefaults {
            authorization: "https://appleid.apple.com/auth/authorize",
            token: "https://appleid.apple.com/auth/token",
            userinfo: None,
            jwks: Some("https://appleid.apple.com/auth/keys"),
            issuer: Some("https://appleid.apple.com"),
            scopes: &["name", "email"],
        },
        "oidc" => ProviderDefaults {
            authorization: "",
            token: "",
            userinfo: None,
            jwks: None,
            issuer: None,
            scopes: &["openid", "profile", "email"],
        },
        _ => ProviderDefaults {
            authorization: "",
            token: "",
            userinfo: None,
            jwks: None,
            issuer: None,
            scopes: &["openid", "profile", "email"],
        },
    }
}

fn endpoints_of(provider: &IdentityProvider) -> ProviderEndpoints {
    let defaults = provider_defaults(&provider.kind);
    ProviderEndpoints {
        authorization: provider
            .authorization_endpoint
            .clone()
            .unwrap_or_else(|| defaults.authorization.to_string()),
        token: provider
            .token_endpoint
            .clone()
            .unwrap_or_else(|| defaults.token.to_string()),
        userinfo: provider
            .userinfo_endpoint
            .clone()
            .or_else(|| defaults.userinfo.map(str::to_string)),
        jwks: provider
            .jwks_uri
            .clone()
            .or_else(|| defaults.jwks.map(str::to_string)),
        issuer: provider
            .issuer
            .clone()
            .or_else(|| defaults.issuer.map(str::to_string)),
        scopes: provider
            .scopes
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_string))
                    .collect()
            })
            .filter(|items: &Vec<String>| !items.is_empty())
            .unwrap_or_else(|| defaults.scopes.iter().map(|s| s.to_string()).collect()),
    }
}

fn map_profile(provider: &IdentityProvider, value: &Value) -> ExternalProfile {
    let mapping = provider.attribute_mapping.as_object();
    let pick = |field: &str, fallback: &[&str]| -> Option<String> {
        if let Some(mapped) = mapping
            .and_then(|map| map.get(field))
            .and_then(Value::as_str)
        {
            if let Some(found) = value.get(mapped).and_then(Value::as_str) {
                return Some(found.to_string());
            }
        }
        fallback
            .iter()
            .find_map(|key| value.get(*key).and_then(Value::as_str))
            .map(str::to_string)
    };
    let subject = pick("subject", &["sub", "id", "user_id"]).unwrap_or_default();
    let email = pick("email", &["email", "mail"]);
    let email_verified = value
        .get("email_verified")
        .and_then(Value::as_bool)
        .unwrap_or(email.is_some());
    ExternalProfile {
        subject,
        email,
        email_verified,
        name: pick(
            "display_name",
            &["name", "display_name", "preferred_username", "login"],
        ),
        avatar: pick("avatar", &["picture", "avatar_url", "avatar"]),
        raw: value.clone(),
    }
}

fn normalize_optional(value: Option<String>) -> Option<String> {
    value.filter(|item| !item.trim().is_empty())
}

fn is_private_host(host: &str) -> bool {
    let host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return true;
    }
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00
            }
        };
    }
    false
}
