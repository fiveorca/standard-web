//! 认证中心客户端：JWKS 离线校验、内部 API 与授权决策。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::redis::aio::ConnectionManager;
use chrono::Utc;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::config::{AuthCenterConfig, RedisConfig};
use crate::infrastructure::redis;
use crate::shared::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    #[serde(default)]
    pub aud: Value,
    #[serde(default)]
    pub exp: i64,
    #[serde(default)]
    pub iat: i64,
    #[serde(default)]
    pub nbf: i64,
    #[serde(default)]
    pub jti: String,
    #[serde(default)]
    pub tenant_id: String,
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub sid: String,
    #[serde(default)]
    pub amr: Vec<String>,
    #[serde(default)]
    pub acr: String,
    #[serde(default)]
    pub typ: String,
    #[serde(default)]
    pub auth_time: Option<i64>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<bool>,
    #[serde(default)]
    pub phone_number: Option<String>,
    #[serde(default)]
    pub phone_number_verified: Option<bool>,
    #[serde(default)]
    pub picture: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub identity_id: Uuid,
    pub tenant_id: Uuid,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub session_id: Option<Uuid>,
    pub claims: Claims,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IdentityView {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: bool,
    #[serde(default)]
    pub phone: Option<String>,
    #[serde(default)]
    pub phone_verified: bool,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub status: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthzDecision {
    pub allowed: bool,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub matched_roles: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Envelope<T> {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: Option<String>,
    data: Option<T>,
}

#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    kty: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    n: Option<String>,
    #[serde(default)]
    e: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct TokenEndpointResponse {
    access_token: String,
    #[serde(default)]
    expires_in: i64,
}

struct KeyCache {
    keys: HashMap<String, DecodingKey>,
    expires_at: Instant,
}

pub struct AuthClient {
    http: reqwest::Client,
    config: AuthCenterConfig,
    redis: Option<ConnectionManager>,
    redis_config: RedisConfig,
    cache: Mutex<Option<KeyCache>>,
    service_token: Mutex<Option<(String, Instant)>>,
}

impl AuthClient {
    pub fn new(
        config: AuthCenterConfig,
        redis: Option<ConnectionManager>,
        redis_config: RedisConfig,
    ) -> Arc<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs.max(1)))
            .user_agent("user-center/0.1")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Arc::new(Self {
            http,
            config,
            redis,
            redis_config,
            cache: Mutex::new(None),
            service_token: Mutex::new(None),
        })
    }

    pub fn base_url(&self) -> String {
        self.config.base_url.trim_end_matches('/').to_string()
    }

    fn jwks_uri(&self) -> String {
        self.config
            .jwks_uri
            .clone()
            .unwrap_or_else(|| format!("{}/oauth2/jwks", self.base_url()))
    }

    fn cache_key(&self) -> String {
        format!("{}:jwks", self.redis_config.key_prefix)
    }

    pub async fn health(&self) -> bool {
        let url = format!("{}/health", self.base_url());
        matches!(
            self.http.get(url).send().await,
            Ok(response) if response.status().is_success()
        )
    }

    /// 使用 JWKS 离线校验 access token。
    pub async fn verify_access_token(&self, token: &str) -> AppResult<AuthContext> {
        let header =
            decode_header(token).map_err(|_| AppError::unauthorized("访问令牌格式不正确"))?;
        if !matches!(
            header.alg,
            Algorithm::RS256
                | Algorithm::RS384
                | Algorithm::RS512
                | Algorithm::ES256
                | Algorithm::ES384
        ) {
            return Err(AppError::unauthorized("访问令牌签名算法不受支持"));
        }
        let kid = header
            .kid
            .ok_or_else(|| AppError::unauthorized("访问令牌缺少 kid"))?;
        let key = self.decoding_key(&kid).await?;

        let mut validation = Validation::new(header.alg);
        validation.set_issuer(&[self.config.issuer.as_str()]);
        if self.config.audience.trim().is_empty() {
            validation.validate_aud = false;
        } else {
            validation.set_audience(&[self.config.audience.as_str()]);
        }
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);
        validation.leeway = 30;

        let data = decode::<Claims>(token, &key, &validation)
            .map_err(|error| AppError::unauthorized(format!("访问令牌校验失败: {error}")))?;
        let claims = data.claims;
        if !claims.typ.is_empty() && claims.typ != "access" {
            return Err(AppError::unauthorized("令牌类型不正确"));
        }
        if claims.exp > 0 && claims.exp < Utc::now().timestamp() {
            return Err(AppError::unauthorized("访问令牌已过期"));
        }
        let identity_id = Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::unauthorized("令牌 subject 非法"))?;
        let tenant_id = Uuid::parse_str(&claims.tenant_id)
            .map_err(|_| AppError::unauthorized("令牌 tenant_id 非法"))?;
        let scopes = claims
            .scope
            .split_whitespace()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let session_id = Uuid::parse_str(&claims.sid).ok();
        Ok(AuthContext {
            identity_id,
            tenant_id,
            client_id: claims.client_id.clone(),
            scopes,
            session_id,
            claims,
        })
    }

    async fn decoding_key(&self, kid: &str) -> AppResult<DecodingKey> {
        {
            let guard = self.cache.lock().await;
            if let Some(cache) = guard.as_ref() {
                if cache.expires_at > Instant::now() {
                    if let Some(key) = cache.keys.get(kid) {
                        return Ok(key.clone());
                    }
                }
            }
        }
        if let Some(manager) = &self.redis {
            if let Ok(Some(cached)) = redis::get(manager, &self.cache_key()).await {
                if let Ok(set) = serde_json::from_str::<JwkSet>(&cached) {
                    let keys = self.build_keys(set)?;
                    if let Some(key) = keys.get(kid).cloned() {
                        let mut guard = self.cache.lock().await;
                        *guard = Some(KeyCache {
                            keys,
                            expires_at: Instant::now()
                                + Duration::from_secs(self.config.jwks_cache_secs.max(30)),
                        });
                        return Ok(key);
                    }
                }
            }
        }

        let response = self
            .http
            .get(self.jwks_uri())
            .send()
            .await
            .map_err(|error| AppError::server_error(format!("获取 JWKS 失败: {error}")))?;
        if !response.status().is_success() {
            return Err(AppError::server_error("认证中心 JWKS 不可用"));
        }
        let text = response
            .text()
            .await
            .map_err(|error| AppError::server_error(format!("读取 JWKS 失败: {error}")))?;
        let set: JwkSet = serde_json::from_str(&text)
            .map_err(|error| AppError::server_error(format!("解析 JWKS 失败: {error}")))?;
        let keys = self.build_keys(set)?;
        let key = keys
            .get(kid)
            .cloned()
            .ok_or_else(|| AppError::unauthorized("令牌签名密钥不存在"))?;
        if let Some(manager) = &self.redis {
            let _ = redis::set_ex(
                manager,
                &self.cache_key(),
                &text,
                self.config.jwks_cache_secs.max(30),
            )
            .await;
        }
        let mut guard = self.cache.lock().await;
        *guard = Some(KeyCache {
            keys,
            expires_at: Instant::now() + Duration::from_secs(self.config.jwks_cache_secs.max(30)),
        });
        Ok(key)
    }

    fn build_keys(&self, set: JwkSet) -> AppResult<HashMap<String, DecodingKey>> {
        let mut keys = HashMap::new();
        for jwk in set.keys {
            let Some(kid) = jwk.kid.clone() else {
                continue;
            };
            let key = match jwk.kty.as_str() {
                "RSA" => match (jwk.n.as_deref(), jwk.e.as_deref()) {
                    (Some(n), Some(e)) => {
                        DecodingKey::from_rsa_components(n, e).map_err(|error| {
                            AppError::server_error(format!("解析 RSA 公钥失败: {error}"))
                        })?
                    }
                    _ => continue,
                },
                "EC" => match (jwk.x.as_deref(), jwk.y.as_deref()) {
                    (Some(x), Some(y)) => {
                        DecodingKey::from_ec_components(x, y).map_err(|error| {
                            AppError::server_error(format!("解析 EC 公钥失败: {error}"))
                        })?
                    }
                    _ => continue,
                },
                _ => {
                    tracing::warn!(kty = %jwk.kty, alg = ?jwk.alg, "忽略不支持的 JWK 类型");
                    continue;
                }
            };
            keys.insert(kid, key);
        }
        if keys.is_empty() {
            return Err(AppError::server_error("认证中心未返回可用签名密钥"));
        }
        Ok(keys)
    }

    /// 使用 client_credentials 获取服务令牌（可选路径）。
    pub async fn service_token(&self) -> AppResult<String> {
        {
            let guard = self.service_token.lock().await;
            if let Some((token, expires_at)) = guard.as_ref() {
                if *expires_at > Instant::now() {
                    return Ok(token.clone());
                }
            }
        }
        if self.config.service_client_secret.is_empty() {
            return Err(AppError::server_error("未配置服务客户端凭据"));
        }
        let url = format!("{}/oauth2/token", self.base_url());
        let response = self
            .http
            .post(url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.config.service_client_id.as_str()),
                ("client_secret", self.config.service_client_secret.as_str()),
                ("scope", "internal"),
            ])
            .send()
            .await
            .map_err(|error| AppError::server_error(format!("获取服务令牌失败: {error}")))?;
        if !response.status().is_success() {
            return Err(AppError::server_error("认证中心拒绝服务令牌请求"));
        }
        let body: TokenEndpointResponse = response
            .json()
            .await
            .map_err(|error| AppError::server_error(format!("解析服务令牌失败: {error}")))?;
        let ttl = (body.expires_in.max(60) - 30) as u64;
        let mut guard = self.service_token.lock().await;
        *guard = Some((
            body.access_token.clone(),
            Instant::now() + Duration::from_secs(ttl),
        ));
        Ok(body.access_token)
    }

    async fn internal_request<T: for<'de> Deserialize<'de>>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> AppResult<T> {
        let url = format!("{}{}", self.base_url(), path);
        let mut request = self
            .http
            .request(method, url)
            .header("x-internal-token", &self.config.internal_token);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .map_err(|error| AppError::server_error(format!("调用认证中心失败: {error}")))?;
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|error| AppError::server_error(format!("读取认证中心响应失败: {error}")))?;
        if !status.is_success() {
            let message = serde_json::from_str::<Value>(&text)
                .ok()
                .and_then(|value| {
                    value
                        .get("message")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or_else(|| format!("认证中心返回 {status}"));
            return Err(AppError::server_error(message));
        }
        let envelope: Envelope<T> = serde_json::from_str(&text)
            .map_err(|error| AppError::server_error(format!("解析认证中心响应失败: {error}")))?;
        if envelope.code != "ok" {
            return Err(AppError::server_error(
                envelope
                    .message
                    .unwrap_or_else(|| "认证中心返回错误".to_string()),
            ));
        }
        envelope.data.ok_or_else(|| {
            AppError::server_error(
                envelope
                    .message
                    .unwrap_or_else(|| "认证中心未返回数据".to_string()),
            )
        })
    }

    async fn internal_ok(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> AppResult<()> {
        let _: Value = self.internal_request(method, path, body).await?;
        Ok(())
    }

    pub async fn create_identity(&self, body: Value) -> AppResult<IdentityView> {
        #[derive(Deserialize)]
        struct Wrapper {
            identity: IdentityView,
        }
        let wrapper: Wrapper = self
            .internal_request(
                reqwest::Method::POST,
                "/api/v1/internal/identities",
                Some(body),
            )
            .await?;
        Ok(wrapper.identity)
    }

    pub async fn get_identity(&self, id: Uuid) -> AppResult<IdentityView> {
        #[derive(Deserialize)]
        struct Wrapper {
            identity: IdentityView,
        }
        let wrapper: Wrapper = self
            .internal_request(
                reqwest::Method::GET,
                &format!("/api/v1/internal/identities/{id}"),
                None,
            )
            .await?;
        Ok(wrapper.identity)
    }

    pub async fn update_status(
        &self,
        id: Uuid,
        status: &str,
        reason: Option<&str>,
    ) -> AppResult<()> {
        self.internal_ok(
            reqwest::Method::POST,
            &format!("/api/v1/internal/identities/{id}/status"),
            Some(json!({ "status": status, "reason": reason })),
        )
        .await
    }

    pub async fn sync_profile(
        &self,
        id: Uuid,
        display_name: Option<&str>,
        avatar_url: Option<&str>,
    ) -> AppResult<()> {
        self.internal_ok(
            reqwest::Method::PATCH,
            &format!("/api/v1/internal/identities/{id}"),
            Some(json!({ "display_name": display_name, "avatar_url": avatar_url })),
        )
        .await
    }

    pub async fn revoke_sessions(&self, id: Uuid) -> AppResult<()> {
        self.internal_ok(
            reqwest::Method::POST,
            &format!("/api/v1/internal/identities/{id}/sessions/revoke"),
            Some(json!({})),
        )
        .await
    }

    pub async fn request_contact_change(
        &self,
        id: Uuid,
        channel: &str,
        value: &str,
    ) -> AppResult<()> {
        self.internal_ok(
            reqwest::Method::POST,
            &format!("/api/v1/internal/identities/{id}/contacts/request"),
            Some(json!({ "channel": channel, "value": value })),
        )
        .await
    }

    pub async fn confirm_contact_change(
        &self,
        id: Uuid,
        channel: &str,
        value: &str,
        code: &str,
    ) -> AppResult<()> {
        self.internal_ok(
            reqwest::Method::POST,
            &format!("/api/v1/internal/identities/{id}/contacts/confirm"),
            Some(json!({ "channel": channel, "value": value, "code": code })),
        )
        .await
    }

    pub async fn clear_contact(&self, id: Uuid, kind: &str) -> AppResult<()> {
        self.internal_ok(
            reqwest::Method::DELETE,
            &format!("/api/v1/internal/identities/{id}/contacts/{kind}"),
            None,
        )
        .await
    }

    /// 通过认证中心内部授权接口做 RBAC/ABAC/ReBAC 判定。
    pub async fn authorize(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        permission: &str,
        resource: Option<Value>,
    ) -> AppResult<AuthzDecision> {
        self.internal_request(
            reqwest::Method::POST,
            "/api/v1/internal/authz/check",
            Some(json!({
                "tenant_id": tenant_id,
                "identity_id": identity_id,
                "permission": permission,
                "resource": resource,
            })),
        )
        .await
    }
}
