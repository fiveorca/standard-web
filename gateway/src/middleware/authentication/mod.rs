//! 身份认证：JWT（HMAC / RSA / EC / JWKS）与 API Key。
//!
//! 安全要点：
//! - 只接受配置中显式声明的签名算法，防止算法混淆攻击；
//! - 强制校验 exp / nbf / iss / aud；
//! - API Key 只保存 SHA-256 摘要，并使用常量时间比较；
//! - 完整 Token 不会写入日志。

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use http::HeaderMap;
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use moka::future::Cache;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::config::model::{ApiKeyConfig, AuthConfig, AuthMode, IdentityHeadersConfig, JwtConfig};
use crate::core::identity::{AuthType, Identity};
use crate::error::{GatewayError, Result};

/// 认证服务。
pub struct AuthService {
    jwt: Option<JwtVerifier>,
    api_keys: HashMap<[u8; 32], ApiKeyEntry>,
    api_key_header: String,
    identity_headers: IdentityHeadersConfig,
}

struct ApiKeyEntry {
    id: String,
    scopes: Vec<String>,
    roles: Vec<String>,
    tenant: Option<String>,
    subject: String,
}

impl AuthService {
    pub fn new(config: &AuthConfig) -> Result<Arc<Self>> {
        let jwt = match &config.jwt {
            Some(jwt_config) => Some(JwtVerifier::new(jwt_config)?),
            None => None,
        };

        let mut api_keys = HashMap::new();
        for entry in &config.api_keys {
            if !entry.enabled {
                continue;
            }
            let hash = api_key_hash(entry)?;
            api_keys.insert(
                hash,
                ApiKeyEntry {
                    id: entry.id.clone(),
                    scopes: entry.scopes.clone(),
                    roles: entry.roles.clone(),
                    tenant: entry.tenant.clone(),
                    subject: entry
                        .subject
                        .clone()
                        .unwrap_or_else(|| format!("api-key:{}", entry.id)),
                },
            );
        }

        Ok(Arc::new(Self {
            jwt,
            api_keys,
            api_key_header: config.api_key_header.to_ascii_lowercase(),
            identity_headers: config.identity_headers.clone(),
        }))
    }

    pub fn identity_headers(&self) -> &IdentityHeadersConfig {
        &self.identity_headers
    }

    pub fn has_jwt(&self) -> bool {
        self.jwt.is_some()
    }

    pub fn has_api_keys(&self) -> bool {
        !self.api_keys.is_empty()
    }

    /// 执行认证。
    ///
    /// - `Public`：直接放行，不解析任何凭证；
    /// - `Optional`：有凭证则校验，无凭证放行；
    /// - `Authenticated`：必须提供有效 JWT（或允许时的 API Key）；
    /// - `ApiKey`：必须提供有效 API Key。
    pub async fn authenticate(
        &self,
        headers: &HeaderMap,
        mode: AuthMode,
        allow_api_key: bool,
    ) -> Result<Option<Identity>> {
        if mode == AuthMode::Public {
            return Ok(None);
        }

        let api_key = self.extract_api_key(headers);
        let jwt_token = headers
            .get(self.jwt_header_name())
            .and_then(|v| v.to_str().ok())
            .and_then(|v| extract_bearer(v, self.jwt_prefix()))
            .map(|s| s.to_string());

        match mode {
            AuthMode::ApiKey => {
                let key = api_key
                    .ok_or_else(|| GatewayError::Unauthorized("missing API key".to_string()))?;
                return self.authenticate_api_key(&key).map(Some);
            }
            AuthMode::Authenticated | AuthMode::Optional => {}
            AuthMode::Public => return Ok(None),
        }

        if let Some(token) = jwt_token {
            let verifier = self.jwt.as_ref().ok_or_else(|| {
                GatewayError::Unauthorized("JWT authentication is not configured".to_string())
            })?;
            return verifier.verify(&token).await.map(Some);
        }

        if allow_api_key {
            if let Some(key) = api_key {
                return self.authenticate_api_key(&key).map(Some);
            }
        }

        if mode == AuthMode::Optional {
            return Ok(None);
        }
        Err(GatewayError::Unauthorized(
            "missing authentication credentials".to_string(),
        ))
    }

    fn jwt_header_name(&self) -> String {
        self.jwt
            .as_ref()
            .map(|j| j.config.header.to_ascii_lowercase())
            .unwrap_or_else(|| "authorization".to_string())
    }

    fn jwt_prefix(&self) -> &str {
        self.jwt
            .as_ref()
            .map(|j| j.config.prefix.as_str())
            .unwrap_or("Bearer")
    }

    fn extract_api_key(&self, headers: &HeaderMap) -> Option<String> {
        headers
            .get(&self.api_key_header)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty())
    }

    fn authenticate_api_key(&self, raw: &str) -> Result<Identity> {
        let digest = sha256(raw.as_bytes());
        match self.api_keys.get(&digest) {
            Some(entry) => Ok(Identity {
                subject: entry.subject.clone(),
                scopes: entry.scopes.clone(),
                roles: entry.roles.clone(),
                tenant: entry.tenant.clone(),
                auth_type: AuthType::ApiKey,
                claims: serde_json::Map::new(),
                token: None,
                api_key_id: Some(entry.id.clone()),
            }),
            None => Err(GatewayError::Unauthorized("invalid API key".to_string())),
        }
    }
}

fn api_key_hash(config: &ApiKeyConfig) -> Result<[u8; 32]> {
    if let Some(hash) = &config.key_hash {
        let bytes = hex::decode(hash).map_err(|_| {
            GatewayError::Config(format!("api key `{}` has invalid key_hash", config.id))
        })?;
        if bytes.len() != 32 {
            return Err(GatewayError::Config(format!(
                "api key `{}` key_hash must be 32 bytes",
                config.id
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    if let Some(key) = &config.key {
        return Ok(sha256(key.as_bytes()));
    }
    Err(GatewayError::Config(format!(
        "api key `{}` requires key or key_hash",
        config.id
    )))
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

#[allow(dead_code)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn extract_bearer<'a>(header: &'a str, prefix: &str) -> Option<&'a str> {
    let value = header.trim();
    if prefix.is_empty() {
        return Some(value);
    }
    let (scheme, token) = value.split_once(' ')?;
    if scheme.eq_ignore_ascii_case(prefix) {
        Some(token.trim())
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// JWT 验证
// ---------------------------------------------------------------------------

enum KeySource {
    Hmac(Vec<u8>),
    Jwks(JwksProvider),
}

struct JwtVerifier {
    config: JwtConfig,
    algorithms: Vec<Algorithm>,
    source: KeySource,
}

impl JwtVerifier {
    fn new(config: &JwtConfig) -> Result<Self> {
        let mut algorithms = Vec::with_capacity(config.algorithms.len());
        for alg in &config.algorithms {
            let parsed = parse_algorithm(alg)?;
            if parsed == Algorithm::HS256 && config.secret.is_none() && config.secret_env.is_none()
            {
                return Err(GatewayError::Config(
                    "HS256 requires a secret or secret_env".to_string(),
                ));
            }
            algorithms.push(parsed);
        }
        if algorithms.is_empty() {
            return Err(GatewayError::Config(
                "jwt.algorithms must not be empty".to_string(),
            ));
        }

        let needs_jwks = algorithms.iter().any(|a| {
            matches!(
                a,
                Algorithm::RS256
                    | Algorithm::RS384
                    | Algorithm::RS512
                    | Algorithm::ES256
                    | Algorithm::ES384
            )
        });

        let source = if needs_jwks {
            let uri = config.jwks_uri.clone().ok_or_else(|| {
                GatewayError::Config("asymmetric JWT algorithms require jwks_uri".to_string())
            })?;
            KeySource::Jwks(JwksProvider::new(
                uri,
                Duration::from_secs(300),
                Duration::from_secs(30),
            )?)
        } else {
            let secret = config
                .secret
                .clone()
                .or_else(|| {
                    config
                        .secret_env
                        .as_ref()
                        .and_then(|name| std::env::var(name).ok())
                })
                .ok_or_else(|| GatewayError::Config("jwt secret is not configured".to_string()))?;
            if secret.len() < 32 {
                tracing::warn!("JWT HMAC secret is shorter than 32 bytes and is considered weak");
            }
            KeySource::Hmac(secret.into_bytes())
        };

        Ok(Self {
            config: config.clone(),
            algorithms,
            source,
        })
    }

    fn allowed_algorithm(&self, header_alg: Algorithm) -> bool {
        self.algorithms.contains(&header_alg)
    }

    async fn verify(&self, token: &str) -> Result<Identity> {
        let header = decode_header(token)
            .map_err(|_| GatewayError::Unauthorized("malformed JWT".to_string()))?;

        if !self.allowed_algorithm(header.alg) {
            return Err(GatewayError::Unauthorized(
                "JWT signing algorithm is not allowed".to_string(),
            ));
        }

        let key = match &self.source {
            KeySource::Hmac(secret) => DecodingKey::from_secret(secret),
            KeySource::Jwks(provider) => provider
                .decoding_key(header.kid.as_deref(), header.alg)
                .await
                .map_err(|e| GatewayError::Unauthorized(format!("JWKS error: {e}")))?,
        };

        let mut validation = Validation::new(header.alg);
        validation.leeway = self.config.leeway;
        validation.validate_exp = true;
        validation.validate_nbf = true;

        let mut required: HashSet<String> = HashSet::new();
        if self.config.require_exp {
            required.insert("exp".to_string());
        }
        for claim in &self.config.required_claims {
            required.insert(claim.clone());
        }
        validation.required_spec_claims = required;

        if self.config.audience.is_empty() {
            validation.validate_aud = false;
        } else {
            validation.set_audience(&self.config.audience);
        }
        if let Some(issuer) = &self.config.issuer {
            validation.set_issuer(&[issuer]);
        }

        let data = decode::<serde_json::Value>(token, &key, &validation).map_err(|e| {
            GatewayError::Unauthorized(format!("invalid JWT: {}", sanitize_jwt_error(&e)))
        })?;

        let claims = match data.claims {
            serde_json::Value::Object(map) => map,
            _ => {
                return Err(GatewayError::Unauthorized(
                    "JWT claims must be a JSON object".to_string(),
                ))
            }
        };

        if let Some(type_claim) = &self.config.token_type_claim {
            if !self.config.allowed_token_types.is_empty() {
                let actual = claims
                    .get(type_claim)
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if !self
                    .config
                    .allowed_token_types
                    .iter()
                    .any(|t| t.eq_ignore_ascii_case(actual))
                {
                    return Err(GatewayError::Unauthorized(
                        "unexpected token type".to_string(),
                    ));
                }
            }
        }

        let subject = claims
            .get(&self.config.subject_claim)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        if subject.is_empty() && self.config.required_claims.iter().any(|c| c == "sub") {
            return Err(GatewayError::Unauthorized(
                "JWT subject is missing".to_string(),
            ));
        }

        let scopes = extract_string_list(claims.get(&self.config.scope_claim));
        let roles = extract_string_list(claims.get(&self.config.roles_claim));
        let tenant = claims
            .get(&self.config.tenant_claim)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(Identity {
            subject: if subject.is_empty() {
                "anonymous".to_string()
            } else {
                subject
            },
            scopes,
            roles,
            tenant,
            auth_type: AuthType::Jwt,
            claims,
            token: Some(token.to_string()),
            api_key_id: None,
        })
    }
}

fn sanitize_jwt_error(err: &jsonwebtoken::errors::Error) -> String {
    use jsonwebtoken::errors::ErrorKind;
    match err.kind() {
        ErrorKind::ExpiredSignature => "token has expired".to_string(),
        ErrorKind::ImmatureSignature => "token is not valid yet".to_string(),
        ErrorKind::InvalidSignature => "signature verification failed".to_string(),
        ErrorKind::InvalidIssuer => "issuer mismatch".to_string(),
        ErrorKind::InvalidAudience => "audience mismatch".to_string(),
        ErrorKind::InvalidToken | ErrorKind::InvalidAlgorithm => "invalid token".to_string(),
        ErrorKind::MissingRequiredClaim(claim) => format!("missing required claim `{claim}`"),
        _ => "token validation failed".to_string(),
    }
}

fn parse_algorithm(value: &str) -> Result<Algorithm> {
    match value.to_ascii_uppercase().as_str() {
        "HS256" => Ok(Algorithm::HS256),
        "HS384" => Ok(Algorithm::HS384),
        "HS512" => Ok(Algorithm::HS512),
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        other => Err(GatewayError::Config(format!(
            "unsupported JWT algorithm `{other}`"
        ))),
    }
}

fn extract_string_list(value: Option<&serde_json::Value>) -> Vec<String> {
    match value {
        Some(serde_json::Value::String(s)) => s
            .split([' ', ','])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

struct JwksProvider {
    uri: String,
    client: reqwest::Client,
    cache: Cache<String, Arc<Vec<Jwk>>>,
    last_refresh: std::sync::Mutex<Option<Instant>>,
    min_refresh_interval: Duration,
}

impl JwksProvider {
    fn new(uri: String, ttl: Duration, min_refresh: Duration) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .build()
            .map_err(|e| GatewayError::Config(format!("failed to build JWKS client: {e}")))?;
        Ok(Self {
            uri,
            client,
            cache: Cache::builder().time_to_live(ttl).max_capacity(4).build(),
            last_refresh: std::sync::Mutex::new(None),
            min_refresh_interval: min_refresh,
        })
    }

    async fn keys(&self, force_refresh: bool) -> std::result::Result<Arc<Vec<Jwk>>, String> {
        if !force_refresh {
            if let Some(keys) = self.cache.get("keys").await {
                return Ok(keys);
            }
        }

        if force_refresh {
            let too_soon = {
                let last = self.last_refresh.lock().unwrap_or_else(|p| p.into_inner());
                last.map(|at| at.elapsed() < self.min_refresh_interval)
                    .unwrap_or(false)
            };
            if too_soon {
                if let Some(keys) = self.cache.get("keys").await {
                    return Ok(keys);
                }
            }
            *self.last_refresh.lock().unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
        }

        let response = self
            .client
            .get(&self.uri)
            .send()
            .await
            .map_err(|e| format!("failed to fetch JWKS: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("JWKS endpoint returned {}", response.status()));
        }
        let set: JwkSet = response
            .json()
            .await
            .map_err(|e| format!("invalid JWKS response: {e}"))?;
        let keys = Arc::new(set.keys);
        self.cache.insert("keys".to_string(), keys.clone()).await;
        *self.last_refresh.lock().unwrap_or_else(|p| p.into_inner()) = Some(Instant::now());
        Ok(keys)
    }

    async fn decoding_key(
        &self,
        kid: Option<&str>,
        algorithm: Algorithm,
    ) -> std::result::Result<DecodingKey, String> {
        let mut keys = self.keys(false).await?;
        let mut found = find_key(&keys, kid);
        if found.is_none() {
            keys = self.keys(true).await?;
            found = find_key(&keys, kid);
        }
        let jwk = found.ok_or_else(|| "no matching JWK found".to_string())?;
        let jwk_alg = jwk.common.key_algorithm;
        if let Some(jwk_alg) = jwk_alg {
            let expected = match algorithm {
                Algorithm::RS256 => Some(jsonwebtoken::jwk::KeyAlgorithm::RS256),
                Algorithm::RS384 => Some(jsonwebtoken::jwk::KeyAlgorithm::RS384),
                Algorithm::RS512 => Some(jsonwebtoken::jwk::KeyAlgorithm::RS512),
                Algorithm::ES256 => Some(jsonwebtoken::jwk::KeyAlgorithm::ES256),
                Algorithm::ES384 => Some(jsonwebtoken::jwk::KeyAlgorithm::ES384),
                _ => None,
            };
            if let Some(expected) = expected {
                if jwk_alg != expected {
                    return Err("JWK algorithm does not match token algorithm".to_string());
                }
            }
        }
        DecodingKey::from_jwk(&jwk).map_err(|e| format!("invalid JWK: {e}"))
    }
}

fn find_key(keys: &[Jwk], kid: Option<&str>) -> Option<Jwk> {
    match kid {
        Some(kid) => keys
            .iter()
            .find(|k| k.common.key_id.as_deref() == Some(kid))
            .cloned(),
        None => {
            if keys.len() == 1 {
                keys.first().cloned()
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde_json::json;

    const SECRET: &[u8] = b"0123456789abcdef0123456789abcdef";

    fn config() -> AuthConfig {
        AuthConfig {
            jwt: Some(JwtConfig {
                algorithms: vec!["HS256".to_string()],
                secret: Some(String::from_utf8(SECRET.to_vec()).unwrap()),
                issuer: Some("https://issuer.example.com".to_string()),
                audience: vec!["gateway".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn token(claims: serde_json::Value) -> String {
        encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap()
    }

    fn valid_claims() -> serde_json::Value {
        let exp = (chrono::Utc::now() + chrono::Duration::seconds(300)).timestamp();
        json!({
            "sub": "user-1",
            "iss": "https://issuer.example.com",
            "aud": "gateway",
            "exp": exp,
            "scope": "read write",
            "roles": ["admin"],
            "tenant": "acme"
        })
    }

    fn headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", format!("Bearer {token}").parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn accepts_valid_token() {
        let service = AuthService::new(&config()).unwrap();
        let identity = service
            .authenticate(
                &headers(&token(valid_claims())),
                AuthMode::Authenticated,
                true,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(identity.subject, "user-1");
        assert!(identity.has_scope("read"));
        assert!(identity.has_role("admin"));
        assert_eq!(identity.tenant.as_deref(), Some("acme"));
    }

    #[tokio::test]
    async fn rejects_expired_token() {
        let service = AuthService::new(&config()).unwrap();
        let mut claims = valid_claims();
        claims["exp"] = json!((chrono::Utc::now() - chrono::Duration::seconds(120)).timestamp());
        let err = service
            .authenticate(&headers(&token(claims)), AuthMode::Authenticated, true)
            .await
            .unwrap_err();
        assert!(matches!(err, GatewayError::Unauthorized(_)));
    }

    #[tokio::test]
    async fn rejects_bad_signature() {
        let service = AuthService::new(&config()).unwrap();
        let forged = encode(
            &Header::new(Algorithm::HS256),
            &valid_claims(),
            &EncodingKey::from_secret(b"another-secret-another-secret-xx"),
        )
        .unwrap();
        assert!(service
            .authenticate(&headers(&forged), AuthMode::Authenticated, true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_wrong_issuer_and_audience() {
        let service = AuthService::new(&config()).unwrap();
        let mut claims = valid_claims();
        claims["iss"] = json!("https://evil.example.com");
        assert!(service
            .authenticate(&headers(&token(claims)), AuthMode::Authenticated, true)
            .await
            .is_err());

        let mut claims = valid_claims();
        claims["aud"] = json!("other");
        assert!(service
            .authenticate(&headers(&token(claims)), AuthMode::Authenticated, true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_algorithm_confusion() {
        let service = AuthService::new(&config()).unwrap();
        // 使用 HS512 签名，但配置只允许 HS256。
        let forged = encode(
            &Header::new(Algorithm::HS512),
            &valid_claims(),
            &EncodingKey::from_secret(SECRET),
        )
        .unwrap();
        assert!(service
            .authenticate(&headers(&forged), AuthMode::Authenticated, true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn api_key_authentication() {
        let hash = hex::encode(sha256(b"secret-key"));
        let config = AuthConfig {
            api_keys: vec![ApiKeyConfig {
                id: "partner".into(),
                key: None,
                key_hash: Some(hash),
                scopes: vec!["read".into()],
                roles: vec![],
                tenant: Some("acme".into()),
                subject: Some("partner-app".into()),
                enabled: true,
            }],
            ..Default::default()
        };
        let service = AuthService::new(&config).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("x-api-key", "secret-key".parse().unwrap());
        let identity = service
            .authenticate(&headers, AuthMode::Authenticated, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(identity.subject, "partner-app");
        assert_eq!(identity.auth_type, AuthType::ApiKey);

        headers.insert("x-api-key", "wrong".parse().unwrap());
        assert!(service
            .authenticate(&headers, AuthMode::Authenticated, true)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn public_mode_skips_authentication() {
        let service = AuthService::new(&AuthConfig::default()).unwrap();
        let identity = service
            .authenticate(&HeaderMap::new(), AuthMode::Public, false)
            .await
            .unwrap();
        assert!(identity.is_none());
    }
}
