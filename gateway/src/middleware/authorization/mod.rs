//! 授权：基于 JWT scope / role / 元数据，以及外部授权中心。
//!
//! 网关只做「接口级」访问控制，不判断用户是否有权访问某一条具体业务数据。
//! 外部授权结果带短 TTL 缓存，并支持明确的超时与 fail-open / fail-closed 策略。

use std::collections::HashMap;
use std::time::Duration;

use async_trait::async_trait;
use http::header::HeaderMap;
use http::Method;
use moka::future::Cache;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::config::model::{ExternalAuthzConfig, IdentityHeadersConfig, RouteAuthorizationConfig};
use crate::core::identity::Identity;
use crate::error::{GatewayError, Result};

/// 授权请求视图。
pub struct AuthorizationRequest<'a> {
    pub identity: Option<&'a Identity>,
    pub method: &'a Method,
    pub path: &'a str,
    pub headers: &'a HeaderMap,
    pub route_id: &'a str,
    pub route_metadata: &'a HashMap<String, String>,
}

/// 统一授权提供者接口。
#[async_trait]
pub trait AuthorizationProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn authorize(
        &self,
        req: &AuthorizationRequest<'_>,
        policy: &RouteAuthorizationConfig,
    ) -> Result<()>;
}

/// 基于 JWT / API Key 身份的本地授权。
#[derive(Debug, Default)]
pub struct IdentityAuthorizationProvider;

#[async_trait]
impl AuthorizationProvider for IdentityAuthorizationProvider {
    fn name(&self) -> &'static str {
        "jwt"
    }

    async fn authorize(
        &self,
        req: &AuthorizationRequest<'_>,
        policy: &RouteAuthorizationConfig,
    ) -> Result<()> {
        let identity = req.identity.ok_or_else(|| {
            GatewayError::Unauthorized("authentication is required for this route".to_string())
        })?;

        if !policy.scopes.is_empty() && !identity.has_any_scope(&policy.scopes) {
            return Err(GatewayError::Forbidden(format!(
                "missing required scope (one of: {})",
                policy.scopes.join(", ")
            )));
        }
        if !policy.roles.is_empty() && !identity.has_any_role(&policy.roles) {
            return Err(GatewayError::Forbidden(format!(
                "missing required role (one of: {})",
                policy.roles.join(", ")
            )));
        }
        for (key, expected) in &policy.metadata {
            let actual = identity
                .claims
                .get(key)
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if actual != expected {
                return Err(GatewayError::Forbidden(format!(
                    "identity metadata `{key}` does not satisfy policy"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct ExternalAuthzPayload<'a> {
    route: &'a str,
    method: &'a str,
    path: &'a str,
    subject: Option<&'a str>,
    tenant: Option<&'a str>,
    scopes: &'a [String],
    roles: &'a [String],
    metadata: &'a HashMap<String, String>,
    headers: HashMap<String, String>,
}

/// 外部授权中心。
pub struct ExternalAuthorizationProvider {
    config: ExternalAuthzConfig,
    client: reqwest::Client,
    cache: Cache<String, bool>,
}

impl ExternalAuthorizationProvider {
    pub fn new(config: ExternalAuthzConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.timeout)
            .pool_max_idle_per_host(16)
            .build()
            .map_err(|e| GatewayError::Config(format!("failed to build authz client: {e}")))?;
        let ttl = config.cache_ttl.max(Duration::from_secs(1));
        Ok(Self {
            config,
            client,
            cache: Cache::builder()
                .time_to_live(ttl)
                .max_capacity(50_000)
                .build(),
        })
    }

    async fn call(&self, req: &AuthorizationRequest<'_>) -> Result<()> {
        let mut forwarded = HashMap::new();
        for name in &self.config.forward_headers {
            if let Some(value) = req.headers.get(name.as_str()).and_then(|v| v.to_str().ok()) {
                forwarded.insert(name.to_ascii_lowercase(), value.to_string());
            }
        }
        let payload = ExternalAuthzPayload {
            route: req.route_id,
            method: req.method.as_str(),
            path: req.path,
            subject: req.identity.map(|i| i.subject.as_str()),
            tenant: req.identity.and_then(|i| i.tenant.as_deref()),
            scopes: req.identity.map(|i| i.scopes.as_slice()).unwrap_or(&[]),
            roles: req.identity.map(|i| i.roles.as_slice()).unwrap_or(&[]),
            metadata: req.route_metadata,
            headers: forwarded,
        };

        let response = self
            .client
            .post(&self.config.url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| {
                GatewayError::ServiceUnavailable(format!("authorization service error: {e}"))
            })?;

        if response.status().is_success() {
            return Ok(());
        }
        if response.status() == http::StatusCode::FORBIDDEN
            || response.status() == http::StatusCode::UNAUTHORIZED
        {
            return Err(GatewayError::Forbidden(
                "access denied by authorization service".to_string(),
            ));
        }
        Err(GatewayError::ServiceUnavailable(format!(
            "authorization service returned {}",
            response.status()
        )))
    }

    fn cache_key(req: &AuthorizationRequest<'_>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(req.route_id.as_bytes());
        hasher.update(b"|");
        hasher.update(req.method.as_str().as_bytes());
        hasher.update(b"|");
        hasher.update(req.path.as_bytes());
        hasher.update(b"|");
        if let Some(identity) = req.identity {
            hasher.update(identity.subject.as_bytes());
            hasher.update(b"|");
            hasher.update(identity.tenant.as_deref().unwrap_or("").as_bytes());
        }
        hex::encode(hasher.finalize())
    }
}

#[async_trait]
impl AuthorizationProvider for ExternalAuthorizationProvider {
    fn name(&self) -> &'static str {
        "external"
    }

    async fn authorize(
        &self,
        req: &AuthorizationRequest<'_>,
        _policy: &RouteAuthorizationConfig,
    ) -> Result<()> {
        let key = Self::cache_key(req);
        if let Some(allowed) = self.cache.get(&key).await {
            if allowed {
                return Ok(());
            }
            return Err(GatewayError::Forbidden(
                "access denied by authorization service".to_string(),
            ));
        }

        let outcome = tokio::time::timeout(self.config.timeout, self.call(req)).await;
        match outcome {
            Ok(Ok(())) => {
                self.cache.insert(key, true).await;
                Ok(())
            }
            Ok(Err(GatewayError::Forbidden(msg))) => {
                self.cache.insert(key, false).await;
                Err(GatewayError::Forbidden(msg))
            }
            Ok(Err(err)) => {
                if self.config.fail_open {
                    tracing::warn!(error = %err, "external authorization failed; fail-open");
                    Ok(())
                } else {
                    Err(err)
                }
            }
            Err(_) => {
                if self.config.fail_open {
                    tracing::warn!("external authorization timed out; fail-open");
                    Ok(())
                } else {
                    Err(GatewayError::ServiceUnavailable(
                        "authorization service timed out".to_string(),
                    ))
                }
            }
        }
    }
}

/// 授权服务：根据路由策略选择本地或外部授权。
pub struct AuthorizationService {
    identity: IdentityAuthorizationProvider,
    externals: HashMap<String, ExternalAuthorizationProvider>,
}

impl AuthorizationService {
    pub fn new() -> Self {
        Self {
            identity: IdentityAuthorizationProvider,
            externals: HashMap::new(),
        }
    }

    pub fn with_external(mut self, config: ExternalAuthzConfig) -> Result<Self> {
        self.register_external(config)?;
        Ok(self)
    }

    pub fn register_external(&mut self, config: ExternalAuthzConfig) -> Result<()> {
        if config.url.trim().is_empty() {
            return Err(GatewayError::Config(
                "external authorization url is empty".to_string(),
            ));
        }
        let provider = ExternalAuthorizationProvider::new(config.clone())?;
        self.externals.insert(config.url, provider);
        Ok(())
    }

    pub async fn authorize(
        &self,
        req: &AuthorizationRequest<'_>,
        policy: &RouteAuthorizationConfig,
    ) -> Result<()> {
        if policy.provider.eq_ignore_ascii_case("external") {
            let config = policy.external.as_ref().ok_or_else(|| {
                GatewayError::Config(
                    "external authorization provider requires `authorization.external`".to_string(),
                )
            })?;
            let external = self.externals.get(&config.url).ok_or_else(|| {
                GatewayError::Config(format!(
                    "external authorization provider `{}` is not configured",
                    config.url
                ))
            })?;
            return external.authorize(req, policy).await;
        }
        self.identity.authorize(req, policy).await
    }
}

impl Default for AuthorizationService {
    fn default() -> Self {
        Self::new()
    }
}

/// 删除客户端自行提交的内部身份头，防止身份伪造。
pub fn sanitize_identity_headers(headers: &mut HeaderMap, config: &IdentityHeadersConfig) {
    for name in [
        &config.user_id,
        &config.scopes,
        &config.roles,
        &config.tenant,
        &config.auth_type,
    ] {
        if let Ok(name) = http::HeaderName::from_bytes(name.as_bytes()) {
            headers.remove(&name);
        }
    }
}

/// 写入由网关生成的可信身份头。
pub fn inject_identity_headers(
    headers: &mut HeaderMap,
    config: &IdentityHeadersConfig,
    identity: &Identity,
) {
    let mut set = |name: &str, value: &str| {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
    };
    set(&config.user_id, &identity.subject);
    if !identity.scopes.is_empty() {
        set(&config.scopes, &identity.scopes.join(" "));
    }
    if !identity.roles.is_empty() {
        set(&config.roles, &identity.roles.join(","));
    }
    if let Some(tenant) = &identity.tenant {
        set(&config.tenant, tenant);
    }
    set(&config.auth_type, identity.auth_type.as_str());
}

/// 对路由的 authentication.scopes / roles 做二次校验。
pub fn enforce_route_requirements(
    identity: Option<&Identity>,
    scopes: &[String],
    roles: &[String],
) -> Result<()> {
    if scopes.is_empty() && roles.is_empty() {
        return Ok(());
    }
    let identity = identity.ok_or_else(|| {
        GatewayError::Unauthorized("authentication is required for this route".to_string())
    })?;
    if !scopes.is_empty() && !identity.has_any_scope(scopes) {
        return Err(GatewayError::Forbidden(
            "missing required scope".to_string(),
        ));
    }
    if !roles.is_empty() && !identity.has_any_role(roles) {
        return Err(GatewayError::Forbidden("missing required role".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::identity::AuthType;

    fn identity(scopes: &[&str], roles: &[&str]) -> Identity {
        Identity {
            subject: "user-1".into(),
            scopes: scopes.iter().map(|s| s.to_string()).collect(),
            roles: roles.iter().map(|r| r.to_string()).collect(),
            tenant: Some("acme".into()),
            auth_type: AuthType::Jwt,
            claims: serde_json::Map::new(),
            token: None,
            api_key_id: None,
        }
    }

    #[tokio::test]
    async fn enforces_scopes_and_roles() {
        let provider = IdentityAuthorizationProvider;
        let id = identity(&["read"], &["admin"]);
        let headers = HeaderMap::new();
        let method = Method::GET;
        let metadata = HashMap::new();
        let req = AuthorizationRequest {
            identity: Some(&id),
            method: &method,
            path: "/api/orders",
            headers: &headers,
            route_id: "orders",
            route_metadata: &metadata,
        };
        let ok = RouteAuthorizationConfig {
            scopes: vec!["read".into()],
            roles: vec!["admin".into()],
            ..Default::default()
        };
        provider.authorize(&req, &ok).await.unwrap();

        let bad = RouteAuthorizationConfig {
            scopes: vec!["write".into()],
            ..Default::default()
        };
        assert!(matches!(
            provider.authorize(&req, &bad).await,
            Err(GatewayError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn requires_identity_when_policy_present() {
        let provider = IdentityAuthorizationProvider;
        let headers = HeaderMap::new();
        let method = Method::GET;
        let metadata = HashMap::new();
        let req = AuthorizationRequest {
            identity: None,
            method: &method,
            path: "/",
            headers: &headers,
            route_id: "r",
            route_metadata: &metadata,
        };
        let policy = RouteAuthorizationConfig {
            scopes: vec!["read".into()],
            ..Default::default()
        };
        assert!(matches!(
            provider.authorize(&req, &policy).await,
            Err(GatewayError::Unauthorized(_))
        ));
    }

    #[test]
    fn identity_headers_are_replaced() {
        let config = IdentityHeadersConfig::default();
        let mut headers = HeaderMap::new();
        headers.insert("x-user-id", "attacker".parse().unwrap());
        sanitize_identity_headers(&mut headers, &config);
        assert!(!headers.contains_key("x-user-id"));
        inject_identity_headers(&mut headers, &config, &identity(&["read"], &["admin"]));
        assert_eq!(headers.get("x-user-id").unwrap(), "user-1");
    }
}
