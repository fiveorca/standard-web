//! 服务发现抽象与实现。
//!
//! 支持两种实现：
//! - [`StaticDiscovery`]：来自配置文件的静态实例列表；
//! - [`ConsulDiscovery`]：通过 Consul HTTP API 查询健康实例。
//!
//! 服务发现与具体代理实现解耦，`lb://service-name` 最终由上游注册表
//! 解析为具体的 HTTP 目标地址。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use dashmap::DashMap;
use serde::Deserialize;

use crate::config::model::{ConsulConfig, InstanceConfig};

/// 服务实例。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceInstance {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub secure: bool,
    pub weight: u32,
    pub metadata: HashMap<String, String>,
}

impl ServiceInstance {
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// 服务发现错误。
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("service `{0}` not found")]
    NotFound(String),
    #[error("service discovery unavailable: {0}")]
    Unavailable(String),
    #[error("invalid discovery response: {0}")]
    InvalidResponse(String),
}

/// 服务发现接口。
#[async_trait]
pub trait ServiceDiscovery: Send + Sync {
    fn name(&self) -> &'static str;
    /// 查询某个服务的健康实例。
    async fn discover(&self, service: &str) -> Result<Vec<ServiceInstance>, DiscoveryError>;
}

// ---------------------------------------------------------------------------
// 静态服务发现
// ---------------------------------------------------------------------------

/// 静态服务发现：实例来自配置文件。
#[derive(Debug, Default)]
pub struct StaticDiscovery {
    services: HashMap<String, Vec<ServiceInstance>>,
}

impl StaticDiscovery {
    pub fn new(services: HashMap<String, Vec<InstanceConfig>>) -> Result<Self, String> {
        let mut map = HashMap::new();
        for (name, instances) in services {
            let mut list = Vec::with_capacity(instances.len());
            for (idx, instance) in instances.into_iter().enumerate() {
                let parsed = url::Url::parse(&instance.uri)
                    .map_err(|e| format!("invalid instance uri `{}`: {e}", instance.uri))?;
                let scheme = parsed.scheme();
                if scheme != "http" && scheme != "https" {
                    return Err(format!(
                        "instance uri `{}` must use http or https",
                        instance.uri
                    ));
                }
                let host = parsed
                    .host_str()
                    .ok_or_else(|| format!("instance uri `{}` has no host", instance.uri))?;
                let port = parsed.port_or_known_default().unwrap_or(80);
                list.push(ServiceInstance {
                    id: instance
                        .id
                        .clone()
                        .unwrap_or_else(|| format!("{name}-{idx}")),
                    host: host.to_string(),
                    port,
                    secure: scheme == "https",
                    weight: instance.weight.max(1),
                    metadata: instance.metadata.clone(),
                });
            }
            map.insert(name, list);
        }
        Ok(Self { services: map })
    }

    pub fn services(&self) -> Vec<String> {
        self.services.keys().cloned().collect()
    }
}

#[async_trait]
impl ServiceDiscovery for StaticDiscovery {
    fn name(&self) -> &'static str {
        "static"
    }

    async fn discover(&self, service: &str) -> Result<Vec<ServiceInstance>, DiscoveryError> {
        self.services
            .get(service)
            .cloned()
            .ok_or_else(|| DiscoveryError::NotFound(service.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Consul 服务发现
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ConsulHealthEntry {
    #[serde(default)]
    node: ConsulNode,
    #[serde(default)]
    service: ConsulService,
    #[serde(default)]
    checks: Vec<ConsulCheck>,
}

#[derive(Debug, Default, Deserialize)]
struct ConsulNode {
    #[serde(default)]
    address: String,
}

#[derive(Debug, Default, Deserialize)]
struct ConsulService {
    #[serde(default)]
    id: String,
    #[serde(default)]
    service: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    meta: HashMap<String, String>,
    #[serde(default)]
    weights: ConsulWeights,
}

#[derive(Debug, Default, Deserialize)]
struct ConsulWeights {
    #[serde(default)]
    passing: u32,
}

#[derive(Debug, Deserialize)]
struct ConsulCheck {
    #[serde(default)]
    status: String,
}

/// Consul 服务发现。
pub struct ConsulDiscovery {
    config: ConsulConfig,
    client: reqwest::Client,
    cache: DashMap<String, CachedInstances>,
    cache_ttl: Duration,
}

struct CachedInstances {
    at: Instant,
    instances: Arc<Vec<ServiceInstance>>,
}

impl ConsulDiscovery {
    pub fn new(config: ConsulConfig) -> Result<Self, String> {
        let token = config.token.clone().or_else(|| {
            config
                .token_env
                .as_ref()
                .and_then(|name| std::env::var(name).ok())
        });
        if let Some(token) = &token {
            if token.trim().is_empty() {
                return Err("consul token is empty".to_string());
            }
        }
        let client = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .connect_timeout(config.request_timeout)
            .pool_max_idle_per_host(4)
            .build()
            .map_err(|e| format!("failed to build consul http client: {e}"))?;
        Ok(Self {
            config,
            client,
            cache: DashMap::new(),
            cache_ttl: Duration::from_secs(2),
        })
    }

    fn token(&self) -> Option<String> {
        self.config.token.clone().or_else(|| {
            self.config
                .token_env
                .as_ref()
                .and_then(|name| std::env::var(name).ok())
        })
    }

    /// 直接查询 Consul（不走缓存）。
    async fn fetch(&self, service: &str) -> Result<Vec<ServiceInstance>, DiscoveryError> {
        let base = self.config.address.trim_end_matches('/');
        let mut url = format!("{base}/v1/health/service/{service}");
        let mut query: Vec<String> = Vec::new();
        if self.config.passing_only {
            query.push("passing=true".to_string());
        }
        if let Some(tag) = &self.config.tag {
            query.push(format!("tag={tag}"));
        }
        if let Some(dc) = &self.config.datacenter {
            query.push(format!("dc={dc}"));
        }
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }

        let mut request = self.client.get(&url);
        if let Some(token) = self.token() {
            request = request.header("X-Consul-Token", token);
        }
        let response = request
            .send()
            .await
            .map_err(|e| DiscoveryError::Unavailable(format!("consul request failed: {e}")))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(DiscoveryError::NotFound(service.to_string()));
        }
        if !response.status().is_success() {
            return Err(DiscoveryError::Unavailable(format!(
                "consul returned status {}",
                response.status()
            )));
        }

        let entries: Vec<ConsulHealthEntry> = response
            .json()
            .await
            .map_err(|e| DiscoveryError::InvalidResponse(e.to_string()))?;

        let mut instances = Vec::with_capacity(entries.len());
        for entry in entries {
            if self.config.passing_only
                && entry
                    .checks
                    .iter()
                    .any(|c| !c.status.eq_ignore_ascii_case("passing"))
            {
                continue;
            }
            let host = if !entry.service.address.is_empty() {
                entry.service.address.clone()
            } else {
                entry.node.address.clone()
            };
            if host.is_empty() || entry.service.port == 0 {
                continue;
            }
            let mut metadata = entry.service.meta;
            metadata.insert("consul_service".to_string(), entry.service.service.clone());
            instances.push(ServiceInstance {
                id: if entry.service.id.is_empty() {
                    format!("{}-{}", host, entry.service.port)
                } else {
                    entry.service.id
                },
                host,
                port: entry.service.port,
                secure: false,
                weight: entry.service.weights.passing.max(1),
                metadata,
            });
        }

        if instances.is_empty() {
            return Err(DiscoveryError::NotFound(service.to_string()));
        }
        Ok(instances)
    }
}

#[async_trait]
impl ServiceDiscovery for ConsulDiscovery {
    fn name(&self) -> &'static str {
        "consul"
    }

    async fn discover(&self, service: &str) -> Result<Vec<ServiceInstance>, DiscoveryError> {
        let key = self
            .config
            .service_prefix
            .as_ref()
            .map(|prefix| format!("{prefix}{service}"))
            .unwrap_or_else(|| service.to_string());

        if let Some(entry) = self.cache.get(&key) {
            if entry.at.elapsed() < self.cache_ttl {
                return Ok(entry.instances.as_ref().clone());
            }
        }

        let instances = self.fetch(&key).await?;
        self.cache.insert(
            key,
            CachedInstances {
                at: Instant::now(),
                instances: Arc::new(instances.clone()),
            },
        );
        Ok(instances)
    }
}

/// 服务发现提供者集合。
pub struct DiscoveryProviders {
    pub static_discovery: Arc<StaticDiscovery>,
    pub consul: Option<Arc<ConsulDiscovery>>,
}

impl DiscoveryProviders {
    pub fn provider(&self, kind: &str) -> Option<Arc<dyn ServiceDiscovery>> {
        match kind {
            "static" => Some(self.static_discovery.clone()),
            "consul" => self.consul.clone().map(|c| c as Arc<dyn ServiceDiscovery>),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_discovery_resolves_instances() {
        let mut services = HashMap::new();
        services.insert(
            "user".to_string(),
            vec![InstanceConfig {
                id: Some("u1".into()),
                uri: "http://127.0.0.1:8081".into(),
                weight: 2,
                metadata: HashMap::new(),
            }],
        );
        let discovery = StaticDiscovery::new(services).unwrap();
        let instances = discovery.discover("user").await.unwrap();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].authority(), "127.0.0.1:8081");
        assert_eq!(instances[0].weight, 2);
        assert!(discovery.discover("missing").await.is_err());
    }
}
