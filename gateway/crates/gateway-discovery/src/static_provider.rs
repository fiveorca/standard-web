//! StaticDiscoveryProvider —— 从 YAML 配置直接加载端点列表的静态 Provider。
//!
//! 这是 Phase 1 唯一的 Provider，适用于：
//!   - 本地开发
//!   - 单机部署
//!   - 测试环境
//!
//! # 设计约束
//!
//! - resolve() 是同步返回（端点在构造时就固定了，不会变化）
//! - health() 永远返回 Healthy（静态数据不会"不可达"）
//! - 运行时 Upstream 的健康状态不由本 Provider 管理，而由
//!   gateway-upstream 的 UpstreamRegistry 管理

use std::collections::HashMap;

use async_trait::async_trait;

use gateway_core::{
    DiscoveryError, DiscoveryHealth, EndpointConfig, ServiceDiscoveryProvider, UpstreamConfig,
};

/// 静态服务发现 Provider。
///
/// 构造时接收一组 `UpstreamConfig`，建立 `upstream_id → Vec<EndpointConfig>` 的映射表。
/// 运行时 `resolve()` 直接查表返回。
///
/// # 使用示例
///
/// ```rust,ignore
/// let provider = StaticDiscoveryProvider::new(&cfg.upstreams);
/// let endpoints = provider.resolve("upstream-1").await?;
/// ```
pub struct StaticDiscoveryProvider {
    /// upstream_id → EndpointConfig 列表。
    /// 构造时一次性建立，之后只读。
    endpoints_by_upstream: HashMap<String, Vec<EndpointConfig>>,
}

impl StaticDiscoveryProvider {
    /// 从一组 UpstreamConfig 构造。
    ///
    /// 只要 `UpstreamConfig.endpoints` 里写了端点，就会被收录。
    /// enabled=false 的 Upstream 也会收录（是否启用由 runtime 控制）。
    pub fn new(upstreams: &[UpstreamConfig]) -> Self {
        let mut map: HashMap<String, Vec<EndpointConfig>> = HashMap::new();
        for u in upstreams {
            map.insert(u.id.clone(), u.endpoints.clone());
        }
        Self {
            endpoints_by_upstream: map,
        }
    }

    /// 判断给定 upstream_id 是否存在。
    pub fn contains(&self, upstream_id: &str) -> bool {
        self.endpoints_by_upstream.contains_key(upstream_id)
    }
}

#[async_trait]
impl ServiceDiscoveryProvider for StaticDiscoveryProvider {
    async fn resolve(&self, upstream_id: &str) -> Result<Vec<EndpointConfig>, DiscoveryError> {
        match self.endpoints_by_upstream.get(upstream_id) {
            Some(list) => Ok(list.clone()),
            None => Err(DiscoveryError::UpstreamNotFound(upstream_id.to_string())),
        }
    }

    async fn health(&self) -> DiscoveryHealth {
        // 静态 Provider 不可能"不健康"——端点列表是构造时就固定好的。
        DiscoveryHealth::Healthy
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_core::EndpointConfig;

    fn make_upstream(id: &str, endpoints: Vec<EndpointConfig>) -> UpstreamConfig {
        UpstreamConfig {
            id: id.to_string(),
            name: None,
            enabled: true,
            algorithm: gateway_core::LoadBalanceAlgorithm::RoundRobin,
            endpoints,
        }
    }

    #[tokio::test]
    async fn resolve_existing() {
        let provider = StaticDiscoveryProvider::new(&[make_upstream(
            "u1",
            vec![EndpointConfig {
                id: None,
                host: "127.0.0.1".into(),
                port: 9090,
                weight: 1,
                zone: None,
            }],
        )]);

        let eps = provider.resolve("u1").await.unwrap();
        assert_eq!(eps.len(), 1);
        assert_eq!(eps[0].port, 9090);
    }

    #[tokio::test]
    async fn resolve_missing_returns_error() {
        let provider = StaticDiscoveryProvider::new(&[]);
        let err = provider.resolve("nope").await.unwrap_err();
        assert!(matches!(err, DiscoveryError::UpstreamNotFound(_)));
    }

    #[tokio::test]
    async fn health_is_always_healthy() {
        let provider = StaticDiscoveryProvider::new(&[]);
        assert_eq!(provider.health().await, DiscoveryHealth::Healthy);
    }
}
