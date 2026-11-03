//! UpstreamRegistry —— 上游运行时状态管理。
//!
//! 职责：
//!   1. 根据启动时加载的 `UpstreamConfig` 构建运行时 `Upstream` 集合
//!   2. 为每个 Upstream 创建一个 LoadBalancer 实例（由其 algorithm 决定类型）
//!   3. 提供 `pick_endpoint(upstream_id)` —— 选一个健康端点
//!   4. 提供 `update_health(upstream_id, endpoint_id, status)` —— 由健康检查/
//!      上游请求失败回调更新端点状态
//!
//! # 并发安全
//!
//! 内部所有可变状态都用 `tokio::sync::RwLock` 保护：
//!   - 读路径（pick_endpoint）可以并发
//!   - 写路径（update_health）独占
//!
//! 但 LoadBalancer 自身是无锁的（AtomicU64），所以选端点时不会
//! 在 LoadBalancer 内部再等待锁。

use std::collections::HashMap;

use async_trait::async_trait;
use tokio::sync::RwLock;

use gateway_core::{
    Endpoint, HealthStatus, LoadBalancer, Upstream, UpstreamConfig, UpstreamError, UpstreamManager,
};

use crate::balancer::make_balancer;

// ---------------------------------------------------------------------------
// UpstreamEntry —— 单个上游的运行时状态
// ---------------------------------------------------------------------------

/// 单个 Upstream 的运行时状态。
///
/// - `upstream`：Upstream 配置 + 端点集合（健康端点会被动态更新）
/// - `balancer`：为这个 Upstream 创建的 LoadBalancer 实例
///
/// 两个字段都包在 `RwLock` 里，让读（选端点）可以并发，写（更新健康状态）独占。
struct UpstreamEntry {
    upstream: RwLock<Upstream>,
    balancer: Box<dyn LoadBalancer>,
}

// ---------------------------------------------------------------------------
// UpstreamRegistry —— 注册表主体
// ---------------------------------------------------------------------------

/// 所有 Upstream 的运行时注册表。
///
/// 在 Runtime 启动时构造一次；热更新（Phase 3+）时通过替换整个注册表
/// 或更新单个 Entry 来生效。
pub struct UpstreamRegistry {
    /// upstream_id → UpstreamEntry。Arc 包裹为了让注册表本身可以被
    /// 多个线程共享（Arc<UpstreamRegistry> 在 Service 闭包里 clone）。
    entries: HashMap<String, UpstreamEntry>,
}

impl UpstreamRegistry {
    /// 从一组 UpstreamConfig 构造注册表。
    ///
    /// 对每个 UpstreamConfig：
    ///   1. 把 EndpointConfig 转成 Endpoint（默认 HealthStatus::Unknown）
    ///   2. 用 Upstream::new() 构造 Upstream
    ///   3. 根据 algorithm 创建对应的 LoadBalancer
    ///   4. 存入 entries HashMap
    ///
    /// 参数：
    /// - `upstreams`：配置文件里的 UpstreamConfig 列表
    pub fn new(upstreams: &[UpstreamConfig]) -> Self {
        let mut entries: HashMap<String, UpstreamEntry> = HashMap::new();

        for cfg in upstreams {
            if !cfg.enabled {
                continue; // disabled 的 Upstream 不进入注册表
            }

            // 从 EndpointConfig 构造 Endpoint，分配 runtime_id
            let endpoints: Vec<Endpoint> = cfg
                .endpoints
                .iter()
                .enumerate()
                .map(|(i, ep_cfg)| {
                    let runtime_id =
                        ep_cfg.id.clone().unwrap_or_else(|| format!("{}-ep-{}", cfg.id, i));
                    Endpoint::new(runtime_id, ep_cfg.clone())
                })
                .collect();

            let upstream = Upstream::new(cfg.clone(), endpoints);

            // 根据算法创建对应的 LoadBalancer
            let balancer = make_balancer(cfg.algorithm);

            entries.insert(
                cfg.id.clone(),
                UpstreamEntry {
                    upstream: RwLock::new(upstream),
                    balancer,
                },
            );
        }

        Self { entries }
    }

    /// 返回当前注册的 Upstream 数量（调试/管理 API 用）
    pub fn upstream_count(&self) -> usize {
        self.entries.len()
    }
}

#[async_trait]
impl UpstreamManager for UpstreamRegistry {
    async fn pick_endpoint(&self, upstream_id: &str) -> Result<Endpoint, UpstreamError> {
        let entry = self
            .entries
            .get(upstream_id)
            .ok_or_else(|| UpstreamError::NotFound(upstream_id.to_string()))?;

        // 读锁：获取 Upstream 快照（含健康端点）
        let upstream = entry.upstream.read().await;
        let healthy_refs: Vec<&Endpoint> = upstream.healthy_endpoints();

        if healthy_refs.is_empty() {
            return Err(UpstreamError::NoHealthyEndpoints(upstream_id.to_string()));
        }

        // LoadBalancer.select 返回的是对 healthy_refs 中元素的引用。
        // 但 healthy_refs 的生命周期是这个函数调用内，而 LoadBalancer
        // 的输出需要返回给调用方。我们需要 clone 一个 Endpoint 返回。
        // 注意：Endpoint 是 Clone 的。
        match entry.balancer.select(&healthy_refs) {
            Some(ep) => Ok(ep.clone()),
            None => Err(UpstreamError::NoHealthyEndpoints(upstream_id.to_string())),
        }
    }

    async fn update_health(&self, upstream_id: &str, endpoint_id: &str, status: HealthStatus) {
        let Some(entry) = self.entries.get(upstream_id) else {
            return; // 上游不存在 → 忽略（可能已删除）
        };

        // 写锁：独占更新某个端点的健康状态
        let mut upstream = entry.upstream.write().await;
        if let Some(ep) = upstream.endpoints.iter_mut().find(|e| e.runtime_id == endpoint_id) {
            tracing::debug!(
                upstream = upstream_id,
                endpoint = endpoint_id,
                status = status.to_string(),
                "endpoint health status updated"
            );
            ep.status = status;
        } else {
            tracing::warn!(
                upstream = upstream_id,
                endpoint = endpoint_id,
                "endpoint not found for health update"
            );
        }
    }

    fn get_upstream(&self, upstream_id: &str) -> Option<Upstream> {
        // 这里同步获取需要读锁，但 UpstreamManager::get_upstream 不是 async
        // 所以我们用 try_read 或直接返回 None。Phase 1 中这个方法主要用于
        // 测试和调试，生产路径用 pick_endpoint 即可。
        //
        // 实际上 Upstream 没有 Arc<Mutex> 包装，所以 try_read 就够了：
        // 如果正在写，就跳过这次读取。
        match self.entries.get(upstream_id)?.upstream.try_read() {
            Ok(upstream) => Some(upstream.clone()),
            Err(_) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_core::EndpointConfig;

    fn mk_upstream(
        id: &str,
        algorithm: gateway_core::LoadBalanceAlgorithm,
        weights: &[u32],
    ) -> UpstreamConfig {
        UpstreamConfig {
            id: id.to_string(),
            name: None,
            enabled: true,
            algorithm,
            endpoints: weights
                .iter()
                .enumerate()
                .map(|(i, w)| EndpointConfig {
                    id: None,
                    host: "127.0.0.1".into(),
                    port: 9000 + i as u16,
                    weight: *w,
                    zone: None,
                })
                .collect(),
        }
    }

    #[tokio::test]
    async fn pick_returns_healthy_endpoint() {
        let registry = UpstreamRegistry::new(&[mk_upstream(
            "u1",
            gateway_core::LoadBalanceAlgorithm::RoundRobin,
            &[1, 1, 1],
        )]);

        // 前三个 Endpoint 初始都是 Unknown；乐观可用语义下 Unknown 也可被选，
        // 这里显式标记为 Healthy 走最典型的健康路径
        for i in 0..3 {
            registry.update_health("u1", &format!("u1-ep-{i}"), HealthStatus::Healthy).await;
        }

        let ep = registry.pick_endpoint("u1").await.unwrap();
        assert!(ep.is_available());
    }

    /// 乐观可用语义：初始 Unknown 的端点在健康检查接入前就可被选中
    #[tokio::test]
    async fn pick_unknown_endpoint_optimistically_available() {
        let registry = UpstreamRegistry::new(&[mk_upstream(
            "u1",
            gateway_core::LoadBalanceAlgorithm::RoundRobin,
            &[1],
        )]);
        // 不更新健康状态 → Unknown，但应能选中
        let ep = registry.pick_endpoint("u1").await.unwrap();
        assert_eq!(ep.status, HealthStatus::Unknown);
    }

    #[tokio::test]
    async fn pick_no_healthy_endpoints_returns_error() {
        let registry = UpstreamRegistry::new(&[mk_upstream(
            "u1",
            gateway_core::LoadBalanceAlgorithm::RoundRobin,
            &[1],
        )]);
        // 显式标记为 Unhealthy → 唯一端点不可用，pick 必须报错
        registry.update_health("u1", "u1-ep-0", HealthStatus::Unhealthy).await;
        let err = registry.pick_endpoint("u1").await.unwrap_err();
        assert!(matches!(err, UpstreamError::NoHealthyEndpoints(_)));
    }

    #[tokio::test]
    async fn pick_missing_upstream_returns_error() {
        let registry = UpstreamRegistry::new(&[]);
        let err = registry.pick_endpoint("nope").await.unwrap_err();
        assert!(matches!(err, UpstreamError::NotFound(_)));
    }

    #[tokio::test]
    async fn update_health_then_pick() {
        let registry = UpstreamRegistry::new(&[mk_upstream(
            "u1",
            gateway_core::LoadBalanceAlgorithm::RoundRobin,
            &[1, 1],
        )]);

        // 先把两个都设 Healthy，然后把 ep-0 设为 Unhealthy
        registry.update_health("u1", "u1-ep-0", HealthStatus::Healthy).await;
        registry.update_health("u1", "u1-ep-1", HealthStatus::Healthy).await;
        registry.update_health("u1", "u1-ep-0", HealthStatus::Unhealthy).await;

        // 重复 pick 100 次，应该始终选中 ep-1
        for _ in 0..100 {
            let ep = registry.pick_endpoint("u1").await.unwrap();
            assert_eq!(ep.runtime_id, "u1-ep-1");
        }
    }
}
