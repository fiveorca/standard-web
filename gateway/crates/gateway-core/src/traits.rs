//! 运行时 Trait 定义。
//!
//! Trait 是 Gateway 模块解耦的关键——每个功能模块都通过 Trait 暴露自己，
//! 上游只依赖 Trait 而不依赖具体实现。这样：
//!   - 实现可以替换（Static ↔ DNS ↔ Consul）
//!   - 测试可以用 Mock 实现
//!   - 不需要把所有模块硬写进一个 Cargo crate
//!
//! # 为什么用 async_trait
//!
//! Rust 1.75 之前 async fn in trait 不稳定。
//! 截至 2026 年（Rust 1.99）虽然已经稳定，但 `async_trait` 依然是最
//! 安全的兼容方案，且其宏生成的 `BoxFuture` 类型擦除开销在这种
//! IO-bound 场景下完全可以忽略。

use async_trait::async_trait;

use crate::models::EndpointConfig;
use crate::types::{DiscoveryHealth, HealthStatus, LoadBalanceAlgorithm};
use crate::{Endpoint, Upstream};

// ---------------------------------------------------------------------------
// ServiceDiscoveryProvider —— 服务发现
// ---------------------------------------------------------------------------

/// 服务发现 Provider Trait。
///
/// 不同部署场景下，端点来源不同：
///   - 本地开发：StaticProvider（从 YAML 读取）
///   - DNS：DnsProvider（定期解析 SRV 记录）
///   - K8s：K8sProvider（监听 EndpointSlice）
///   - Consul/Nacos：后续 P2 扩展
///
/// 所有 Provider 统一实现本 Trait，Route Engine / LoadBalancer 只依赖 Trait。
#[async_trait]
pub trait ServiceDiscoveryProvider: Send + Sync {
    /// 根据上游 ID 解析出当前所有端点。
    ///
    /// 参数：
    /// - `upstream_id`：需要解析的上游 ID（YAML 中 `upstreams[].id` 字段）
    ///
    /// 返回：
    /// - `Ok(Vec<EndpointConfig>)`：最新的端点列表（可能为空）
    /// - `Err(DiscoveryError)`：Provider 内部失败
    async fn resolve(&self, upstream_id: &str) -> Result<Vec<EndpointConfig>, DiscoveryError>;

    /// 返回 Provider 自身的健康状态。
    ///
    /// 监控和运维可以根据这个状态决定降级策略。
    async fn health(&self) -> DiscoveryHealth;
}

/// 服务发现错误。
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    /// Provider 内部错误（例如网络超时、解析失败）
    #[error("discovery provider error: {0}")]
    Provider(String),
    /// 给定的 upstream_id 在 Provider 中不存在
    #[error("upstream not found: {0}")]
    UpstreamNotFound(String),
}

// ---------------------------------------------------------------------------
// LoadBalancer —— 负载均衡器
// ---------------------------------------------------------------------------

/// 负载均衡器 Trait。
///
/// 每个 Upstream 有一个 LoadBalancer 实例。实现只负责：
/// "给定一堆健康端点，根据算法选一个出来"。
///
/// 设计约束：
///   - 只接受 HEALTHY 的端点（调用方负责过滤）
///   - 并发安全（内部状态用 Arc<Mutex> 或 atomic 保护）
///   - 端点集合为空时返回 None
pub trait LoadBalancer: Send + Sync {
    /// 从健康端点中选择一个返回引用。
    ///
    /// 参数：
    /// - `healthy`：调用方过滤好的健康端点引用列表
    ///
    /// 返回：
    /// - `Some(&Endpoint)`：选中的端点
    /// - `None`：输入列表为空
    fn select<'a>(&self, healthy: &'a [&'a Endpoint]) -> Option<&'a Endpoint>;

    /// 带会话键的选择（IP Hash / 一致性哈希 / 区域感知使用）。
    ///
    /// 默认实现忽略 `key`，退化为 [`LoadBalancer::select`]，保证已有
    /// 算法无需改动即可继续工作。
    fn select_with_key<'a>(
        &self,
        healthy: &'a [&'a Endpoint],
        key: Option<&str>,
    ) -> Option<&'a Endpoint> {
        let _ = key;
        self.select(healthy)
    }

    /// 请求开始占用某个端点时回调（Least Connections 统计在途请求数）。
    ///
    /// 默认空实现；只有需要连接计数的算法覆盖它。
    fn on_connection_start(&self, _endpoint_id: &str) {}

    /// 请求结束释放某个端点时回调。
    fn on_connection_end(&self, _endpoint_id: &str) {}

    /// 返回本负载均衡器的算法类型（调试/日志用）
    fn algorithm(&self) -> LoadBalanceAlgorithm;
}

// ---------------------------------------------------------------------------
// UpstreamManager —— 上游状态管理（负载均衡 + 健康状态更新）
// ---------------------------------------------------------------------------

/// 运行时上游管理器 Trait。
///
/// Phase 1 中 UpstreamRegistry 实现本 Trait。
/// 负责：维护 Upstream 集合、负载均衡、健康状态标记。
#[async_trait]
pub trait UpstreamManager: Send + Sync {
    /// 根据 upstream_id 选一个健康端点。
    /// 内部会自己维护负载均衡状态。
    async fn pick_endpoint(&self, upstream_id: &str) -> Result<Endpoint, UpstreamError>;

    /// 带会话键选择端点（IP Hash / 一致性哈希 / 区域感知使用）。
    ///
    /// 默认实现忽略 key，退化为 [`UpstreamManager::pick_endpoint`]。
    async fn pick_endpoint_with_key(
        &self,
        upstream_id: &str,
        key: Option<&str>,
    ) -> Result<Endpoint, UpstreamError> {
        let _ = key;
        self.pick_endpoint(upstream_id).await
    }

    /// 请求开始占用端点（Least Connections 计数）。
    fn on_connection_start(&self, upstream_id: &str, endpoint_id: &str) {
        let _ = (upstream_id, endpoint_id);
    }

    /// 请求结束释放端点。
    fn on_connection_end(&self, upstream_id: &str, endpoint_id: &str) {
        let _ = (upstream_id, endpoint_id);
    }

    /// 更新某个端点的健康状态。
    /// 由健康检查或上游请求失败回调触发。
    async fn update_health(&self, upstream_id: &str, endpoint_id: &str, status: HealthStatus);

    /// 取得某个上游的快照（调试/管理 API 用）。
    fn get_upstream(&self, upstream_id: &str) -> Option<Upstream>;
}

/// 上游错误。
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("upstream not found: {0}")]
    NotFound(String),
    #[error("no healthy endpoints for upstream {0}")]
    NoHealthyEndpoints(String),
}
