//! 领域枚举类型。
//!
//! 这些枚举在多个 crate 间共享：
//!   - 配置加载时反序列化使用
//!   - 路由匹配时根据 PathType 决定匹配策略
//!   - 负载均衡时根据 LoadBalanceAlgorithm 选择算法
//!   - 健康检查和运行时维护时根据 HealthStatus 判断端点是否可用

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PathType —— 路由匹配时的路径匹配方式
// ---------------------------------------------------------------------------

/// 路由路径匹配方式。
///
/// 需求文档 4.2 节规定 P0 只支持 Exact 和 Prefix；正则匹配作为 P1。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathType {
    /// 完全匹配。请求路径必须和配置值一字不差。
    /// 例如 route path="/api/users" 只匹配 GET /api/users，不匹配 /api/users/42。
    Exact,
    /// 前缀匹配。请求路径以配置值开头即可。
    /// 例如 route path="/api/users" 匹配 /api/users、/api/users/42、/api/users/list?page=1。
    Prefix,
}

impl fmt::Display for PathType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathType::Exact => f.write_str("exact"),
            PathType::Prefix => f.write_str("prefix"),
        }
    }
}

// ---------------------------------------------------------------------------
// LoadBalanceAlgorithm —— 负载均衡算法
// ---------------------------------------------------------------------------

/// 上游实例负载均衡算法。
///
/// 需求文档 4.3 节规定：
///   - P0：RoundRobin / WeightedRoundRobin / Random / WeightedRandom
///   - P1：LeastConnections / IPHash / ConsistentHash / ZoneAware
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceAlgorithm {
    /// 轮询，不考虑权重
    #[default]
    RoundRobin,
    /// 带权轮询，按权重比例选择
    WeightedRoundRobin,
    /// 随机
    Random,
    /// 带权随机
    WeightedRandom,
    /// 最少连接（P1）
    LeastConnections,
    /// IP Hash（P1）
    IpHash,
    /// 一致性哈希（P1）
    ConsistentHash,
    /// 区域感知（P1）
    ZoneAware,
}

impl fmt::Display for LoadBalanceAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Serialize 会用 snake_case，这里复用 Display 输出相同格式方便日志
        match self {
            LoadBalanceAlgorithm::RoundRobin => f.write_str("round_robin"),
            LoadBalanceAlgorithm::WeightedRoundRobin => f.write_str("weighted_round_robin"),
            LoadBalanceAlgorithm::Random => f.write_str("random"),
            LoadBalanceAlgorithm::WeightedRandom => f.write_str("weighted_random"),
            LoadBalanceAlgorithm::LeastConnections => f.write_str("least_connections"),
            LoadBalanceAlgorithm::IpHash => f.write_str("ip_hash"),
            LoadBalanceAlgorithm::ConsistentHash => f.write_str("consistent_hash"),
            LoadBalanceAlgorithm::ZoneAware => f.write_str("zone_aware"),
        }
    }
}

// ---------------------------------------------------------------------------
// DiscoveryProviderKind —— 服务发现提供者类型（Phase 6）
// ---------------------------------------------------------------------------

/// 服务发现提供者类型。
///
/// 与 `gateway-discovery` 中具体 Provider 一一对应；
/// `static` 表示端点直接写在 `upstreams[].endpoints` 中（默认）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryProviderKind {
    /// 静态端点（YAML 直接配置）
    #[default]
    Static,
    /// DNS：A/AAAA 或 SRV 记录
    Dns,
    /// Kubernetes EndpointSlice
    Kubernetes,
}

impl fmt::Display for DiscoveryProviderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryProviderKind::Static => f.write_str("static"),
            DiscoveryProviderKind::Dns => f.write_str("dns"),
            DiscoveryProviderKind::Kubernetes => f.write_str("kubernetes"),
        }
    }
}

// ---------------------------------------------------------------------------
// LifecycleStatus —— API 生命周期（Phase 7）
// ---------------------------------------------------------------------------

/// API 生命周期状态。
///
/// 数据面编译规则：
/// - `Draft` / `Retired`：不进入路由表（对外不可见）
/// - `Published`：正常提供服务
/// - `Deprecated`：继续提供服务，但响应头带 `X-API-Deprecated: true`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleStatus {
    /// 草稿：仅控制面可见，不对外发布
    Draft,
    /// 已发布：正常提供服务（默认）
    #[default]
    Published,
    /// 已废弃：仍提供服务，但标记弃用（客户端应尽快迁移）
    Deprecated,
    /// 已下线：不进入路由表
    Retired,
}

impl LifecycleStatus {
    /// 是否允许数据面服务该资源。
    pub fn is_servable(self) -> bool {
        matches!(self, LifecycleStatus::Published | LifecycleStatus::Deprecated)
    }

    /// 是否属于「已发布（含废弃）」状态（门户目录展示用）。
    pub fn is_listed(self) -> bool {
        self.is_servable()
    }
}

impl fmt::Display for LifecycleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LifecycleStatus::Draft => f.write_str("draft"),
            LifecycleStatus::Published => f.write_str("published"),
            LifecycleStatus::Deprecated => f.write_str("deprecated"),
            LifecycleStatus::Retired => f.write_str("retired"),
        }
    }
}

// ---------------------------------------------------------------------------
// HealthStatus —— 端点运行时健康状态
// ---------------------------------------------------------------------------

/// 上游端点的运行时健康状态。
///
/// 需求文档 4.3 节规定的四种状态：
/// - HEALTHY：健康，可以接收流量
/// - UNHEALTHY：不健康，已经被剔除
/// - UNKNOWN：还没进行过健康检查，或者初始状态
/// - DRAINING：正在摘流（优雅关闭或灰度发布切换），不再接收新连接
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum HealthStatus {
    /// 健康，允许流量进入
    Healthy,
    /// 不健康，被健康检查标记或连接/5xx 统计触发
    Unhealthy,
    /// 未知，初始状态或健康检查暂时无结果
    #[default]
    Unknown,
    /// 摘流中，不再接收新连接（已有连接继续服务）
    Draining,
}

impl HealthStatus {
    /// 判断端点是否可接收新流量。
    ///
    /// # 乐观可用（optimistic availability）语义
    ///
    /// `Healthy` 和 `Unknown` 都返回 true：
    /// - `Healthy`：健康检查明确通过
    /// - `Unknown`：尚未做过健康检查的端点。网关在主动健康检查接入前
    ///   （Phase 2 健康检查模块之前）采用乐观策略——先放行，
    ///   由被动失败统计（连接错误 / 5xx 比例）把它降级为 Unhealthy。
    ///   若 Unknown 也不放行，则没有任何主动健康检查器的部署形态下
    ///   所有端点永远无法被选中，数据面完全不可用。
    ///
    /// `Unhealthy` / `Draining` 返回 false。
    pub fn is_available(self) -> bool {
        matches!(self, HealthStatus::Healthy | HealthStatus::Unknown)
    }
}

impl fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HealthStatus::Healthy => f.write_str("HEALTHY"),
            HealthStatus::Unhealthy => f.write_str("UNHEALTHY"),
            HealthStatus::Unknown => f.write_str("UNKNOWN"),
            HealthStatus::Draining => f.write_str("DRAINING"),
        }
    }
}

// ---------------------------------------------------------------------------
// DiscoveryHealth —— 服务发现提供者自身的健康状态
// ---------------------------------------------------------------------------

/// 服务发现 Provider 本身的健康状态。
///
/// 当 StaticDiscoveryProvider 时永远 Healthy；
/// 当 DNS/Remote 时需要考虑提供者是否可达。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryHealth {
    /// 提供者正常，能稳定返回端点列表
    #[default]
    Healthy,
    /// 提供者暂时不可用，但之前有缓存结果可以继续用
    Degraded,
    /// 提供者完全不可用，且没有可用缓存
    Unhealthy,
}
