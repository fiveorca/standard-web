//! 领域模型——配置模型（从 YAML 反序列化）和运行时模型（带健康状态的实际端点）。
//!
//! # 设计思路
//!
//! 配置模型（带 `Config` 后缀）是 YAML 的直接映射：
//!   - 每个配置字段都有明确的默认值或校验规则
//!   - 尽量用 `Option` 表示可选字段，反序列化时不会 panic
//!
//! 运行时模型（不带 `Config` 后缀）是在编译阶段由 Config 转换而来：
//!   - 包含运行时状态（如 `HealthStatus`）
//!   - 可能比 Config 多一些计算字段（如 `RequestContext.matched_route`）
//!
//! 这样配置校验和运行时状态更新是两个独立步骤，不会互相污染。
//!
//! # 为什么用 Arc
//!
//! 配置在启动时编译为不可变快照，运行时通过 `ArcSwap<RuntimeSnapshot>`
//! 原子交换。每个 Route 被多个并发请求引用，因此 Route/Service/Upstream
//! 用 `Arc<T>` 包一下，避免 Clone 大结构体。

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::types::{HealthStatus, LoadBalanceAlgorithm, PathType};

// ===========================================================================
// 配置模型（Config）
// ===========================================================================

// ---------------------------------------------------------------------------
// HeaderMatch / QueryMatch —— 路由匹配条件
// ---------------------------------------------------------------------------

/// Route 级别的 Header 匹配条件。
///
/// 例如：`{ name: "X-API-Version", exact: "v2" }` 表示请求头中有
/// `X-API-Version: v2` 才匹配。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderMatch {
    /// Header 名称（大小写不敏感，匹配时会统一转小写）
    pub name: String,
    /// 精确匹配值
    pub exact: String,
}

/// Route 级别的 Query 参数匹配条件。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryMatch {
    /// Query 参数名
    pub name: String,
    /// 精确匹配值
    pub exact: String,
}

// ---------------------------------------------------------------------------
// RouteConfig —— 路由配置（YAML 直接映射）
// ---------------------------------------------------------------------------

/// 路由配置。
///
/// 一个 Route 完整描述了：请求的匹配条件 + 匹配后的处理行为（转发到哪个 Service、
/// 用什么超时、什么鉴权策略等）。Phase 1 中鉴权/限流/重试等策略字段保留但暂不生效。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteConfig {
    /// 唯一标识，用于日志、审计、配置版本追踪
    pub id: String,
    /// 人类可读名称，例如 "user-api-v1"。可选，用于日志和管理界面展示
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用。禁用的 Route 在编译时被跳过
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 优先级。数字越大越优先。同一个 Host+Path+Method+Header+Query+Priority
    /// 组合出现多条 Route 时，配置编译必须报错（冲突检测）
    #[serde(default = "default_priority")]
    pub priority: i32,

    // ---- 匹配条件 ---- //
    /// 允许匹配的 Host 列表（请求头 Host 字段）。空数组表示不限制 Host
    #[serde(default)]
    pub hosts: Vec<String>,
    /// 允许匹配的 HTTP Method 列表。空数组表示不限制 Method
    #[serde(default)]
    pub methods: Vec<String>,
    /// 路径匹配方式
    #[serde(default = "default_path_type")]
    pub path_type: PathType,
    /// 路径匹配值。Exact 时必须完全相等，Prefix 时前缀相等即可
    pub path_value: String,
    /// Header 精确匹配条件。全部满足才算匹配成功
    #[serde(default)]
    pub header_matches: Vec<HeaderMatch>,
    /// Query 参数精确匹配条件
    #[serde(default)]
    pub query_matches: Vec<QueryMatch>,

    // ---- 处理行为 ---- //
    /// 转发到的 Service ID（必须能在 services 列表中找到）
    pub service_id: String,

    // ---- 策略引用（Phase 2 开始生效，Phase 1 仅保留字段）---- //
    /// 超时策略引用
    #[serde(default)]
    pub timeout_policy_id: Option<String>,
    /// 认证策略引用
    #[serde(default)]
    pub auth_policy_id: Option<String>,
    /// 限流策略引用
    #[serde(default)]
    pub rate_limit_policy_id: Option<String>,
    /// 重试策略引用
    #[serde(default)]
    pub retry_policy_id: Option<String>,
    /// 熔断策略引用（P2.1 新增）
    #[serde(default)]
    pub circuit_breaker_policy_id: Option<String>,
    /// CORS 策略引用（P2.1 新增）
    #[serde(default)]
    pub cors_policy_id: Option<String>,

    // ---- 请求/响应转换（Phase 2+）---- //
    #[serde(default)]
    pub path_rewrite: Option<String>,
    /// 请求 Header 转换策略引用（P2.1 新增）
    ///
    /// 转发前对请求头做 remove/set/add，策略定义在
    /// `policies.request_transform`
    #[serde(default)]
    pub request_transform_id: Option<String>,
    /// 响应 Header 转换策略引用（P2.1 新增）
    ///
    /// 返回客户端前对响应头做 remove/set/add，策略定义在
    /// `policies.response_transform`
    #[serde(default)]
    pub response_transform_id: Option<String>,
}

// 小工具：serde default 函数
fn default_enabled() -> bool {
    true
}
fn default_priority() -> i32 {
    100
}
fn default_path_type() -> PathType {
    PathType::Prefix
}

// ---------------------------------------------------------------------------
// ServiceConfig —— 后端服务配置
// ---------------------------------------------------------------------------

/// Service 表示一个逻辑后端服务（例如 user-service）。
/// 它本身不持有具体实例地址，而是关联一个 Upstream。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfig {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 关联的 Upstream ID
    pub upstream_id: String,
}

// ---------------------------------------------------------------------------
// EndpointConfig —— 静态端点配置
// ---------------------------------------------------------------------------

/// YAML 中定义的端点。
///
/// 用于 StaticDiscoveryProvider 场景；其他 Provider（DNS/K8s）会在运行时动态发现。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointConfig {
    #[serde(default)]
    pub id: Option<String>,
    pub host: String,
    pub port: u16,
    /// 权重。默认 1。LoadBalancer 根据权重决定被选中概率
    #[serde(default = "default_weight")]
    pub weight: u32,
    /// 所在可用区（Zone），用于区域感知负载均衡（P1）
    #[serde(default)]
    pub zone: Option<String>,
}

fn default_weight() -> u32 {
    1
}

// ---------------------------------------------------------------------------
// UpstreamConfig —— 上游配置（带端点列表和负载均衡算法）
// ---------------------------------------------------------------------------

/// Upstream 表示一组后端实例。
/// Phase 1 只实现 Static Discovery，所以 endpoints 是内联写在 Upstream 里的。
/// 后续阶段可以把 discovery_provider 改成 "dns" / "k8s" 等。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub algorithm: LoadBalanceAlgorithm,
    /// Static Provider 的端点列表
    #[serde(default)]
    pub endpoints: Vec<EndpointConfig>,
}

// ===========================================================================
// 运行时模型（非 Config 后缀，在编译阶段生成）
// ===========================================================================

// ---------------------------------------------------------------------------
// Endpoint —— 运行时端点（带健康状态）
// ---------------------------------------------------------------------------

/// 运行时端点。
///
/// 和 `EndpointConfig` 的区别：
///   - 增加了 `HealthStatus` 字段，负载均衡器只会从 HEALTHY 端点里挑选
///   - 有一个唯一的 runtime_id（配置中没写 id 时也会生成一个）
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// 运行时唯一 ID（即使配置中没写也会生成）
    pub runtime_id: String,
    pub host: String,
    pub port: u16,
    pub weight: u32,
    pub zone: Option<String>,
    pub status: HealthStatus,
}

impl Endpoint {
    pub fn new(runtime_id: impl Into<String>, cfg: EndpointConfig) -> Self {
        Self {
            runtime_id: runtime_id.into(),
            host: cfg.host,
            port: cfg.port,
            weight: cfg.weight,
            zone: cfg.zone,
            // 新端点默认为 Unknown，等待健康检查或首次请求后的判定
            status: HealthStatus::Unknown,
        }
    }

    /// 返回 `host:port` 格式的地址串，用于日志和上游连接。
    pub fn address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// 判断端点是否可接收新流量。
    /// 乐观可用语义：HEALTHY 和 UNKNOWN 返回 true（详见 HealthStatus::is_available）。
    pub fn is_available(&self) -> bool {
        self.status.is_available()
    }
}

// ---------------------------------------------------------------------------
// Upstream —— 运行时上游（带端点集合）
// ---------------------------------------------------------------------------

/// 运行时上游。
///
/// 包含完整的端点集合和负载均衡算法配置。
/// 负载均衡器在选择实例时，只会从 `endpoints` 中筛选"可用"的端点
/// （Healthy + Unknown 乐观可用，详见 HealthStatus::is_available）。
#[derive(Debug, Clone)]
pub struct Upstream {
    pub id: String,
    pub algorithm: LoadBalanceAlgorithm,
    pub endpoints: Vec<Endpoint>,
}

impl Upstream {
    pub fn new(cfg: UpstreamConfig, endpoints: Vec<Endpoint>) -> Self {
        Self {
            id: cfg.id,
            algorithm: cfg.algorithm,
            endpoints,
        }
    }

    /// 从运行时端点集合中过滤出健康的端点。
    /// 返回引用切片，调用方不能修改端点状态（状态更新由 UpstreamRegistry 协调）。
    pub fn healthy_endpoints(&self) -> Vec<&Endpoint> {
        self.endpoints.iter().filter(|ep| ep.is_available()).collect()
    }
}

// ===========================================================================
// RuntimeSnapshot —— 数据面启动后、配置加载完成后的运行时快照
// ===========================================================================

/// 数据面运行时不可变快照。
///
/// 启动时从 YAML 配置编译而来；后续热更新时通过 `ArcSwap<RuntimeSnapshot>`
/// 原子替换。所有请求处理线程引用同一个快照，读路径无锁。
///
/// 使用 `Arc<RouteConfig>` 等而不是直接嵌入，是因为：
///   - 路由表要同时被 RouteResolver 和 RequestContext 引用
///   - Arc 让引用计数自动管理，不需要手动 clone 大结构
#[derive(Debug, Clone)]
pub struct RuntimeSnapshot {
    /// 配置 schema 版本号，用于拒绝不识别的配置格式
    pub schema_version: String,
    /// 配置版本号，每次发布递增
    pub config_version: u64,
    /// 所有路由（以 id 为 key，方便通过 id 查找）
    pub routes_by_id: HashMap<String, Arc<RouteConfig>>,
    /// 所有服务（以 id 为 key）
    pub services_by_id: HashMap<String, Arc<ServiceConfig>>,
    /// 所有上游（以 id 为 key）
    pub upstreams_by_id: HashMap<String, Arc<Upstream>>,
}

impl RuntimeSnapshot {
    /// 创建空的运行时快照（用于测试或占位）。
    pub fn empty() -> Self {
        Self {
            schema_version: "v1".to_string(),
            config_version: 0,
            routes_by_id: HashMap::new(),
            services_by_id: HashMap::new(),
            upstreams_by_id: HashMap::new(),
        }
    }
}
