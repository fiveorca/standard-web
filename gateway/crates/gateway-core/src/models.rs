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

use crate::types::{
    DiscoveryProviderKind, HealthStatus, LifecycleStatus, LoadBalanceAlgorithm, PathType,
};

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
    /// 所属租户（Phase 7 Multi-Tenant）。
    ///
    /// `None` 表示平台级公共路由；配置后控制面按租户隔离，
    /// 数据面对请求租户的校验由认证插件写入 RequestContext 完成。
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// API 生命周期状态（Phase 7）。
    ///
    /// 默认 `published`，保证既有配置行为不变。
    #[serde(default)]
    pub lifecycle: LifecycleStatus,
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
    /// WAF 策略引用（Phase 7）
    #[serde(default)]
    pub waf_policy_id: Option<String>,
    /// 配额策略引用（Phase 7）
    #[serde(default)]
    pub quota_policy_id: Option<String>,

    // ---- 请求/响应转换（Phase 2+）---- //
    #[serde(default)]
    pub path_rewrite: Option<String>,

    // ---- Phase 6：灰度发布 / 流量镜像 ---- //
    /// 灰度 / 蓝绿 / 加权路由：按权重把流量分发到多个 Service。
    ///
    /// 未配置时全部走 `service_id`；配置后 `service_id` 作为兜底目标，
    /// targets 的权重决定实际分流比例（Canary 常用 90/10，
    /// Blue-Green 通过把权重切换到 0/100 完成整体切换）。
    #[serde(default)]
    pub traffic_split: Option<TrafficSplitConfig>,
    /// 流量镜像：把按比例抽取的请求副本异步发送到影子 Service。
    ///
    /// 镜像请求不参与客户端响应，失败只记录日志，不影响主链路。
    #[serde(default)]
    pub mirror: Option<MirrorConfig>,
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
// TrafficSplitConfig —— 灰度 / 蓝绿 / 加权路由（Phase 6）
// ---------------------------------------------------------------------------

/// 流量拆分配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficSplitConfig {
    /// 目标列表，按 weight 占比分流
    #[serde(default)]
    pub targets: Vec<TrafficTarget>,
}

/// 单个分流目标。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficTarget {
    /// 目标 Service ID（必须存在于 services 列表）
    pub service_id: String,
    /// 权重，默认 1
    #[serde(default = "default_weight")]
    pub weight: u32,
}

// ---------------------------------------------------------------------------
// MirrorConfig —— 流量镜像（Phase 6）
// ---------------------------------------------------------------------------

/// 流量镜像配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorConfig {
    /// 影子 Service ID
    pub service_id: String,
    /// 镜像比例（0-100），默认 100
    #[serde(default = "default_mirror_percentage")]
    pub percentage: u8,
}

fn default_mirror_percentage() -> u8 {
    100
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
    /// 所属租户（Phase 7）
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// API 生命周期状态（Phase 7）
    #[serde(default)]
    pub lifecycle: LifecycleStatus,
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
    /// 所在地域（Region，Phase 7 多地域配置）
    ///
    /// 与 zone 的区别：region 是更大范围的容器（如 cn-east-1、cn-north-1），
    /// 用于跨地域流量调度；zone 用于同地域内的机房感知。
    #[serde(default)]
    pub region: Option<String>,
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
    /// 所属租户（Phase 7）
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// 所属集群（Phase 7 多集群配置）
    ///
    /// 同一上游可部署在多个集群；控制面按 cluster_id 下发子集，
    /// 数据面只加载属于自身集群的上游。
    #[serde(default)]
    pub cluster_id: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub algorithm: LoadBalanceAlgorithm,
    /// Static Provider 的端点列表
    #[serde(default)]
    pub endpoints: Vec<EndpointConfig>,
    /// 动态服务发现配置（Phase 6）。
    ///
    /// 未配置时按 Static 语义使用 `endpoints`；配置后由数据面后台任务
    /// 定期刷新端点，并把结果写回运行时上游注册表。
    #[serde(default)]
    pub discovery: Option<DiscoveryConfig>,
    /// 健康检查配置。未配置时不做主动探测，端点保持乐观可用语义。
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

// ---------------------------------------------------------------------------
// HealthCheckConfig —— 主动 / 被动健康检查配置
// ---------------------------------------------------------------------------

/// 主动健康检查方式。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckKind {
    /// HTTP GET：要求状态码在期望范围内
    #[default]
    Http,
    /// 仅建立 TCP 连接，不发送请求
    Tcp,
}

impl std::fmt::Display for HealthCheckKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HealthCheckKind::Http => f.write_str("http"),
            HealthCheckKind::Tcp => f.write_str("tcp"),
        }
    }
}

/// 主动 / 被动健康检查配置。
///
/// # 状态迁移规则
///
/// - 连续 `unhealthy_threshold` 次探测失败 → `UNHEALTHY`（摘流）
/// - 连续 `healthy_threshold` 次探测成功 → `HEALTHY`（恢复）
///
/// 被动检查（请求失败 / 5xx）使用 `passive` 中的独立阈值，
/// 与主动探测互不干扰，两者都可能改变端点状态。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    /// 是否启用主动健康检查
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 探测方式
    #[serde(default)]
    pub kind: HealthCheckKind,
    /// HTTP 探测路径（`kind = http` 时生效），默认 `/`
    #[serde(default = "default_health_path")]
    pub path: String,
    /// 探测间隔（秒），默认 10
    #[serde(default = "default_health_interval_secs")]
    pub interval_secs: u64,
    /// 单次探测超时（秒），默认 3
    #[serde(default = "default_health_timeout_secs")]
    pub timeout_secs: u64,
    /// 连续失败多少次判定为不健康，默认 3
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    /// 连续成功多少次判定为恢复，默认 2
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    /// 期望状态码表达式；为空时接受 `200-399`。
    ///
    /// 支持两种形式（YAML 里都是字符串）：
    /// - 单值：`"200"`
    /// - 闭区间：`"200-299"`
    #[serde(default)]
    pub expected_status: Option<String>,
    /// 被动健康检查配置
    #[serde(default)]
    pub passive: PassiveHealthConfig,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            kind: HealthCheckKind::Http,
            path: default_health_path(),
            interval_secs: default_health_interval_secs(),
            timeout_secs: default_health_timeout_secs(),
            unhealthy_threshold: default_unhealthy_threshold(),
            healthy_threshold: default_healthy_threshold(),
            expected_status: None,
            passive: PassiveHealthConfig::default(),
        }
    }
}

/// 被动健康检查配置。
///
/// 由真实请求结果驱动，无需额外探测流量：
/// - 连接失败 / 超时 / 5xx 计为失败
/// - 成功响应计为成功
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassiveHealthConfig {
    /// 是否启用被动检查
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 连续失败多少次摘流，默认 5
    #[serde(default = "default_passive_failure_threshold")]
    pub failure_threshold: u32,
    /// 连续成功多少次恢复，默认 3
    #[serde(default = "default_passive_recovery_threshold")]
    pub recovery_threshold: u32,
}

impl Default for PassiveHealthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            failure_threshold: default_passive_failure_threshold(),
            recovery_threshold: default_passive_recovery_threshold(),
        }
    }
}

/// 解析期望状态码表达式为闭区间 `(min, max)`。
///
/// 支持的输入：
/// - `"200"` → `(200, 200)`
/// - `"200-299"` → `(200, 299)`
///
/// 返回 `Err` 表示表达式非法（非数字、范围颠倒、超出 HTTP 状态码范围）。
pub fn parse_expected_status(expr: &str) -> Result<(u16, u16), String> {
    let trimmed = expr.trim();
    if trimmed.is_empty() {
        return Err("empty status expression".to_string());
    }

    let parse_code = |s: &str| -> Result<u16, String> {
        let code: u16 = s.trim().parse().map_err(|_| format!("invalid status code '{s}'"))?;
        if !(100..=599).contains(&code) {
            return Err(format!("status code {code} out of range 100-599"));
        }
        Ok(code)
    };

    match trimmed.split_once('-') {
        Some((low, high)) => {
            let low = parse_code(low)?;
            let high = parse_code(high)?;
            if low > high {
                return Err(format!("status range {low}-{high} is inverted"));
            }
            Ok((low, high))
        },
        None => {
            let code = parse_code(trimmed)?;
            Ok((code, code))
        },
    }
}

/// 判断状态码是否被期望表达式接受。`None` 表达式接受 200–399。
pub fn status_matches(expr: Option<&str>, status: u16) -> bool {
    match expr {
        Some(raw) => match parse_expected_status(raw) {
            Ok((low, high)) => (low..=high).contains(&status),
            Err(_) => false,
        },
        None => (200..400).contains(&status),
    }
}

fn default_health_path() -> String {
    "/".to_string()
}

fn default_health_interval_secs() -> u64 {
    10
}

fn default_health_timeout_secs() -> u64 {
    3
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_healthy_threshold() -> u32 {
    2
}

fn default_passive_failure_threshold() -> u32 {
    5
}

fn default_passive_recovery_threshold() -> u32 {
    3
}

// ---------------------------------------------------------------------------
// DiscoveryConfig —— 动态服务发现配置（Phase 6）
// ---------------------------------------------------------------------------

/// 上游动态服务发现配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    /// Provider 类型（dns / kubernetes）
    #[serde(default)]
    pub provider: DiscoveryProviderKind,
    /// DNS 查询域名（provider=dns 时必填）
    #[serde(default)]
    pub domain: Option<String>,
    /// DNS 查询类型：a / srv（默认 a）
    #[serde(default)]
    pub dns_record: DnsRecordKind,
    /// DNS 解析服务器，例如 `127.0.0.1:53`；为空时回退到 127.0.0.1:53
    #[serde(default)]
    pub dns_resolver: Option<String>,
    /// Kubernetes 命名空间（provider=kubernetes 时必填）
    #[serde(default)]
    pub namespace: Option<String>,
    /// Kubernetes Service 名称（provider=kubernetes 时必填）
    #[serde(default)]
    pub service: Option<String>,
    /// Kubernetes 端口名过滤
    #[serde(default)]
    pub port_name: Option<String>,
    /// Kubernetes API Server 地址；为空时从 KUBERNETES_SERVICE_HOST 推导
    #[serde(default)]
    pub api_server: Option<String>,
    /// ServiceAccount Token 文件路径（默认集群内标准路径）
    #[serde(default)]
    pub token_file: Option<String>,
    /// CA 证书文件路径（默认集群内标准路径）
    #[serde(default)]
    pub ca_file: Option<String>,
    /// 刷新间隔（秒），默认 15
    #[serde(default = "default_refresh_interval_secs")]
    pub refresh_interval_secs: u64,
}

/// DNS 记录类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordKind {
    /// A / AAAA 主机记录（使用 upstream 的默认端口）
    #[default]
    A,
    /// SRV 服务记录（端口由记录携带）
    Srv,
}

fn default_refresh_interval_secs() -> u64 {
    15
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_status_code() {
        assert_eq!(parse_expected_status("200"), Ok((200, 200)));
        assert_eq!(parse_expected_status(" 204 "), Ok((204, 204)));
    }

    #[test]
    fn parses_status_range() {
        assert_eq!(parse_expected_status("200-299"), Ok((200, 299)));
        assert_eq!(parse_expected_status("500 - 599"), Ok((500, 599)));
    }

    #[test]
    fn rejects_invalid_expressions() {
        assert!(parse_expected_status("").is_err());
        assert!(parse_expected_status("abc").is_err());
        assert!(parse_expected_status("99").is_err());
        assert!(parse_expected_status("600").is_err());
        assert!(parse_expected_status("300-200").is_err());
        assert!(parse_expected_status("200-x").is_err());
    }

    #[test]
    fn status_matches_rules() {
        // 无表达式：200–399
        assert!(status_matches(None, 200));
        assert!(status_matches(None, 301));
        assert!(!status_matches(None, 404));
        // 单值
        assert!(status_matches(Some("200"), 200));
        assert!(!status_matches(Some("200"), 201));
        // 范围
        assert!(status_matches(Some("200-299"), 250));
        assert!(!status_matches(Some("200-299"), 300));
        // 非法表达式一律视为不匹配
        assert!(!status_matches(Some("bad"), 200));
    }
}
