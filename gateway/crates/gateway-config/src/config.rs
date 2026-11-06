//! GatewayConfig —— YAML 顶层结构定义。
//!
//! 所有字段都要显式带 serde 注解：
//!   - `#[serde(default)]`：未提供时使用 Rust 类型默认值
//!   - `#[serde(rename_all = "snake_case")]`：YAML 中的字段名风格
//!   - `#[serde(deny_unknown_fields)]`（嵌套层可选）：拒绝未知字段
//!
//! 注意：顶层结构不使用 deny_unknown_fields，而是在 loader 层
//! 手动收集未知字段。原因是 Figment 在 merge 后会把所有层的字段
//! 混在一起，deny_unknown_fields 会误报"环境变量里有这个字段但
//! YAML 里没写"。我们改用 validator 层手动检查。

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// GatewayConfig —— 顶层入口
// ---------------------------------------------------------------------------

/// Gateway 完整运行时配置。
///
/// 对应 YAML 文件的根节点。所有嵌套结构都在本文件中定义。
/// 字段分组：
///   - `gateway`：网关自身标识
///   - `server`：监听端口（业务 HTTP / 管理 Admin）
///   - `runtime`：运行时资源限制
///   - `observability`：日志/Metrics/Tracing 初始化参数
///   - `control_plane`：是否连接控制面（Phase 3 开始生效）
///   - `upstreams` / `services` / `routes`：核心业务配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub gateway: GatewayMeta,
    pub server: ServerConfig,
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub observability: ObservabilityConfig,
    #[serde(default)]
    pub control_plane: ControlPlaneConfig,

    #[serde(default)]
    pub upstreams: Vec<gateway_core::UpstreamConfig>,
    #[serde(default)]
    pub services: Vec<gateway_core::ServiceConfig>,
    #[serde(default)]
    pub routes: Vec<gateway_core::RouteConfig>,

    /// TLS 证书资源（YAML / 引导配置模式）。
    ///
    /// 与 `server.http.tls.certificate_id` 配合使用；控制面模式下
    /// 证书资源随配置快照下发，本地列表只作为启动引导与文件回退。
    #[serde(default)]
    pub certificates: Vec<gateway_core::CertificateConfig>,

    /// Phase 2 策略配置段（P2.1 新增）。
    ///
    /// 所有治理策略（鉴权/限流/超时/重试/熔断/CORS/Header 转换）集中
    /// 定义在这里，由 Route 通过 `*_policy_id` 按 ID 引用。
    /// 未配置时各子列表为空，等价于"全部策略关闭"，不影响 Phase 1 行为。
    #[serde(default)]
    pub policies: PoliciesConfig,
}

// ---------------------------------------------------------------------------
// GatewayMeta —— 网关自身标识
// ---------------------------------------------------------------------------

/// 网关元信息。
///
/// Phase 1 中主要用于日志和健康检查输出。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayMeta {
    /// 网关实例 ID，日志中会出现。默认 "gateway-default"
    #[serde(default = "default_gateway_id")]
    pub id: String,
    /// 实例名称，人类可读。默认 "gateway-instance"
    #[serde(default = "default_instance_name")]
    pub instance_name: String,
    /// 运行环境标识：development / staging / production
    #[serde(default = "default_environment")]
    pub environment: String,
}

fn default_gateway_id() -> String {
    "gateway-default".into()
}
fn default_instance_name() -> String {
    "gateway-instance".into()
}
fn default_environment() -> String {
    "development".into()
}

impl Default for GatewayMeta {
    fn default() -> Self {
        Self {
            id: default_gateway_id(),
            instance_name: default_instance_name(),
            environment: default_environment(),
        }
    }
}

// ---------------------------------------------------------------------------
// ServerConfig —— 监听端口
// ---------------------------------------------------------------------------

/// 服务端监听配置。
///
/// 业务 Listener 和管理 Listener 是两个独立的端口。管理端口默认
/// 只绑定 127.0.0.1，不能直接暴露在公网。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// 业务 HTTP Listener。Phase 1 只支持 HTTP（HTTPS 是 P1）
    #[serde(default)]
    pub http: HttpListenerConfig,
    /// 管理 Admin Listener。Phase 1 只暴露 /health /ready /version
    #[serde(default)]
    pub admin: AdminListenerConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpListenerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_http_address")]
    pub address: String,
    #[serde(default = "default_http_port")]
    pub port: u16,
    /// TLS（HTTPS）配置。未启用时监听明文 HTTP。
    #[serde(default)]
    pub tls: TlsListenerConfig,
}

/// 业务 Listener 的 TLS 配置。
///
/// 证书来源按优先级：
/// 1. `certificate_id`：引用 `certificates` 资源（YAML 或控制面快照）
/// 2. `cert_file` + `key_file`：直接从文件加载（支持热重载）
///
/// 两者可同时配置：文件证书作为启动引导/回退，配置快照中的证书
/// 会在发布后加入 SNI 集合，并可按 `certificate_id` 切换默认证书。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsListenerConfig {
    /// 是否启用 HTTPS
    #[serde(default)]
    pub enabled: bool,
    /// 默认证书资源 ID（SNI 未命中时使用）
    #[serde(default)]
    pub certificate_id: Option<String>,
    /// 证书链 PEM 文件路径（YAML 独立部署模式）
    #[serde(default)]
    pub cert_file: Option<String>,
    /// 私钥 PEM 文件路径（PKCS#8 / RSA / ECDSA）
    #[serde(default)]
    pub key_file: Option<String>,
    /// 文件证书绑定的域名列表（SNI 匹配，支持 `*.example.com`）
    #[serde(default)]
    pub domains: Vec<String>,
    /// 可选客户端 CA 文件；配置后要求 mTLS 客户端证书
    #[serde(default)]
    pub client_ca_file: Option<String>,
    /// 文件证书热重载轮询间隔（秒）
    #[serde(default = "default_tls_reload_interval_secs")]
    pub reload_interval_secs: u64,
}

fn default_tls_reload_interval_secs() -> u64 {
    10
}

impl Default for TlsListenerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            certificate_id: None,
            cert_file: None,
            key_file: None,
            domains: Vec::new(),
            client_ca_file: None,
            reload_interval_secs: default_tls_reload_interval_secs(),
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_http_address() -> String {
    "0.0.0.0".into()
}
fn default_http_port() -> u16 {
    8080
}

impl Default for HttpListenerConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            address: default_http_address(),
            port: default_http_port(),
            tls: TlsListenerConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminListenerConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 管理端口默认只绑定本机，不能暴露公网
    #[serde(default = "default_admin_address")]
    pub address: String,
    #[serde(default = "default_admin_port")]
    pub port: u16,
}

fn default_admin_address() -> String {
    "127.0.0.1".into()
}
fn default_admin_port() -> u16 {
    8081
}

impl Default for AdminListenerConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            address: default_admin_address(),
            port: default_admin_port(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http: HttpListenerConfig::default(),
            admin: AdminListenerConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// RuntimeConfig —— 运行时资源限制
// ---------------------------------------------------------------------------

/// 运行时资源限制配置。
///
/// 这些限制是 Phase 1 中网络接入层的核心保护：
///   - max_connections：防止无限制接受连接导致文件描述符耗尽
///   - max_concurrent_requests：防止内存被瞬时高并发打爆
///   - graceful_shutdown_timeout：收到 SIGTERM 后最多等多久
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// 最大并发连接数（accept backlog 之外的硬限制）
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// 最大并发请求数（同一时刻正在处理的请求数）
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: u32,
    /// 最大请求体大小（字节）。超过会返回 413
    #[serde(default = "default_max_request_body_size")]
    pub max_request_body_size: u64,
    /// 优雅关闭超时（秒）
    #[serde(default = "default_graceful_timeout")]
    pub graceful_shutdown_timeout_secs: u64,
}

fn default_max_connections() -> u32 {
    10_000
}
fn default_max_concurrent_requests() -> u32 {
    5_000
}
fn default_max_request_body_size() -> u64 {
    10 * 1024 * 1024
} // 10 MB
fn default_graceful_timeout() -> u64 {
    30
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_concurrent_requests: default_max_concurrent_requests(),
            max_request_body_size: default_max_request_body_size(),
            graceful_shutdown_timeout_secs: default_graceful_timeout(),
        }
    }
}

// ---------------------------------------------------------------------------
// ObservabilityConfig —— 日志/Metrics/Tracing 初始化参数
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ObservabilityConfig {
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub tracing: TracingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// 日志级别：trace / debug / info / warn / error
    #[serde(default = "default_log_level")]
    pub level: String,
    /// 日志格式：json / pretty
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "json".into()
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

fn default_metrics_path() -> String {
    "/metrics".into()
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_metrics_path(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    #[serde(default)]
    pub enabled: bool,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
}

// ---------------------------------------------------------------------------
// ControlPlaneConfig —— 控制面连接参数（Phase 3 开始生效）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneConfig {
    /// Phase 1 中禁用。改为 true 后 Runtime 会尝试连接控制面
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_reconnect_interval")]
    pub reconnect_interval_secs: u64,
}

fn default_heartbeat_interval() -> u64 {
    10
}
fn default_reconnect_interval() -> u64 {
    5
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            heartbeat_interval_secs: default_heartbeat_interval(),
            reconnect_interval_secs: default_reconnect_interval(),
        }
    }
}

// ---------------------------------------------------------------------------
// PoliciesConfig —— Phase 2 策略集合
// ---------------------------------------------------------------------------

/// 策略配置集合。
///
/// # 为什么按类型分段而不是一个扁平列表
///
/// 不同策略的字段结构完全不同（鉴权有 secret、限流有 rate），
/// 分段可以让每类策略使用独立的强类型结构：
///   - serde 反序列化阶段就能拒绝类型错误的字段（例如给限流写 `secret`）
///   - validator 只需遍历对应段做针对性校验
///   - 未来新增策略类型不影响已有段的 schema
///
/// # 引用与命名
///
/// 各段内的 `id` 只需在**本段内唯一**。Route 的引用字段是强类型的
/// （`auth_policy_id` 只能引用 `auth` 段），因此跨段重名不会产生歧义。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PoliciesConfig {
    /// 鉴权策略（IP 黑白名单 / Basic / API Key / JWT）
    #[serde(default)]
    pub auth: Vec<gateway_core::AuthPolicyConfig>,
    /// 限流策略（Token Bucket / Fixed Window）
    #[serde(default)]
    pub rate_limit: Vec<gateway_core::RateLimitPolicyConfig>,
    /// 超时策略（连接/首包/空闲）
    #[serde(default)]
    pub timeout: Vec<gateway_core::TimeoutPolicyConfig>,
    /// 重试策略（幂等方法白名单 + 退避）
    #[serde(default)]
    pub retry: Vec<gateway_core::RetryPolicyConfig>,
    /// 熔断策略（Closed / Open / HalfOpen 状态机参数）
    #[serde(default)]
    pub circuit_breaker: Vec<gateway_core::CircuitBreakerPolicyConfig>,
    /// CORS 策略
    #[serde(default)]
    pub cors: Vec<gateway_core::CorsPolicyConfig>,
    /// 请求 Header 转换策略
    #[serde(default)]
    pub request_transform: Vec<gateway_core::TransformPolicyConfig>,
    /// 响应 Header 转换策略
    #[serde(default)]
    pub response_transform: Vec<gateway_core::TransformPolicyConfig>,
    /// WAF 策略（Phase 7）
    #[serde(default)]
    pub waf: Vec<gateway_core::WafPolicyConfig>,
    /// 配额策略（Phase 7）
    #[serde(default)]
    pub quota: Vec<gateway_core::QuotaPolicyConfig>,
}
