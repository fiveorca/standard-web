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
