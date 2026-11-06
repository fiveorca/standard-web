//! 网关配置模型。
//!
//! 所有配置项都有明确的默认值，并且默认值遵循“安全优先”原则：
//! 上游 TLS 校验默认开启、管理接口默认只监听回环地址、限流在 Redis 故障时默认拒绝请求。

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::utils::duration as dur;

/// 顶层配置。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GatewayConfig {
    #[serde(default)]
    pub gateway: GatewaySection,
    #[serde(default)]
    pub routes: Vec<RouteConfig>,
}

/// `gateway` 配置节。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GatewaySection {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub admin: AdminConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub tracing: TracingConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
    #[serde(default)]
    pub authentication: AuthConfig,
    #[serde(default)]
    pub rate_limit: GlobalRateLimitConfig,
    #[serde(default)]
    pub service_discovery: ServiceDiscoveryConfig,
    #[serde(default)]
    pub load_balancer: LoadBalancerConfig,
    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,
    #[serde(default)]
    pub cache: GlobalCacheConfig,
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    #[serde(default)]
    pub ip_filter: IpFilterConfig,
    #[serde(default)]
    pub upstream_tls: UpstreamTlsConfig,
    #[serde(default)]
    pub redis: RedisConfig,
    /// 静态上游服务组，供 `lb://service-name` 使用。
    #[serde(default)]
    pub services: HashMap<String, ServiceConfig>,
    /// 全局过滤器：对所有路由生效，先于路由级过滤器执行。
    #[serde(default)]
    pub global_filters: Vec<FilterSpec>,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub timeouts: ServerTimeouts,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(
        default = "default_graceful_shutdown",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub graceful_shutdown_timeout: Duration,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_true")]
    pub enable_http2: bool,
    /// 可信代理 IP / CIDR：只有来自这些地址的 `X-Forwarded-*` 才会被采信。
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: default_host(),
            port: default_port(),
            tls: TlsConfig::default(),
            timeouts: ServerTimeouts::default(),
            limits: LimitsConfig::default(),
            graceful_shutdown_timeout: default_graceful_shutdown(),
            max_connections: default_max_connections(),
            enable_http2: true,
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub cert_path: Option<String>,
    #[serde(default)]
    pub key_path: Option<String>,
    /// 双向 TLS：要求客户端证书的 CA 证书路径。
    #[serde(default)]
    pub client_ca_path: Option<String>,
    /// 最低 TLS 协议版本：`1.2` 或 `1.3`。
    #[serde(default = "default_tls_version")]
    pub min_version: String,
}

fn default_tls_version() -> String {
    "1.2".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerTimeouts {
    /// 读取客户端请求头 / 建立连接的默认超时（由下游服务器控制）。
    #[serde(
        default = "default_connect_timeout",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub client_connect: Duration,
    /// 空闲连接超时。
    #[serde(
        default = "default_idle_timeout",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub idle: Duration,
    /// 单个请求的整体默认超时（路由未配置时使用）。
    #[serde(
        default = "default_request_timeout",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub request: Duration,
}

impl Default for ServerTimeouts {
    fn default() -> Self {
        Self {
            client_connect: default_connect_timeout(),
            idle: default_idle_timeout(),
            request: default_request_timeout(),
        }
    }
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(5)
}
fn default_idle_timeout() -> Duration {
    Duration::from_secs(75)
}
fn default_request_timeout() -> Duration {
    Duration::from_secs(60)
}
fn default_graceful_shutdown() -> Duration {
    Duration::from_secs(30)
}
fn default_max_connections() -> usize {
    10_000
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LimitsConfig {
    /// 请求头总大小上限（字节）。
    #[serde(default = "default_max_header_size")]
    pub max_header_size: usize,
    /// 请求体大小上限（字节），0 表示不限制。
    #[serde(default = "default_max_body_size")]
    pub max_body_size: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_header_size: default_max_header_size(),
            max_body_size: default_max_body_size(),
        }
    }
}

fn default_max_header_size() -> usize {
    32 * 1024
}
fn default_max_body_size() -> u64 {
    64 * 1024 * 1024
}

// ---------------------------------------------------------------------------
// Admin
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_admin_host")]
    pub host: String,
    #[serde(default = "default_admin_port")]
    pub port: u16,
    /// 允许访问管理接口的来源 IP / CIDR。为空表示不额外限制（仍需认证）。
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub auth: AdminAuthConfig,
    #[serde(default)]
    pub persistence: PersistenceConfig,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            host: default_admin_host(),
            port: default_admin_port(),
            allowed_ips: Vec::new(),
            auth: AdminAuthConfig::default(),
            persistence: PersistenceConfig::default(),
        }
    }
}

fn default_admin_host() -> String {
    "127.0.0.1".to_string()
}
fn default_admin_port() -> u16 {
    9090
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AdminAuthConfig {
    /// `api_key`（默认）、`jwt` 或 `none`（仅当显式配置时才允许）。
    #[serde(default = "default_admin_auth_mode")]
    pub mode: String,
    /// 允许的管理 API Key 明文列表。支持 `${ENV_VAR}` 占位。
    #[serde(default)]
    pub api_keys: Vec<String>,
    /// 使用 JWT 保护管理接口时的 JWT 配置。
    #[serde(default)]
    pub jwt: Option<JwtConfig>,
    /// 管理 Key 的请求头名称。
    #[serde(default = "default_admin_key_header")]
    pub header: String,
}

impl Default for AdminAuthConfig {
    fn default() -> Self {
        Self {
            mode: default_admin_auth_mode(),
            api_keys: Vec::new(),
            jwt: None,
            header: default_admin_key_header(),
        }
    }
}

fn default_admin_auth_mode() -> String {
    "api_key".to_string()
}
fn default_admin_key_header() -> String {
    "x-admin-key".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PersistenceConfig {
    /// 是否把管理 API 的路由变更持久化到磁盘。
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 持久化路径，默认使用配置文件所在目录下的 `routes.yaml`。
    #[serde(default)]
    pub path: Option<String>,
}

impl Default for PersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Logging / tracing / metrics / security
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    /// `json` 或 `text`。
    #[serde(default = "default_log_format")]
    pub format: String,
    #[serde(default = "default_true")]
    pub access_log: bool,
    /// 日志中需要脱敏的请求头。
    #[serde(default = "default_redact_headers")]
    pub redact_headers: Vec<String>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
            access_log: true,
            redact_headers: default_redact_headers(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}
fn default_redact_headers() -> Vec<String> {
    vec![
        "authorization".to_string(),
        "cookie".to_string(),
        "set-cookie".to_string(),
        "x-api-key".to_string(),
        "x-admin-key".to_string(),
        "proxy-authorization".to_string(),
    ]
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TracingConfig {
    #[serde(default)]
    pub enabled: bool,
    /// OTLP HTTP endpoint，例如 `http://127.0.0.1:4318`。
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_service_name")]
    pub service_name: String,
    #[serde(default = "default_sample_ratio")]
    pub sample_ratio: f64,
    #[serde(default)]
    pub headers: HashMap<String, String>,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: None,
            service_name: default_service_name(),
            sample_ratio: default_sample_ratio(),
            headers: HashMap::new(),
        }
    }
}

fn default_service_name() -> String {
    "rust-api-gateway".to_string()
}
fn default_sample_ratio() -> f64 {
    1.0
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SecurityConfig {
    #[serde(default = "default_request_id_header")]
    pub request_id_header: String,
    /// 是否信任客户端传入的请求 ID（仍会做格式校验）。
    #[serde(default = "default_true")]
    pub trust_client_request_id: bool,
    /// 是否在响应中添加安全头。
    #[serde(default = "default_true")]
    pub add_security_headers: bool,
    #[serde(default)]
    pub host_validation: HostValidationConfig,
    /// 是否禁止代理到私网 / 回环 / 链路本地地址（多租户场景建议开启）。
    #[serde(default)]
    pub block_private_upstreams: bool,
    /// 自定义安全响应头。
    #[serde(default)]
    pub extra_headers: HashMap<String, String>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            request_id_header: default_request_id_header(),
            trust_client_request_id: true,
            add_security_headers: true,
            host_validation: HostValidationConfig::default(),
            block_private_upstreams: false,
            extra_headers: HashMap::new(),
        }
    }
}

fn default_request_id_header() -> String {
    "x-request-id".to_string()
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct HostValidationConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_path")]
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_metrics_path(),
        }
    }
}

fn default_metrics_path() -> String {
    "/metrics".to_string()
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default)]
    pub jwt: Option<JwtConfig>,
    #[serde(default)]
    pub api_keys: Vec<ApiKeyConfig>,
    #[serde(
        default = "default_jwks_cache_ttl",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub jwks_cache_ttl: Duration,
    #[serde(
        default = "default_jwks_min_refresh",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub jwks_min_refresh_interval: Duration,
    #[serde(default = "default_api_key_header")]
    pub api_key_header: String,
    #[serde(default)]
    pub identity_headers: IdentityHeadersConfig,
}

fn default_api_key_header() -> String {
    "x-api-key".to_string()
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            jwt: None,
            api_keys: Vec::new(),
            jwks_cache_ttl: default_jwks_cache_ttl(),
            jwks_min_refresh_interval: default_jwks_min_refresh(),
            api_key_header: default_api_key_header(),
            identity_headers: IdentityHeadersConfig::default(),
        }
    }
}

fn default_jwks_cache_ttl() -> Duration {
    Duration::from_secs(300)
}
fn default_jwks_min_refresh() -> Duration {
    Duration::from_secs(30)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct IdentityHeadersConfig {
    #[serde(default = "default_user_id_header")]
    pub user_id: String,
    #[serde(default = "default_scopes_header")]
    pub scopes: String,
    #[serde(default = "default_roles_header")]
    pub roles: String,
    #[serde(default = "default_tenant_header")]
    pub tenant: String,
    #[serde(default = "default_auth_type_header")]
    pub auth_type: String,
}

impl Default for IdentityHeadersConfig {
    fn default() -> Self {
        Self {
            user_id: default_user_id_header(),
            scopes: default_scopes_header(),
            roles: default_roles_header(),
            tenant: default_tenant_header(),
            auth_type: default_auth_type_header(),
        }
    }
}

fn default_user_id_header() -> String {
    "x-user-id".to_string()
}
fn default_scopes_header() -> String {
    "x-user-scopes".to_string()
}
fn default_roles_header() -> String {
    "x-user-roles".to_string()
}
fn default_tenant_header() -> String {
    "x-tenant-id".to_string()
}
fn default_auth_type_header() -> String {
    "x-auth-type".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwtConfig {
    /// 允许的签名算法：HS256、HS384、HS512、RS256、RS384、RS512、ES256、ES384。
    #[serde(default = "default_jwt_algorithms")]
    pub algorithms: Vec<String>,
    /// HS* 算法使用的共享密钥。推荐通过 `secret_env` 注入。
    #[serde(default)]
    pub secret: Option<String>,
    /// 从环境变量读取共享密钥。
    #[serde(default)]
    pub secret_env: Option<String>,
    /// OIDC JWKS 地址，用于 RS*/ES* 算法。
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Vec<String>,
    /// 时钟偏移容忍（秒）。
    #[serde(default = "default_jwt_leeway")]
    pub leeway: u64,
    #[serde(default = "default_true")]
    pub require_exp: bool,
    /// 必须存在的声明。
    #[serde(default)]
    pub required_claims: Vec<String>,
    /// Token 类型声明名称，例如 `typ`。
    #[serde(default)]
    pub token_type_claim: Option<String>,
    /// 允许的 Token 类型值。
    #[serde(default)]
    pub allowed_token_types: Vec<String>,
    /// 携带 Token 的请求头。
    #[serde(default = "default_auth_header")]
    pub header: String,
    /// Token 前缀，例如 `Bearer`。
    #[serde(default = "default_auth_prefix")]
    pub prefix: String,
    /// 承载 scopes 的声明名。
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
    /// 承载角色列表的声明名。
    #[serde(default = "default_roles_claim")]
    pub roles_claim: String,
    /// 承载租户的声明名。
    #[serde(default = "default_tenant_claim")]
    pub tenant_claim: String,
    /// 承载用户主体的声明名。
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
}

impl Default for JwtConfig {
    fn default() -> Self {
        Self {
            algorithms: default_jwt_algorithms(),
            secret: None,
            secret_env: None,
            jwks_uri: None,
            issuer: None,
            audience: Vec::new(),
            leeway: default_jwt_leeway(),
            require_exp: true,
            required_claims: Vec::new(),
            token_type_claim: None,
            allowed_token_types: Vec::new(),
            header: default_auth_header(),
            prefix: default_auth_prefix(),
            scope_claim: default_scope_claim(),
            roles_claim: default_roles_claim(),
            tenant_claim: default_tenant_claim(),
            subject_claim: default_subject_claim(),
        }
    }
}

fn default_jwt_algorithms() -> Vec<String> {
    vec!["HS256".to_string()]
}
fn default_jwt_leeway() -> u64 {
    30
}
fn default_auth_header() -> String {
    "authorization".to_string()
}
fn default_auth_prefix() -> String {
    "Bearer".to_string()
}
fn default_scope_claim() -> String {
    "scope".to_string()
}
fn default_roles_claim() -> String {
    "roles".to_string()
}
fn default_tenant_claim() -> String {
    "tenant".to_string()
}
fn default_subject_claim() -> String {
    "sub".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ApiKeyConfig {
    pub id: String,
    /// 明文 Key（兼容写法，生产环境建议使用 `key_hash`）。
    #[serde(default)]
    pub key: Option<String>,
    /// Key 的 SHA-256 十六进制摘要。
    #[serde(default)]
    pub key_hash: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

// ---------------------------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitMode {
    #[default]
    Local,
    Redis,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKeyType {
    #[default]
    Global,
    Ip,
    User,
    Tenant,
    ApiKey,
    Custom,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct QuotaConfig {
    #[serde(default)]
    pub requests_per_second: Option<f64>,
    #[serde(default)]
    pub requests_per_minute: Option<f64>,
    #[serde(default)]
    pub requests_per_hour: Option<f64>,
    #[serde(default)]
    pub burst_capacity: Option<u32>,
    /// 兼容示例配置中的 `replenish_rate`。
    #[serde(default)]
    pub replenish_rate: Option<f64>,
}

impl QuotaConfig {
    /// 计算每秒补充速率。
    pub fn rate_per_second(&self) -> f64 {
        if let Some(v) = self.requests_per_second.or(self.replenish_rate) {
            return v.max(0.0);
        }
        if let Some(v) = self.requests_per_minute {
            return (v / 60.0).max(0.0);
        }
        if let Some(v) = self.requests_per_hour {
            return (v / 3600.0).max(0.0);
        }
        100.0
    }

    /// 突发容量。
    pub fn burst(&self) -> u32 {
        if let Some(v) = self.burst_capacity {
            return v.max(1);
        }
        (self.rate_per_second().ceil() as u32).max(1)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalRateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: RateLimitMode,
    #[serde(default)]
    pub key_type: RateLimitKeyType,
    #[serde(default)]
    pub quota: QuotaConfig,
    #[serde(default = "default_redis_prefix")]
    pub redis_key_prefix: String,
    /// Redis 故障时是否放行。默认关闭（fail-closed）。
    #[serde(default)]
    pub fail_open: bool,
    /// 本地限流桶的最大数量。
    #[serde(default = "default_max_rate_keys")]
    pub max_keys: usize,
    #[serde(
        default = "default_cleanup_interval",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub cleanup_interval: Duration,
}

impl Default for GlobalRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: RateLimitMode::Local,
            key_type: RateLimitKeyType::Global,
            quota: QuotaConfig::default(),
            redis_key_prefix: default_redis_prefix(),
            fail_open: false,
            max_keys: default_max_rate_keys(),
            cleanup_interval: default_cleanup_interval(),
        }
    }
}

fn default_redis_prefix() -> String {
    "gateway:rl:".to_string()
}
fn default_max_rate_keys() -> usize {
    100_000
}
fn default_cleanup_interval() -> Duration {
    Duration::from_secs(60)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RedisConfig {
    #[serde(default)]
    pub url: String,
    #[serde(
        default = "default_redis_pool",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub connect_timeout: Duration,
    #[serde(
        default = "default_redis_timeout",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub command_timeout: Duration,
    /// 多实例配置同步使用的 Pub/Sub 频道。
    #[serde(default = "default_redis_channel")]
    pub channel: String,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            connect_timeout: default_redis_pool(),
            command_timeout: default_redis_timeout(),
            channel: default_redis_channel(),
        }
    }
}

fn default_redis_channel() -> String {
    "gateway:config".to_string()
}

fn default_redis_pool() -> Duration {
    Duration::from_secs(3)
}
fn default_redis_timeout() -> Duration {
    Duration::from_secs(2)
}

// ---------------------------------------------------------------------------
// Service discovery
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceDiscoveryConfig {
    #[serde(
        default = "default_discovery_refresh",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub refresh_interval: Duration,
    #[serde(default)]
    pub consul: Option<ConsulConfig>,
}

impl Default for ServiceDiscoveryConfig {
    fn default() -> Self {
        Self {
            refresh_interval: default_discovery_refresh(),
            consul: None,
        }
    }
}

fn default_discovery_refresh() -> Duration {
    Duration::from_secs(10)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConsulConfig {
    #[serde(default = "default_consul_address")]
    pub address: String,
    #[serde(default)]
    pub datacenter: Option<String>,
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub token_env: Option<String>,
    #[serde(default)]
    pub tag: Option<String>,
    /// 是否只返回通过健康检查的实例。
    #[serde(default = "default_true")]
    pub passing_only: bool,
    #[serde(
        default = "default_consul_timeout",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub request_timeout: Duration,
    /// 服务名到 Consul 服务名的映射前缀。
    #[serde(default)]
    pub service_prefix: Option<String>,
}

impl Default for ConsulConfig {
    fn default() -> Self {
        Self {
            address: default_consul_address(),
            datacenter: None,
            token: None,
            token_env: None,
            tag: None,
            passing_only: true,
            request_timeout: default_consul_timeout(),
            service_prefix: None,
        }
    }
}

fn default_consul_address() -> String {
    "http://127.0.0.1:8500".to_string()
}
fn default_consul_timeout() -> Duration {
    Duration::from_secs(3)
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServiceConfig {
    /// `static` 或 `consul`。
    #[serde(default = "default_static_discovery")]
    pub discovery: String,
    /// Consul 中的服务名，默认使用路由中的服务名。
    #[serde(default)]
    pub consul_service: Option<String>,
    #[serde(default)]
    pub instances: Vec<InstanceConfig>,
    #[serde(default)]
    pub load_balancer: Option<LbStrategy>,
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            discovery: default_static_discovery(),
            consul_service: None,
            instances: Vec::new(),
            load_balancer: None,
            health_check: None,
        }
    }
}

fn default_static_discovery() -> String {
    "static".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InstanceConfig {
    #[serde(default)]
    pub id: Option<String>,
    pub uri: String,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

fn default_weight() -> u32 {
    1
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthCheckConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_health_path")]
    pub path: String,
    #[serde(
        default = "default_health_interval",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub interval: Duration,
    #[serde(
        default = "default_health_timeout",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub timeout: Duration,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    /// 仅做 TCP 连通性检查。
    #[serde(default)]
    pub tcp_only: bool,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            path: default_health_path(),
            interval: default_health_interval(),
            timeout: default_health_timeout(),
            healthy_threshold: default_healthy_threshold(),
            unhealthy_threshold: default_unhealthy_threshold(),
            tcp_only: false,
        }
    }
}

fn default_health_path() -> String {
    "/health".to_string()
}
fn default_health_interval() -> Duration {
    Duration::from_secs(10)
}
fn default_health_timeout() -> Duration {
    Duration::from_secs(2)
}
fn default_healthy_threshold() -> u32 {
    2
}
fn default_unhealthy_threshold() -> u32 {
    3
}

// ---------------------------------------------------------------------------
// Load balancer / circuit breaker / cache
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LbStrategy {
    #[default]
    #[serde(alias = "roundrobin", alias = "round-robin")]
    RoundRobin,
    Random,
    #[serde(alias = "weighted_round_robin")]
    WeightedRoundRobin,
    #[serde(alias = "weighted_random")]
    WeightedRandom,
    LeastConnections,
    #[serde(alias = "p2c")]
    PowerOfTwoChoices,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoadBalancerConfig {
    #[serde(default)]
    pub strategy: LbStrategy,
    #[serde(default = "default_weight")]
    pub default_weight: u32,
}

impl Default for LoadBalancerConfig {
    fn default() -> Self {
        Self {
            strategy: LbStrategy::RoundRobin,
            default_weight: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct CircuitBreakerConfig {
    #[serde(default)]
    pub enabled: bool,
    /// 失败率阈值（百分比）。
    #[serde(default = "default_failure_rate")]
    pub failure_rate_threshold: f64,
    /// 慢调用判定阈值。
    #[serde(
        default = "default_slow_call",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub slow_call_duration: Duration,
    /// 慢调用率阈值（百分比）。
    #[serde(default = "default_slow_rate")]
    pub slow_call_rate_threshold: f64,
    /// 滑动窗口内保留的最大样本数。
    #[serde(default = "default_window_size")]
    pub sliding_window_size: usize,
    /// 滑动窗口时间长度。
    #[serde(
        default = "default_window_duration",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub window_duration: Duration,
    /// 触发统计所需的最小请求数。
    #[serde(default = "default_min_requests")]
    pub minimum_requests: usize,
    /// 熔断持续时间。
    #[serde(
        default = "default_open_duration",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub open_duration: Duration,
    /// 半开状态允许的探测请求数。
    #[serde(default = "default_half_open_calls")]
    pub half_open_max_calls: u32,
    /// 半开状态下需要连续成功多少次才关闭熔断。
    #[serde(default = "default_half_open_successes")]
    pub half_open_success_threshold: u32,
    #[serde(default)]
    pub fallback: Option<FallbackConfig>,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            failure_rate_threshold: default_failure_rate(),
            slow_call_duration: default_slow_call(),
            slow_call_rate_threshold: default_slow_rate(),
            sliding_window_size: default_window_size(),
            window_duration: default_window_duration(),
            minimum_requests: default_min_requests(),
            open_duration: default_open_duration(),
            half_open_max_calls: default_half_open_calls(),
            half_open_success_threshold: default_half_open_successes(),
            fallback: None,
        }
    }
}

fn default_failure_rate() -> f64 {
    50.0
}
fn default_slow_call() -> Duration {
    Duration::from_secs(2)
}
fn default_slow_rate() -> f64 {
    80.0
}
fn default_window_size() -> usize {
    50
}
fn default_window_duration() -> Duration {
    Duration::from_secs(30)
}
fn default_min_requests() -> usize {
    10
}
fn default_open_duration() -> Duration {
    Duration::from_secs(10)
}
fn default_half_open_calls() -> u32 {
    3
}
fn default_half_open_successes() -> u32 {
    3
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct FallbackConfig {
    #[serde(default = "default_fallback_status")]
    pub status: u16,
    #[serde(default = "default_fallback_body")]
    pub body: String,
    #[serde(default = "default_fallback_content_type")]
    pub content_type: String,
}

fn default_fallback_status() -> u16 {
    503
}
fn default_fallback_body() -> String {
    r#"{"success":false,"error":{"code":"SERVICE_UNAVAILABLE","message":"service temporarily unavailable"}}"#
        .to_string()
}
fn default_fallback_content_type() -> String {
    "application/json; charset=utf-8".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct GlobalCacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(
        default = "default_cache_ttl",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub default_ttl: Duration,
    #[serde(default = "default_cache_capacity")]
    pub max_capacity: u64,
    #[serde(default = "default_cache_statuses")]
    pub cacheable_status: Vec<u16>,
    #[serde(default = "default_cache_body_limit")]
    pub max_body_size: usize,
    #[serde(default = "default_true")]
    pub respect_cache_control: bool,
    /// 是否缓存带 Authorization 的请求响应。
    #[serde(default)]
    pub cache_authenticated: bool,
}

impl Default for GlobalCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            default_ttl: default_cache_ttl(),
            max_capacity: default_cache_capacity(),
            cacheable_status: default_cache_statuses(),
            max_body_size: default_cache_body_limit(),
            respect_cache_control: true,
            cache_authenticated: false,
        }
    }
}

fn default_cache_ttl() -> Duration {
    Duration::from_secs(30)
}
fn default_cache_capacity() -> u64 {
    10_000
}
fn default_cache_statuses() -> Vec<u16> {
    vec![200]
}
fn default_cache_body_limit() -> usize {
    1024 * 1024
}

// ---------------------------------------------------------------------------
// CORS / IP filter / upstream TLS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CorsConfig {
    #[serde(default = "default_allowed_origins")]
    pub allowed_origins: Vec<String>,
    #[serde(default = "default_allowed_methods")]
    pub allowed_methods: Vec<String>,
    #[serde(default = "default_allowed_headers")]
    pub allowed_headers: Vec<String>,
    #[serde(default)]
    pub exposed_headers: Vec<String>,
    #[serde(default)]
    pub allow_credentials: bool,
    #[serde(
        default = "default_cors_max_age",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub max_age: Duration,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: default_allowed_origins(),
            allowed_methods: default_allowed_methods(),
            allowed_headers: default_allowed_headers(),
            exposed_headers: Vec::new(),
            allow_credentials: false,
            max_age: default_cors_max_age(),
        }
    }
}

fn default_allowed_origins() -> Vec<String> {
    vec!["*".to_string()]
}
fn default_allowed_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "POST".to_string(),
        "PUT".to_string(),
        "PATCH".to_string(),
        "DELETE".to_string(),
        "OPTIONS".to_string(),
        "HEAD".to_string(),
    ]
}
fn default_allowed_headers() -> Vec<String> {
    vec!["*".to_string()]
}
fn default_cors_max_age() -> Duration {
    Duration::from_secs(3600)
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct IpFilterConfig {
    /// 白名单：非空时只允许列表内地址。
    #[serde(default)]
    pub allow: Vec<String>,
    /// 黑名单：优先级高于白名单。
    #[serde(default)]
    pub deny: Vec<String>,
}

impl IpFilterConfig {
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamTlsConfig {
    /// 是否校验上游证书。生产环境必须保持 true。
    #[serde(default = "default_true")]
    pub verify: bool,
    #[serde(default)]
    pub ca_cert_path: Option<String>,
    #[serde(default)]
    pub client_cert_path: Option<String>,
    #[serde(default)]
    pub client_key_path: Option<String>,
    /// SNI 覆盖值。
    #[serde(default)]
    pub server_name: Option<String>,
}

impl Default for UpstreamTlsConfig {
    fn default() -> Self {
        Self {
            verify: true,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
            server_name: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteConfig {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 路由顺序：数值越小优先级越高。
    #[serde(default)]
    pub order: i32,
    pub uri: String,
    #[serde(default)]
    pub predicates: Vec<PredicateSpec>,
    #[serde(default)]
    pub filters: Vec<FilterSpec>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub authentication: Option<RouteAuthConfig>,
    #[serde(default)]
    pub authorization: Option<RouteAuthorizationConfig>,
    #[serde(default)]
    pub timeout: Option<RouteTimeoutConfig>,
    #[serde(default)]
    pub retry: Option<RetryConfig>,
    #[serde(default)]
    pub rate_limit: Option<RouteRateLimitConfig>,
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    #[serde(default)]
    pub cors: Option<CorsConfig>,
    #[serde(default)]
    pub cache: Option<RouteCacheConfig>,
    #[serde(default)]
    pub ip_filter: Option<IpFilterConfig>,
    #[serde(default)]
    pub load_balancer: Option<LbStrategy>,
    #[serde(default)]
    pub upstream: Option<RouteUpstreamConfig>,
    #[serde(default)]
    pub description: Option<String>,
}

impl RouteConfig {
    pub fn authentication_mode(&self) -> AuthMode {
        self.authentication
            .as_ref()
            .map(|a| a.mode)
            .unwrap_or(AuthMode::Public)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    #[default]
    Public,
    Authenticated,
    ApiKey,
    Optional,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteAuthConfig {
    #[serde(default)]
    pub mode: AuthMode,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    /// 是否允许使用 API Key 完成认证。
    #[serde(default = "default_true")]
    pub allow_api_key: bool,
}

impl Default for RouteAuthConfig {
    fn default() -> Self {
        Self {
            mode: AuthMode::Public,
            scopes: Vec::new(),
            roles: Vec::new(),
            allow_api_key: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteAuthorizationConfig {
    /// `jwt` 或 `external`。
    #[serde(default = "default_authz_provider")]
    pub provider: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    /// 路由元数据到要求值的映射，例如 `{"team": "payments"}` 表示请求身份必须具备该元数据。
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    #[serde(default)]
    pub external: Option<ExternalAuthzConfig>,
}

impl Default for RouteAuthorizationConfig {
    fn default() -> Self {
        Self {
            provider: default_authz_provider(),
            scopes: Vec::new(),
            roles: Vec::new(),
            metadata: HashMap::new(),
            external: None,
        }
    }
}

fn default_authz_provider() -> String {
    "jwt".to_string()
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExternalAuthzConfig {
    pub url: String,
    #[serde(
        default = "default_authz_timeout",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub timeout: Duration,
    #[serde(
        default = "default_authz_cache_ttl",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub cache_ttl: Duration,
    /// 授权中心不可用时是否放行。
    #[serde(default)]
    pub fail_open: bool,
    /// 转发给授权中心的请求头。
    #[serde(default)]
    pub forward_headers: Vec<String>,
}

fn default_authz_timeout() -> Duration {
    Duration::from_secs(2)
}
fn default_authz_cache_ttl() -> Duration {
    Duration::from_secs(30)
}
fn default_authz_cache_timeout() -> Duration {
    default_authz_timeout()
}

impl Default for ExternalAuthzConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout: default_authz_cache_timeout(),
            cache_ttl: default_authz_cache_ttl(),
            fail_open: false,
            forward_headers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RouteTimeoutConfig {
    #[serde(
        default,
        deserialize_with = "dur::deserialize_opt",
        serialize_with = "dur::serialize_opt"
    )]
    pub connect: Option<Duration>,
    #[serde(
        default,
        deserialize_with = "dur::deserialize_opt",
        serialize_with = "dur::serialize_opt"
    )]
    pub response: Option<Duration>,
    #[serde(
        default,
        deserialize_with = "dur::deserialize_opt",
        serialize_with = "dur::serialize_opt"
    )]
    pub total: Option<Duration>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RetryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_retry_statuses")]
    pub retry_on_status: Vec<u16>,
    #[serde(default = "default_true")]
    pub retry_on_connect_error: bool,
    #[serde(default = "default_true")]
    pub retry_on_timeout: bool,
    #[serde(
        default = "default_backoff_initial",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub backoff_initial: Duration,
    #[serde(
        default = "default_backoff_max",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub backoff_max: Duration,
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,
    #[serde(default = "default_true")]
    pub jitter: bool,
    /// 允许非幂等请求重试（仅在显式开启时生效）。
    #[serde(default)]
    pub allow_non_idempotent: bool,
    /// 可重试请求体的最大缓冲字节数，超过则放弃重试以保证流式转发。
    #[serde(default = "default_retry_body_limit")]
    pub max_body_bytes: usize,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            max_attempts: default_max_attempts(),
            retry_on_status: default_retry_statuses(),
            retry_on_connect_error: true,
            retry_on_timeout: true,
            backoff_initial: default_backoff_initial(),
            backoff_max: default_backoff_max(),
            backoff_multiplier: default_backoff_multiplier(),
            jitter: true,
            allow_non_idempotent: false,
            max_body_bytes: default_retry_body_limit(),
        }
    }
}

fn default_max_attempts() -> u32 {
    2
}
fn default_retry_statuses() -> Vec<u16> {
    vec![502, 503, 504]
}
fn default_backoff_initial() -> Duration {
    Duration::from_millis(100)
}
fn default_backoff_max() -> Duration {
    Duration::from_secs(2)
}
fn default_backoff_multiplier() -> f64 {
    2.0
}
fn default_retry_body_limit() -> usize {
    64 * 1024
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RouteRateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub key_type: RateLimitKeyType,
    /// 自定义 Key 模板，例如 `header:X-Tenant`、`query:appid`、`literal:global`。
    #[serde(default)]
    pub key_template: Option<String>,
    #[serde(default)]
    pub quota: QuotaConfig,
    /// 覆盖全局限流模式。
    #[serde(default)]
    pub mode: Option<RateLimitMode>,
    /// 覆盖全局 fail-open 策略。
    #[serde(default)]
    pub fail_open: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteCacheConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(
        default = "default_cache_ttl",
        deserialize_with = "dur::deserialize",
        serialize_with = "dur::serialize"
    )]
    pub ttl: Duration,
    #[serde(default = "default_cache_capacity")]
    pub max_capacity: u64,
    /// 自定义缓存 Key 模板，例如 `header:X-App-Id`。
    #[serde(default)]
    pub key_template: Option<String>,
    #[serde(default = "default_cache_statuses")]
    pub cacheable_status: Vec<u16>,
    #[serde(default = "default_cache_body_limit")]
    pub max_body_size: usize,
    #[serde(default)]
    pub cache_authenticated: bool,
    #[serde(default)]
    pub vary_headers: Vec<String>,
    #[serde(default = "default_true")]
    pub respect_cache_control: bool,
}

impl Default for RouteCacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl: default_cache_ttl(),
            max_capacity: default_cache_capacity(),
            key_template: None,
            cacheable_status: default_cache_statuses(),
            max_body_size: default_cache_body_limit(),
            cache_authenticated: false,
            vary_headers: Vec::new(),
            respect_cache_control: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocol {
    #[default]
    #[serde(alias = "auto")]
    Auto,
    #[serde(alias = "http1", alias = "http/1.1")]
    Http1,
    #[serde(alias = "http2", alias = "h2", alias = "http/2")]
    Http2,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteUpstreamConfig {
    #[serde(default)]
    pub protocol: UpstreamProtocol,
    #[serde(default)]
    pub tls: UpstreamTlsConfig,
    /// 是否允许 WebSocket 升级转发（默认允许）。
    #[serde(default = "default_true")]
    pub websocket: bool,
}

impl Default for RouteUpstreamConfig {
    fn default() -> Self {
        Self {
            protocol: UpstreamProtocol::Auto,
            tls: UpstreamTlsConfig::default(),
            websocket: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Predicate / filter specs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PredicateSpec {
    Short(String),
    Full(PredicateObject),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PredicateObject {
    pub name: String,
    #[serde(default)]
    pub args: serde_yaml::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum FilterSpec {
    Short(String),
    Full(FilterObject),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilterObject {
    pub name: String,
    #[serde(default)]
    pub args: serde_yaml::Value,
}

// ---------------------------------------------------------------------------
// 默认值函数
// ---------------------------------------------------------------------------

fn default_true() -> bool {
    true
}
fn default_host() -> String {
    "0.0.0.0".to_string()
}
fn default_port() -> u16 {
    8080
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quota_conversion() {
        let q = QuotaConfig {
            requests_per_minute: Some(120.0),
            burst_capacity: Some(10),
            ..Default::default()
        };
        assert!((q.rate_per_second() - 2.0).abs() < f64::EPSILON);
        assert_eq!(q.burst(), 10);
    }

    #[test]
    fn route_uri_parsing_defaults() {
        let yaml = r#"
id: demo
uri: http://127.0.0.1:8081
predicates:
  - Path=/api/**
filters:
  - StripPrefix=1
"#;
        let route: RouteConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(route.id, "demo");
        assert_eq!(route.authentication_mode(), AuthMode::Public);
        assert_eq!(route.filters.len(), 1);
    }
}
