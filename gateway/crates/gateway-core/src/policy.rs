//! 策略（Policy）配置模型 —— Phase 2 治理能力的配置契约。
//!
//! # 本模块的职责边界
//!
//! 本模块**只定义数据结构**，不实现任何执行逻辑：
//!   - 鉴权（Auth）：IP 黑白名单、Basic、API Key、JWT
//!   - 限流（Rate Limit）：Token Bucket、Fixed Window
//!   - 超时（Timeout）
//!   - 重试（Retry）
//!   - 熔断（Circuit Breaker）
//!   - CORS
//!   - 请求/响应 Header 转换（Transform）
//!
//! 真正的执行器分别在 gateway-security（P2.3）、gateway-traffic（P2.4）、
//! gateway-transform（P2.5）、gateway-resilience（P2.6）中实现。
//!
//! # 为什么策略是"独立配置 + ID 引用"而不是内联在 Route 上
//!
//! 需求文档第 7 章要求策略必须可以复用与组合：
//!   - 同一条 JWT 策略可能被 20 条 Route 引用
//!   - 修改密钥或算法白名单时只改一处
//!   - 策略变更与路由变更可以独立灰度
//!
//! 因此 Route 只持有 `*_policy_id` 字符串引用，
//! `gateway-config::validate` 负责校验引用的目标确实存在。
//!
//! # 设计约束
//!
//!   - 本 crate 不依赖任何 IO 框架，模型保持纯数据（可 `Clone` / `PartialEq`）
//!   - 所有可选字段必须有明确默认值，避免反序列化 panic
//!   - 不使用浮点数（`f32`/`f64`）配置项，避免精度与 `Eq` 派生问题
//!   - 安全相关的默认值必须"安全优先"（fail closed）

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// 通用小工具
// ---------------------------------------------------------------------------

/// serde 默认值：`enabled = true`。
///
/// 策略只有在显式写 `enabled: false` 时才停用，
/// 避免"忘记写 enabled 导致策略静默失效"这一常见的安全事故。
fn default_enabled() -> bool {
    true
}

/// serde 默认值：`true`。
fn default_true() -> bool {
    true
}

// ===========================================================================
// Auth —— 鉴权策略
// ===========================================================================

/// 鉴权策略配置。
///
/// YAML 形态（`type` 字段由 [`AuthPolicySpec`] 的 serde tag 提供）：
///
/// ```yaml
/// policies:
///   auth:
///     - id: jwt-main
///       type: jwt
///       secret: "change-me"
///       algorithms: [HS256]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthPolicyConfig {
    /// 策略唯一 ID，Route 通过 `auth_policy_id` 引用
    pub id: String,
    /// 人类可读名称（日志/管理界面展示用）
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用。默认 true（安全策略不应因为漏写字段而失效）
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 策略的具体类型与参数。
    ///
    /// `#[serde(flatten)]` 把枚举内部字段（含 `type` 标签）
    /// 平铺到本结构体的同一层，因此 YAML 中 `type` 与 `id` 平级。
    /// serde 约束：被 flatten 的枚举必须是 map 形态（内部标签枚举满足）。
    #[serde(flatten)]
    pub spec: AuthPolicySpec,
}

/// 鉴权策略类型。
///
/// # serde 内部标签
/// `#[serde(tag = "type", rename_all = "snake_case")]` 表示 YAML 中用
/// `type: ip_allowlist` / `type: jwt` 等字段区分变体。
///
/// # 为什么用"枚举"而不是"一个带所有可选字段的大结构体"
/// 枚举能在反序列化阶段就拒绝非法组合。例如 `type: jwt` 的配置里
/// 写 `cidrs` 会直接报错，而不是被静默忽略——这符合需求文档
/// "未知字段不能默默接受"的约束。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthPolicySpec {
    /// IP 允许名单：只有命中名单的客户端才能访问。
    IpAllowlist {
        /// CIDR 或单个 IP 列表，例如 `10.0.0.0/8`、`192.168.1.5`
        #[serde(default)]
        cidrs: Vec<String>,
    },
    /// IP 拒绝名单：命中名单的客户端一律拒绝（优先级高于黑白名单中的放行）。
    IpDenylist {
        /// CIDR 或单个 IP 列表
        #[serde(default)]
        cidrs: Vec<String>,
    },
    /// HTTP Basic 认证（用户名 + 密码）。
    Basic {
        /// 允许的凭据列表
        #[serde(default)]
        credentials: Vec<BasicCredentialConfig>,
    },
    /// API Key 认证。
    ApiKey {
        /// 允许的 Key 列表
        #[serde(default)]
        keys: Vec<ApiKeyConfig>,
        /// 从哪个 Header 读取 Key，默认 `X-API-Key`
        #[serde(default = "default_api_key_header")]
        header_name: String,
        /// 是否允许从 Query 参数读取（默认不允许，避免 Key 泄漏到访问日志）
        #[serde(default)]
        query_param: Option<String>,
    },
    /// JWT 认证。
    ///
    /// 本实现采用 **静态密钥 + 算法白名单** 方案：
    ///   - 只支持 HMAC 系列（HS256/HS384/HS512），密钥为静态共享密钥
    ///   - 算法必须在 `algorithms` 白名单内，杜绝 `alg: none` 伪造
    ///   - 非对称算法（RS/ES）留待后续使用 JWKS 时再引入
    Jwt {
        /// HMAC 静态密钥（明文或 base64 均可，具体编码由 security 模块约定）。
        ///
        /// 校验器在 `enabled = true` 时必须提供该字段（见 validator）。
        #[serde(default)]
        secret: Option<String>,
        /// 允许的签名算法白名单。**不能为空**。
        ///
        /// 该白名单是防 `alg` 混淆攻击的核心手段：
        /// 攻击者若把 header 改成 `none` 或别的算法，签名校验直接失败。
        #[serde(default)]
        algorithms: Vec<JwtAlgorithm>,
        /// 期望的 `iss`（签发者）。配置后必须精确匹配。
        #[serde(default)]
        issuer: Option<String>,
        /// 期望的 `aud`（受众）。配置后必须精确匹配。
        #[serde(default)]
        audience: Option<String>,
        /// 时钟偏移容忍（秒），用于 `exp` / `nbf` 校验。
        ///
        /// 分布式部署中签发方与网关的系统时间可能有秒级偏差。
        #[serde(default)]
        leeway_secs: u64,
        /// 是否强制要求请求必须携带 Token。
        ///
        /// `true` 时无 Token 直接 401；`false` 时无 Token 放行、
        /// 有 Token 则校验（用于"可选登录态"场景）。
        #[serde(default = "default_true")]
        required: bool,
        /// 从哪个 Header 读取 Token，默认 `Authorization`（形如 `Bearer <jwt>`）
        #[serde(default = "default_authorization_header")]
        header_name: String,
        /// 是否允许从 Query 参数读取 Token（默认不允许）
        #[serde(default)]
        query_param: Option<String>,
        /// 是否校验 `exp`。默认 true。
        #[serde(default = "default_true")]
        validate_exp: bool,
    },
}

/// JWT 允许的签名算法（静态密钥方案下的白名单成员）。
///
/// # 为什么只列 HMAC 三种
/// 静态密钥方案下只有对称算法可用。把 `none` 与其他非对称算法
/// 排除在枚举之外，意味着它们在反序列化阶段就会被拒绝——
/// 这是"算法白名单"的第一道防线。
///
/// # serde 命名
/// `rename_all = "UPPERCASE"` 让 YAML 中可以直接写 `HS256`，
/// 与 JWT 生态（jose/jwt.io）的通用写法一致。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum JwtAlgorithm {
    /// HMAC-SHA256
    Hs256,
    /// HMAC-SHA384
    Hs384,
    /// HMAC-SHA512
    Hs512,
}

/// HTTP Basic 凭据。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicCredentialConfig {
    /// 用户名
    pub username: String,
    /// 密码（**明文配置**；日志与审计中严禁输出）
    pub password: String,
}

/// API Key 条目。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyConfig {
    /// Key 值（**敏感**；日志与审计中严禁输出）
    pub key: String,
    /// 标签（例如所属调用方名称），用于日志脱敏后的可读标识
    #[serde(default)]
    pub label: Option<String>,
    /// 该 Key 所属租户（Phase 7 多租户）
    #[serde(default)]
    pub tenant_id: Option<String>,
}

/// serde 默认值：API Key 读取 Header 名。
fn default_api_key_header() -> String {
    "X-API-Key".into()
}

/// serde 默认值：JWT 读取 Header 名。
fn default_authorization_header() -> String {
    "Authorization".into()
}

// ===========================================================================
// Rate Limit —— 限流策略
// ===========================================================================

/// 限流策略配置。
///
/// YAML 形态：
/// ```yaml
/// policies:
///   rate_limit:
///     - id: ip-limiter
///       algorithm: token_bucket
///       rate: 100
///       burst: 200
///       key: { kind: client_ip }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateLimitPolicyConfig {
    /// 策略唯一 ID，Route 通过 `rate_limit_policy_id` 引用
    pub id: String,
    /// 人类可读名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用，默认 true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 限流算法
    #[serde(default)]
    pub algorithm: RateLimitAlgorithm,
    /// 速率：
    ///   - Token Bucket：每秒补充的令牌数
    ///   - Fixed Window：每个窗口内允许的请求数
    pub rate: u64,
    /// Token Bucket 的桶容量（允许的突发上限）。
    ///
    /// 未配置时按 `rate` 取值（即不允许突发）。
    /// Fixed Window 算法忽略此字段。
    #[serde(default)]
    pub burst: Option<u64>,
    /// Fixed Window 的窗口长度（秒），默认 1 秒。
    /// Token Bucket 算法忽略此字段。
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
    /// 限流计数键
    #[serde(default)]
    pub key: RateLimitKeySpec,
    /// 存储后端故障时的行为（Phase 2 为进程内计数，故障几乎不可能；
    /// Phase 3 接入 Redis 后由本字段决定 Redis 不可用时的策略）
    #[serde(default)]
    pub failure_mode: FailureMode,
    /// 计数存储后端（Phase 6）
    #[serde(default)]
    pub backend: RateLimitBackend,
    /// Redis 连接地址，例如 `redis://127.0.0.1:6379/0`
    ///
    /// `backend = redis` 时必填；`backend = local` 时忽略。
    #[serde(default)]
    pub redis_url: Option<String>,
}

/// 限流计数存储后端。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitBackend {
    /// 进程内计数（默认，单实例语义）
    #[default]
    Local,
    /// Redis 共享计数（多实例全局限流）
    ///
    /// Redis 后端使用固定窗口算法（`INCR` + `EXPIRE` 原子脚本），
    /// `algorithm = token_bucket` 时会退化为固定窗口。
    Redis,
}

/// 限流算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitAlgorithm {
    /// 令牌桶：允许突发（桶容量内立即放行），之后按恒定速率补充
    #[default]
    TokenBucket,
    /// 固定窗口：每个时间窗口内计数，窗口边界重置
    FixedWindow,
}

/// 限流计数键。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RateLimitKeySpec {
    /// 键类型
    #[serde(default)]
    pub kind: RateLimitKeyKind,
    /// 当 `kind = header` 时读取的 Header 名称
    #[serde(default)]
    pub header: Option<String>,
}

/// 限流键类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKeyKind {
    /// 按客户端 IP 维度限流（最常见，无需信任上游身份）
    #[default]
    ClientIp,
    /// 全局共享一个计数器（保护整条链路的总吞吐）
    Global,
    /// 按某个 Header 的取值维度限流（例如按 API Key / 租户 ID）
    Header,
    /// 按 Route ID 维度限流（同一实例内所有引用该策略的路由共享/或按路由拆分）
    Route,
}

/// 存储后端故障时的处理模式。
///
/// 需求文档 7.x 明确规定：**不能默默降级为无限制访问**。
/// 因此默认值是 `FailClosed`（拒绝请求），而不是 `FailOpen`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FailureMode {
    /// 拒绝所有请求，保障配额/安全策略（安全优先，默认）
    #[default]
    FailClosed,
    /// 放行所有请求，仅保障可用性（需要显式配置才生效）
    FailOpen,
}

/// serde 默认值：固定窗口长度 1 秒。
fn default_window_secs() -> u64 {
    1
}

// ===========================================================================
// Timeout —— 超时策略
// ===========================================================================

/// 超时策略配置。
///
/// 时间单位统一用毫秒，避免秒级粒度无法表达短超时。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeoutPolicyConfig {
    /// 策略唯一 ID，Route 通过 `timeout_policy_id` 引用
    pub id: String,
    /// 人类可读名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用，默认 true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 连接上游的超时（毫秒），默认 5000
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// 从发出上游请求到收到响应头的超时（毫秒），默认 10000。
    ///
    /// 注意：这是"首包超时"，不是整个响应流的超时。
    /// 流式响应（SSE）的传输时长不受此限制——否则长连接会被误杀。
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// 响应体传输阶段的空闲超时（毫秒）。未配置时不限制。
    ///
    /// 用于兜底"上游开始返回后卡住不动"的场景，
    /// 同时不误杀持续有数据到来的慢速流。
    #[serde(default)]
    pub idle_timeout_ms: Option<u64>,
}

/// serde 默认值：连接超时 5000ms。
fn default_connect_timeout_ms() -> u64 {
    5_000
}

/// serde 默认值：请求超时 10000ms。
fn default_request_timeout_ms() -> u64 {
    10_000
}

// ===========================================================================
// Retry —— 重试策略
// ===========================================================================

/// 重试策略配置。
///
/// # 安全约束（需求文档"不允许不安全重试"）
///
/// 重试会重放请求体，非幂等方法（POST/PATCH）重放可能造成
/// 重复下单、重复扣款等业务事故。因此：
///   - `retry_methods` 只允许幂等方法（validator 强制校验）
///   - 默认白名单为 GET/HEAD/OPTIONS/PUT/DELETE
///   - `max_body_bytes` 限制需要缓冲的请求体大小，避免重试路径 OOM
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryPolicyConfig {
    /// 策略唯一 ID，Route 通过 `retry_policy_id` 引用
    pub id: String,
    /// 人类可读名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用，默认 true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 最大尝试次数（**包含首次请求**）。1 表示不重试。
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    /// 允许重试的 HTTP Method 白名单（大小写不敏感）。
    ///
    /// 默认只含幂等方法。validator 会拒绝非幂等方法。
    #[serde(default = "default_retry_methods")]
    pub retry_methods: Vec<String>,
    /// 触发重试的上游状态码列表，默认 502 / 503 / 504。
    ///
    /// 4xx 不重试（客户端错误重试无意义），500 也不默认重试
    /// （可能是上游业务逻辑确定性失败）。
    #[serde(default = "default_retry_statuses")]
    pub retry_statuses: Vec<u16>,
    /// 上游连接失败（连接被拒/超时/连接中断）是否重试，默认 true
    #[serde(default = "default_true")]
    pub retry_on_connection_error: bool,
    /// 退避策略
    #[serde(default)]
    pub backoff: BackoffConfig,
    /// 允许缓冲的请求体上限（字节），默认 1 MiB。
    ///
    /// 超过该大小的请求不缓冲、不重试（直接单次转发），
    /// 避免为可重放性而把大 body 放进内存。
    #[serde(default = "default_retry_max_body_bytes")]
    pub max_body_bytes: u64,
}

/// 退避策略。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackoffConfig {
    /// 退避算法
    #[serde(default)]
    pub strategy: BackoffStrategy,
    /// 基础延迟（毫秒），默认 100
    #[serde(default = "default_base_delay_ms")]
    pub base_delay_ms: u64,
    /// 单次退避上限（毫秒），默认 1000
    #[serde(default = "default_max_delay_ms")]
    pub max_delay_ms: u64,
}

/// 退避算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BackoffStrategy {
    /// 固定延迟：每次重试间隔 = base_delay_ms
    #[default]
    Fixed,
    /// 指数退避：base * 2^(n-1)，封顶 max_delay_ms
    Exponential,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            strategy: BackoffStrategy::default(),
            base_delay_ms: default_base_delay_ms(),
            max_delay_ms: default_max_delay_ms(),
        }
    }
}

/// serde 默认值：最大尝试次数 3（即最多重试 2 次）。
fn default_max_attempts() -> u32 {
    3
}

/// serde 默认值：幂等方法白名单。
fn default_retry_methods() -> Vec<String> {
    vec![
        "GET".into(),
        "HEAD".into(),
        "OPTIONS".into(),
        "PUT".into(),
        "DELETE".into(),
    ]
}

/// serde 默认值：可重试的上游状态码。
fn default_retry_statuses() -> Vec<u16> {
    vec![502, 503, 504]
}

/// serde 默认值：重试缓冲体上限 1 MiB。
fn default_retry_max_body_bytes() -> u64 {
    1024 * 1024
}

/// serde 默认值：基础退避 100ms。
fn default_base_delay_ms() -> u64 {
    100
}

/// serde 默认值：退避上限 1000ms。
fn default_max_delay_ms() -> u64 {
    1_000
}

// ===========================================================================
// Circuit Breaker —— 熔断策略
// ===========================================================================

/// 熔断策略配置。
///
/// # 状态机语义（P2.6 实现）
///
/// ```text
/// Closed ──(窗口内失败数 >= failure_threshold)──▶ Open
///   ▲                                              │
///   │                                        (open_duration 到期)
///   │                                              ▼
///   └──(HalfOpen 连续成功 >= success_threshold)── HalfOpen
///                (HalfOpen 任一次失败 → 立刻回 Open)
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CircuitBreakerPolicyConfig {
    /// 策略唯一 ID，Route 通过 `circuit_breaker_policy_id` 引用
    pub id: String,
    /// 人类可读名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用，默认 true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 触发熔断的连续失败次数，默认 5
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    /// 半开状态下恢复所需的连续成功次数，默认 3
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    /// 熔断打开后保持多久再进入半开（秒），默认 30
    #[serde(default = "default_open_duration_secs")]
    pub open_duration_secs: u64,
    /// 视为失败的上游状态码，默认 500-599 全量由实现展开；
    /// 这里用显式列表，默认 500/502/503/504。
    #[serde(default = "default_breaker_statuses")]
    pub failure_statuses: Vec<u16>,
    /// 上游连接失败是否计入失败，默认 true
    #[serde(default = "default_true")]
    pub count_connection_errors: bool,
}

/// serde 默认值：连续失败阈值 5。
fn default_failure_threshold() -> u32 {
    5
}

/// serde 默认值：半开恢复成功阈值 3。
fn default_success_threshold() -> u32 {
    3
}

/// serde 默认值：熔断保持 30 秒。
fn default_open_duration_secs() -> u64 {
    30
}

/// serde 默认值：视为失败的响应码。
fn default_breaker_statuses() -> Vec<u16> {
    vec![500, 502, 503, 504]
}

// ===========================================================================
// CORS —— 跨域策略
// ===========================================================================

/// CORS 策略配置。
///
/// # 安全约束
/// `allow_credentials = true` 与 `allow_origins = ["*"]` 不能同时出现：
/// 浏览器规范禁止 `Access-Control-Allow-Origin: *` 与
/// `Access-Control-Allow-Credentials: true` 组合（等价于允许任意站点
/// 携带用户凭据发起跨域请求）。validator 会拒绝该组合。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorsPolicyConfig {
    /// 策略唯一 ID，Route 通过 `cors_policy_id` 引用
    pub id: String,
    /// 人类可读名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用，默认 true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 允许的源（Origin）。`["*"]` 表示允许任意源。
    #[serde(default)]
    pub allow_origins: Vec<String>,
    /// 允许的请求方法，默认常用安全集合
    #[serde(default = "default_cors_methods")]
    pub allow_methods: Vec<String>,
    /// 允许的请求头。`["*"]` 表示允许任意请求头。
    #[serde(default)]
    pub allow_headers: Vec<String>,
    /// 允许暴露给浏览器的响应头
    #[serde(default)]
    pub expose_headers: Vec<String>,
    /// 是否允许携带凭据（Cookie / Authorization）
    #[serde(default)]
    pub allow_credentials: bool,
    /// 预检结果缓存时长（秒），默认 3600
    #[serde(default = "default_max_age_secs")]
    pub max_age_secs: u64,
}

/// serde 默认值：CORS 允许方法。
fn default_cors_methods() -> Vec<String> {
    vec![
        "GET".into(),
        "HEAD".into(),
        "POST".into(),
        "PUT".into(),
        "PATCH".into(),
        "DELETE".into(),
        "OPTIONS".into(),
    ]
}

/// serde 默认值：预检缓存 3600 秒。
fn default_max_age_secs() -> u64 {
    3_600
}

// ===========================================================================
// Transform —— 请求/响应 Header 转换策略
// ===========================================================================

/// Header 转换策略配置。
///
/// 同一个结构同时用于请求方向（`policies.request_transform`）与
/// 响应方向（`policies.response_transform`）：
///   - 请求方向：删除/设置/追加 header 后再转发给上游
///   - 响应方向：删除/设置/追加 header 后再返回给客户端
///
/// # 三类操作的语义
///   - `remove_headers`：按名称删除（大小写不敏感的 Header 名）
///   - `set_headers`：覆盖写入（已存在则替换）
///   - `add_headers`：追加写入（保留已存在值）
///
/// 执行顺序在 P2.5 实现中固定为：先 remove → 再 set → 最后 add，
/// 保证结果可预测（与配置书写顺序无关）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransformPolicyConfig {
    /// 策略唯一 ID，Route 通过 `request_transform_id` /
    /// `response_transform_id` 引用
    pub id: String,
    /// 人类可读名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用，默认 true
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 需要删除的 Header 名称列表
    #[serde(default)]
    pub remove_headers: Vec<String>,
    /// 需要覆盖写入的 Header
    #[serde(default)]
    pub set_headers: Vec<HeaderEntryConfig>,
    /// 需要追加写入的 Header
    #[serde(default)]
    pub add_headers: Vec<HeaderEntryConfig>,
}

/// Header 键值对。
///
/// `value` 支持简单变量占位（P2.5 实现时替换）：
///   - `${request_id}`：当前请求 ID
///   - `${client_ip}`：客户端 IP
///   - `${route_id}`：命中的路由 ID
///
/// 占位解析失败的替换结果为空字符串，不阻断请求。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderEntryConfig {
    /// Header 名称（必须是非空合法 HTTP 头名，validator 做基础校验）
    pub name: String,
    /// Header 值
    pub value: String,
}

// ===========================================================================
// WAF 策略（Phase 7）
// ===========================================================================

/// WAF 检查目标。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WafTarget {
    /// 路径（path）
    Path,
    /// 查询串（query）
    Query,
    /// 请求头值
    Headers,
    /// 请求体（需要 Runtime 预读；受 max_body_bytes 限制）
    Body,
}

/// WAF 命中后的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WafAction {
    /// 阻断：返回 403
    #[default]
    Block,
    /// 仅记录：放行但写审计日志与指标
    Detect,
}

/// WAF 规则灵敏度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WafSensitivity {
    /// 低：只匹配高置信度特征（默认）
    #[default]
    Low,
    /// 中：增加常见攻击特征
    Medium,
    /// 高：更激进的正则（可能误报）
    High,
}

/// WAF 策略配置。
///
/// 规则为内置 OWASP Core Rule Set 风格的特征集合（SQL 注入、XSS、
/// 路径遍历、命令注入），不依赖外部规则引擎。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WafPolicyConfig {
    /// 唯一 ID
    pub id: String,
    /// 人类可读名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 命中后的动作
    #[serde(default)]
    pub action: WafAction,
    /// 灵敏度
    #[serde(default)]
    pub sensitivity: WafSensitivity,
    /// 检查目标（默认 path + query + headers）
    #[serde(default = "default_waf_targets")]
    pub targets: Vec<WafTarget>,
    /// 单请求体检查上限（字节），默认 1 MiB
    #[serde(default = "default_waf_body_bytes")]
    pub max_body_bytes: u64,
}

/// 默认检查目标：path / query / headers。
fn default_waf_targets() -> Vec<WafTarget> {
    vec![WafTarget::Path, WafTarget::Query, WafTarget::Headers]
}

/// 默认 body 检查上限（1 MiB）。
fn default_waf_body_bytes() -> u64 {
    1024 * 1024
}

// ===========================================================================
// 配额策略（Phase 7）
// ===========================================================================

/// 配额周期。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum QuotaPeriod {
    /// 按天
    #[default]
    Daily,
    /// 按月（按 30 天计算）
    Monthly,
}

/// 配额维度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum QuotaScope {
    /// 按租户（默认）：同一租户的所有请求共享配额
    #[default]
    Tenant,
    /// 按消费者（认证身份主体）
    Consumer,
    /// 按路由
    Route,
}

/// 配额策略配置。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaPolicyConfig {
    /// 唯一 ID
    pub id: String,
    /// 人类可读名称
    #[serde(default)]
    pub name: Option<String>,
    /// 是否启用
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// 周期
    #[serde(default)]
    pub period: QuotaPeriod,
    /// 每周期允许的请求数
    pub limit: u64,
    /// 配额维度
    #[serde(default)]
    pub scope: QuotaScope,
    /// 计数后端：local（进程内）或 redis（全局限额）
    #[serde(default)]
    pub backend: RateLimitBackend,
    /// Redis 连接地址（backend=redis 时必填）
    #[serde(default)]
    pub redis_url: Option<String>,
    /// 阈值告警比例（0-100），达到后写警告日志；默认 80
    #[serde(default = "default_quota_warn_percent")]
    pub warn_at_percent: u8,
}

/// 默认告警阈值 80%。
fn default_quota_warn_percent() -> u8 {
    80
}

impl QuotaPolicyConfig {
    /// 周期长度（秒）。
    pub fn period_secs(&self) -> u64 {
        match self.period {
            QuotaPeriod::Daily => 86_400,
            QuotaPeriod::Monthly => 30 * 86_400,
        }
    }
}

// ===========================================================================
// 测试
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// 鉴权策略：JWT 变体可以正确反序列化，且 `type` 标签与 id 平级。
    ///
    /// 说明：测试用 JSON 文本，serde 走与 YAML 完全相同的反序列化路径
    /// （gateway-config 的 Figment 最终也是先转成 serde 的通用数据模型），
    /// 因此用 JSON 测试不引入 serde_yaml 依赖也能验证模型契约。
    #[test]
    fn auth_jwt_deserializes() {
        let text = r#"{
            "id": "jwt-main",
            "type": "jwt",
            "secret": "s3cr3t",
            "algorithms": ["HS256", "HS384"],
            "issuer": "gateway",
            "leeway_secs": 5
        }"#;
        let cfg: AuthPolicyConfig =
            serde_json::from_str(text).expect("jwt policy should deserialize");
        assert_eq!(cfg.id, "jwt-main");
        // enabled 未显式配置时默认为 true（安全策略不能因漏写字段而失效）
        assert!(cfg.enabled, "enabled 默认应为 true");
        match cfg.spec {
            AuthPolicySpec::Jwt {
                secret,
                algorithms,
                issuer,
                required,
                header_name,
                ..
            } => {
                assert_eq!(secret.as_deref(), Some("s3cr3t"));
                assert_eq!(algorithms, vec![JwtAlgorithm::Hs256, JwtAlgorithm::Hs384]);
                assert_eq!(issuer.as_deref(), Some("gateway"));
                assert!(required, "required 默认应为 true");
                assert_eq!(header_name, "Authorization");
            },
            other => panic!("unexpected variant: {other:?}"),
        }
    }

    /// 鉴权策略：非法算法名（例如 none / RS256）必须被拒绝。
    ///
    /// 这是"算法白名单"的第一道防线：非白名单算法在反序列化阶段就失败。
    #[test]
    fn auth_jwt_rejects_unknown_algorithm() {
        let text = r#"{
            "id": "jwt-bad",
            "type": "jwt",
            "secret": "s",
            "algorithms": ["none"]
        }"#;
        let result: Result<AuthPolicyConfig, _> = serde_json::from_str(text);
        assert!(result.is_err(), "`none` 不在算法白名单枚举内，必须反序列化失败");
    }

    /// 限流策略：默认算法为 token_bucket，默认键为 client_ip，默认故障模式 fail_closed
    #[test]
    fn rate_limit_defaults() {
        let text = r#"{"id": "rl", "rate": 100}"#;
        let cfg: RateLimitPolicyConfig = serde_json::from_str(text).expect("should parse");
        assert_eq!(cfg.algorithm, RateLimitAlgorithm::TokenBucket);
        assert_eq!(cfg.key.kind, RateLimitKeyKind::ClientIp);
        assert_eq!(cfg.window_secs, 1);
        assert_eq!(cfg.failure_mode, FailureMode::FailClosed);
        assert!(cfg.enabled);
    }

    /// 重试策略：默认只允许幂等方法，默认重试状态码为 502/503/504
    #[test]
    fn retry_defaults_are_idempotent_only() {
        let text = r#"{"id": "rt"}"#;
        let cfg: RetryPolicyConfig = serde_json::from_str(text).expect("should parse");
        assert_eq!(cfg.max_attempts, 3);
        assert!(cfg.retry_methods.iter().all(|m| !m.eq_ignore_ascii_case("POST")));
        assert_eq!(cfg.retry_statuses, vec![502, 503, 504]);
        assert_eq!(cfg.backoff.strategy, BackoffStrategy::Fixed);
        assert_eq!(cfg.max_body_bytes, 1024 * 1024);
    }

    /// 转换策略：Header 列表反序列化
    #[test]
    fn transform_deserializes() {
        let text = r#"{
            "id": "t1",
            "remove_headers": ["X-Internal"],
            "add_headers": [{"name": "X-Gateway", "value": "standard-web"}]
        }"#;
        let cfg: TransformPolicyConfig = serde_json::from_str(text).expect("should parse");
        assert_eq!(cfg.remove_headers, vec!["X-Internal".to_string()]);
        assert_eq!(cfg.add_headers.len(), 1);
        assert_eq!(cfg.add_headers[0].name, "X-Gateway");
    }

    /// CORS 策略：默认方法与预检缓存生效
    #[test]
    fn cors_defaults() {
        let text = r#"{"id": "c1", "allow_origins": ["*"]}"#;
        let cfg: CorsPolicyConfig = serde_json::from_str(text).expect("should parse");
        assert!(cfg.allow_methods.contains(&"GET".to_string()));
        assert_eq!(cfg.max_age_secs, 3_600);
        assert!(!cfg.allow_credentials, "凭据默认关闭");
    }
}
