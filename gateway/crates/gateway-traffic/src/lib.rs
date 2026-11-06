//! `gateway-traffic` —— 流量治理能力（Phase 2 / P2.4）。
//!
//! # 分层位置
//!
//! ```text
//! gateway-runtime（组装插件链）
//!        │
//!        ▼
//! gateway-traffic ──▶ gateway-plugin（Plugin / PluginChain / Registry）
//!        │              gateway-core  （RateLimitPolicyConfig / RouteConfig）
//!        │              gateway-common（ErrorCode / RequestId）
//!        ▼
//! （无下游依赖：本 crate 不发起网络请求、不读写配置源）
//! ```
//!
//! # 提供的限流算法
//!
//! | 算法 | 语义 | 突发支持 | 适用场景 |
//! |---|---|---|---|
//! | Token Bucket | 恒定速率补充令牌，桶容量内允许突发 | 是 | 平滑限流 |
//! | Fixed Window | 严格按窗口计数，窗口边界重置 | 否 | 简单配额 |
//!
//! # 计数键维度
//!
//! | 键类型 | 来源 | 说明 |
//! |---|---|---|
//! | `client_ip` | `ctx.client_ip` | 按客户端 IP 限流（最常见） |
//! | `global` | 固定 `"global"` | 全局限流（保护整条链路） |
//! | `header` | 指定 Header 值 | 按 API Key / 租户 ID 限流 |
//! | `route` | `route.id` | 按路由限流（同一路由共享计数器） |
//!
//! # 故障模式
//!
//! - `FailClosed`（默认）：限流器故障时拒绝请求（安全优先）
//! - `FailOpen`：限流器故障时放行请求（可用性优先）
//!
//! Phase 2 为进程内内存实现，故障几乎不可能；`failure_mode` 为 Phase 3
//! 接入 Redis 预留。

pub mod fixed_window;
pub mod key;
pub mod plugin;
pub mod policy;
pub mod quota;
pub mod redis_limiter;
pub mod token_bucket;

// 扁平 re-export
pub use plugin::{RateLimitPlugin, RATE_LIMIT_PLUGIN_NAME};
pub use policy::{CompiledRateLimitPolicies, CompiledRateLimitPolicy, RateLimiter};
pub use quota::{CompiledQuotaPolicies, QuotaDecision, QuotaPlugin, QUOTA_PLUGIN_NAME};
pub use redis_limiter::{RateLimitOutcome, RedisLimiter};
