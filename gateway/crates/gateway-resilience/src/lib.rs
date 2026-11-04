//! `gateway-resilience` —— 韧性能力（Phase 2 / P2.6）。
//!
//! # 分层位置
//!
//! ```text
//! gateway-runtime（组装插件链）
//!        │
//!        ▼
//! gateway-resilience ──▶ gateway-plugin（Plugin / PluginChain / Registry）
//!        │              gateway-core  （Time/Retry/CircuitBreaker policy config）
//!        │              gateway-common（ErrorCode / RequestId）
//!        ▼
//! （无下游依赖）
//! ```
//!
//! # 三类策略，两种消费方式
//!
//! | 策略 | 编译产物 | 消费方式 |
//! |---|---|---|
//! | Timeout | `CompiledTimeoutPolicy` | Runtime/Proxy 的 HTTP 客户端直接用 |
//! | Retry | `CompiledRetryPolicy` | Runtime/Proxy 的重试循环直接用 |
//! | Circuit Breaker | `CircuitBreakerRegistry`（Arc 共享熔断器实例） | 插件链两实例消费 |
//!
//! Timeout 和 Retry 虽然编译好了，但 Phase 2 下暂不由插件链执行——
//! 插件无法包裹上游 HTTP 调用。Runtime/Proxy 接入时会把它们直接注入
//! HTTP 客户端参数。Circuit Breaker 则天然是**前置拦截 + 后置记录**
//! 的两阶段组件，完全契合插件链架构。
//!
//! # 熔断器状态机
//!
//! ```text
//!  Closed ──(连续失败 ≥ failure_threshold)──▶ Open
//!    ▲                                              │
//!    │                                    (open_duration 到期)
//!    │                                              ▼
//!    └──(HalfOpen 连续成功 ≥ success_threshold)── HalfOpen
//!                (HalfOpen 任一次失败 → 立刻回 Open)
//! ```
//!
//! # 熔断键的维度
//! Phase 2 下熔断器实例按**策略 ID** 索引。也就是说：
//!   - Route A → cb1，Route B → cb1 → 共享同一个熔断器
//!   - Route A → cb1，Route B → cb2 → 独立
//!
//! 每个策略实例内部是 `tokio::sync::Mutex` 保护的三态状态机，
//! 并发请求串行化到同一锁上，保证状态转换精确且线程安全。

pub mod circuit_breaker;
pub mod plugin;
pub mod policy;

// 扁平 re-export
pub use circuit_breaker::{CircuitBreaker, CircuitBreakerRegistry, CircuitState};
pub use plugin::{CbDirection, CircuitBreakerPlugin, PLUGIN_NAME};
pub use policy::{
    CompiledBackoff, CompiledResiliencePolicies, CompiledRetryPolicy,
    CompiledTimeoutPolicy,
};
