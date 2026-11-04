//! 熔断器状态机。
//!
//! # 状态机
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
//! # 并发安全
//! 用 `tokio::sync::Mutex` 保护状态（`state` + 计数器 + 时间戳）。
//! 同一熔断键的并发请求会串行化到该锁上，保证状态转换精确。
//!
//! 熔断触发后所有并发请求都会看到 OPEN 状态并被快速拒绝——
//! 这正是熔断器的意义：**失败时快速失败，而不是排队等慢上游**。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tokio::time::Instant;

/// 熔断器状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// 正常工作
    Closed,
    /// 熔断打开，快速拒绝
    Open,
    /// 半开，允许探测性请求
    HalfOpen,
}

impl CircuitState {
    pub fn as_str(self) -> &'static str {
        match self {
            CircuitState::Closed => "closed",
            CircuitState::Open => "open",
            CircuitState::HalfOpen => "half_open",
        }
    }
}

/// 单个熔断器的内部状态（受 Mutex 保护）。
#[derive(Debug)]
struct BreakerState {
    state: CircuitState,
    /// Closed 下连续失败计数；HalfOpen 下连续成功计数
    consecutive: u32,
    /// OPEN 状态进入时间；用于判断 open_duration 是否到期
    entered_open_at: Option<Instant>,
}

/// 熔断器实例。
///
/// 每个策略一个实例（key = 策略 ID），保护同一个上游的所有路由。
#[derive(Debug)]
pub struct CircuitBreaker {
    state: Mutex<BreakerState>,
    /// 连续失败阈值 → Open
    failure_threshold: u32,
    /// HalfOpen 下连续成功阈值 → Closed
    success_threshold: u32,
    /// Open 持续时间
    open_duration: Duration,
    /// 视为"失败"的上游 HTTP 状态码集合（空集默认 5xx 全量）
    failure_statuses: Vec<u16>,
}

impl CircuitBreaker {
    /// 构造熔断器。
    ///
    /// 参数与 `CircuitBreakerPolicyConfig` 对齐，Duration 在调用方换算好。
    ///
    /// 参数：
    /// - `failure_threshold`：连续失败多少次触发 Open
    /// - `success_threshold`：HalfOpen 下连续成功多少次恢复 Closed
    /// - `open_duration`：Open 状态持续多久后进入 HalfOpen
    /// - `failure_statuses`：哪些 HTTP 状态码算"失败"；若为空则默认 5xx 全量
    pub fn new(
        failure_threshold: u32,
        success_threshold: u32,
        open_duration: Duration,
        failure_statuses: Vec<u16>,
    ) -> Self {
        Self {
            state: Mutex::new(BreakerState {
                state: CircuitState::Closed,
                consecutive: 0,
                entered_open_at: None,
            }),
            failure_threshold,
            success_threshold,
            open_duration,
            failure_statuses,
        }
    }

    /// 判断给定 HTTP 状态码是否属于"失败"（应由调用方在 record_result 前决定）。
    ///
    /// 规则：
    /// - 如果 `failure_statuses` 非空 → 仅列表内状态码算失败
    /// - 如果 `failure_statuses` 为空（兜底）→ 5xx 全量算失败
    pub fn is_failure_status(&self, status: u16) -> bool {
        if self.failure_statuses.is_empty() {
            status >= 500
        } else {
            self.failure_statuses.contains(&status)
        }
    }

    /// 请求进入时检查状态。
    ///
    /// 返回：
    /// - `true`：放行（Closed 或 HalfOpen）
    /// - `false`：熔断打开，应返回 503
    ///
    /// **重要**：在 OPEN 状态下同时检查是否应进入 HalfOpen（到期自动转换）。
    pub async fn allow_request(&self) -> bool {
        let mut state = self.state.lock().await;

        match state.state {
            CircuitState::Closed => true,

            CircuitState::Open => {
                // 判断是否到期：到期则转入 HalfOpen，放行本次（作为探测请求）
                if let Some(entered) = state.entered_open_at {
                    if entered.elapsed() >= self.open_duration {
                        state.state = CircuitState::HalfOpen;
                        state.consecutive = 0; // HalfOpen 下计数成功
                        state.entered_open_at = None;
                        tracing::info!(
                            target: "resilience",
                            "circuit breaker transitioned Open → HalfOpen (probe allowed)"
                        );
                        true
                    } else {
                        false
                    }
                } else {
                    // 不可能：Open 状态必须有 entered_open_at；兜底拒绝
                    false
                }
            },

            // HalfOpen 下所有请求放行，但每次结果都会改变状态
            CircuitState::HalfOpen => true,
        }
    }

    /// 记录请求结果（成功 / 失败）。
    ///
    /// 参数：
    /// - `success`：上游请求是否成功（由调用方根据状态码/连接错误决定）
    pub async fn record_result(&self, success: bool) {
        let mut state = self.state.lock().await;

        match state.state {
            CircuitState::Closed => {
                if success {
                    // Closed 下成功：清零连续失败计数
                    state.consecutive = 0;
                } else {
                    state.consecutive += 1;
                    if state.consecutive >= self.failure_threshold {
                        // 达到阈值 → 进入 Open
                        state.state = CircuitState::Open;
                        state.consecutive = 0;
                        state.entered_open_at = Some(Instant::now());
                        tracing::warn!(
                            target: "resilience",
                            consecutive_failures = self.failure_threshold,
                            open_duration = ?self.open_duration,
                            "circuit breaker transitioned Closed → Open"
                        );
                    }
                }
            },

            CircuitState::Open => {
                // Open 下不应有请求到达（allow_request 已拦截）；
                // 但如果真的发生（如锁竞争导致的时序问题），忽略
            },

            CircuitState::HalfOpen => {
                if success {
                    state.consecutive += 1;
                    if state.consecutive >= self.success_threshold {
                        state.state = CircuitState::Closed;
                        state.consecutive = 0;
                        tracing::info!(
                            target: "resilience",
                            consecutive_successes = self.success_threshold,
                            "circuit breaker transitioned HalfOpen → Closed"
                        );
                    }
                } else {
                    // HalfOpen 下任一次失败 → 立刻回 Open，计时重置
                    state.state = CircuitState::Open;
                    state.consecutive = 0;
                    state.entered_open_at = Some(Instant::now());
                    tracing::warn!(
                        target: "resilience",
                        "circuit breaker transitioned HalfOpen → Open (probe failed)"
                    );
                }
            },
        }
    }

    /// 查询当前状态（调试/管理接口用）。
    pub async fn current_state(&self) -> CircuitState {
        self.state.lock().await.state
    }
}

/// 熔断器注册表（按策略 ID 索引）。
///
/// 与 `CompiledRateLimitPolicies` / `CompiledTransformPolicies` 同构：
/// 启动期编译出策略 → 请求路径上按 ID 取出对应熔断器。
#[derive(Debug, Default)]
pub struct CircuitBreakerRegistry {
    /// 策略 ID → 熔断器实例
    pub by_id: HashMap<String, Arc<CircuitBreaker>>,
}

impl CircuitBreakerRegistry {
    /// 构造空注册表。
    pub fn new() -> Self {
        Self {
            by_id: HashMap::new(),
        }
    }

    /// 注册一个熔断器。
    ///
    /// 参数：
    /// - `id`：策略 ID
    /// - `failure_threshold` / `success_threshold` / `open_duration`：熔断参数
    /// - `failure_statuses`：视为"失败"的 HTTP 状态码列表（空则默认 5xx）
    pub fn register(
        &mut self,
        id: String,
        failure_threshold: u32,
        success_threshold: u32,
        open_duration: Duration,
        failure_statuses: Vec<u16>,
    ) {
        self.by_id.insert(
            id,
            Arc::new(CircuitBreaker::new(
                failure_threshold,
                success_threshold,
                open_duration,
                failure_statuses,
            )),
        );
    }

    /// 按策略 ID 查找熔断器。
    pub fn get(&self, id: &str) -> Option<Arc<CircuitBreaker>> {
        self.by_id.get(id).cloned()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    /// 辅助：构造默认熔断器（failure=3, success=2, open=100ms）
    /// failure_statuses 为空 → 默认 5xx 全量算失败
    fn breaker() -> Arc<CircuitBreaker> {
        Arc::new(CircuitBreaker::new(
            3,
            2,
            Duration::from_millis(100),
            Vec::new(),
        ))
    }

    /// 辅助：构造自定义 failure_statuses 的熔断器
    fn breaker_with_statuses(statuses: Vec<u16>) -> Arc<CircuitBreaker> {
        Arc::new(CircuitBreaker::new(
            3,
            2,
            Duration::from_millis(100),
            statuses,
        ))
    }

    /// Closed 下连续成功一直放行
    #[tokio::test]
    async fn closed_allows_requests() {
        let b = breaker();
        for _ in 0..5 {
            assert!(b.allow_request().await);
            b.record_result(true).await;
        }
        assert_eq!(b.current_state().await, CircuitState::Closed);
    }

    /// 连续失败达到阈值 → Open
    #[tokio::test]
    async fn consecutive_failures_open_circuit() {
        let b = breaker();
        // 3 次连续失败
        for _ in 0..3 {
            assert!(b.allow_request().await);
            b.record_result(false).await;
        }
        assert_eq!(b.current_state().await, CircuitState::Open);
        // 被 Open 后应拒绝
        assert!(!b.allow_request().await);
    }

    /// Closed 下成功会清零连续失败计数
    #[tokio::test]
    async fn success_resets_failure_count() {
        let b = breaker();
        b.allow_request().await;
        b.record_result(false).await;
        b.allow_request().await;
        b.record_result(false).await;
        // 成功 → 清零
        b.allow_request().await;
        b.record_result(true).await;
        // 再 2 次失败才到阈值（之前已清零）
        b.allow_request().await;
        b.record_result(false).await;
        b.allow_request().await;
        b.record_result(false).await;
        // 仍 Closed（2 < 3）
        assert_eq!(b.current_state().await, CircuitState::Closed);
    }

    /// Open 到期后 → HalfOpen，放行探测请求
    #[tokio::test]
    async fn open_transitions_to_halfopen_on_expiry() {
        let b = breaker();
        // 打满阈值
        for _ in 0..3 {
            b.allow_request().await;
            b.record_result(false).await;
        }
        assert_eq!(b.current_state().await, CircuitState::Open);

        // 等过 open_duration
        sleep(Duration::from_millis(110)).await;

        // 下一次 allow_request 会触发 Open → HalfOpen 转换
        assert!(b.allow_request().await);
        assert_eq!(b.current_state().await, CircuitState::HalfOpen);
    }

    /// HalfOpen 下连续成功达阈值 → Closed
    #[tokio::test]
    async fn halfopen_success_recovers() {
        let b = breaker();
        // 先打满失败 → Open
        for _ in 0..3 {
            b.allow_request().await;
            b.record_result(false).await;
        }
        sleep(Duration::from_millis(110)).await;
        // 进入 HalfOpen
        b.allow_request().await;

        // 2 次连续成功 → Closed
        b.record_result(true).await;
        b.allow_request().await;
        b.record_result(true).await;
        assert_eq!(b.current_state().await, CircuitState::Closed);
    }

    /// HalfOpen 下任一次失败 → 立刻回 Open
    #[tokio::test]
    async fn halfopen_failure_reopens() {
        let b = breaker();
        for _ in 0..3 {
            b.allow_request().await;
            b.record_result(false).await;
        }
        sleep(Duration::from_millis(110)).await;
        b.allow_request().await;

        // 探测请求失败 → 立刻回 Open
        b.record_result(false).await;
        assert_eq!(b.current_state().await, CircuitState::Open);
    }

    /// failure_statuses 为空时，默认 5xx 全量算失败
    #[test]
    fn empty_statuses_default_to_5xx() {
        let b = breaker();
        assert!(b.is_failure_status(500));
        assert!(b.is_failure_status(503));
        assert!(b.is_failure_status(599));
        assert!(!b.is_failure_status(200));
        assert!(!b.is_failure_status(404));
        assert!(!b.is_failure_status(301));
    }

    /// failure_statuses 非空时，严格按列表匹配
    #[test]
    fn explicit_statuses_only_match_listed() {
        // 只认 502 和 503
        let b = breaker_with_statuses(vec![502, 503]);
        assert!(b.is_failure_status(502));
        assert!(b.is_failure_status(503));
        assert!(!b.is_failure_status(500)); // 不在列表里
        assert!(!b.is_failure_status(504));
        assert!(!b.is_failure_status(200));
    }
}
