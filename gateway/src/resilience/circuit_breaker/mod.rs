//! 熔断器。
//!
//! 采用滑动窗口统计失败率与慢调用率，支持 Closed / Open / Half-Open 三态。
//! 临界区只包含内存操作，不包含任何 `.await`，因此使用 `std::sync::Mutex` 是安全的。

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::config::model::{CircuitBreakerConfig, FallbackConfig};
use crate::error::GatewayError;
use crate::observability::metrics::Metrics;

/// 熔断状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

impl BreakerState {
    pub fn as_str(&self) -> &'static str {
        match self {
            BreakerState::Closed => "closed",
            BreakerState::Open => "open",
            BreakerState::HalfOpen => "half_open",
        }
    }

    pub fn metric_value(&self) -> i64 {
        match self {
            BreakerState::Closed => 0,
            BreakerState::HalfOpen => 1,
            BreakerState::Open => 2,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Sample {
    at: Instant,
    success: bool,
    slow: bool,
}

struct Inner {
    state: BreakerState,
    opened_at: Option<Instant>,
    half_open_calls: u32,
    half_open_successes: u32,
    samples: VecDeque<Sample>,
}

/// 熔断器。
pub struct CircuitBreaker {
    key: String,
    config: CircuitBreakerConfig,
    inner: Mutex<Inner>,
    metrics: Arc<Metrics>,
}

impl CircuitBreaker {
    pub fn new(key: String, config: CircuitBreakerConfig, metrics: Arc<Metrics>) -> Self {
        let state = BreakerState::Closed;
        metrics.set_circuit_breaker_state(&key, state.metric_value());
        Self {
            key,
            config,
            inner: Mutex::new(Inner {
                state,
                opened_at: None,
                half_open_calls: 0,
                half_open_successes: 0,
                samples: VecDeque::new(),
            }),
            metrics,
        }
    }

    pub fn config(&self) -> &CircuitBreakerConfig {
        &self.config
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn state(&self) -> BreakerState {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        self.refresh_state(&mut inner);
        inner.state
    }

    fn refresh_state(&self, inner: &mut Inner) {
        if inner.state == BreakerState::Open {
            if let Some(opened_at) = inner.opened_at {
                if opened_at.elapsed() >= self.config.open_duration {
                    inner.state = BreakerState::HalfOpen;
                    inner.half_open_calls = 0;
                    inner.half_open_successes = 0;
                    self.metrics.set_circuit_breaker_state(
                        &self.key,
                        BreakerState::HalfOpen.metric_value(),
                    );
                }
            }
        }
    }

    /// 判断是否允许请求通过。
    pub fn allow(&self) -> Result<(), GatewayError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        self.refresh_state(&mut inner);
        match inner.state {
            BreakerState::Closed => Ok(()),
            BreakerState::Open => Err(GatewayError::CircuitOpen(self.key.clone())),
            BreakerState::HalfOpen => {
                if inner.half_open_calls < self.config.half_open_max_calls {
                    inner.half_open_calls += 1;
                    Ok(())
                } else {
                    Err(GatewayError::CircuitOpen(self.key.clone()))
                }
            }
        }
    }

    /// 记录一次成功调用。
    pub fn on_success(&self, duration: Duration) {
        let slow = duration >= self.config.slow_call_duration;
        self.record(true, slow);
    }

    /// 记录一次失败调用。
    pub fn on_failure(&self, duration: Duration) {
        let slow = duration >= self.config.slow_call_duration;
        self.record(false, slow);
    }

    fn record(&self, success: bool, slow: bool) {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let now = Instant::now();

        if inner.state == BreakerState::HalfOpen {
            if success {
                inner.half_open_successes += 1;
                if inner.half_open_successes >= self.config.half_open_success_threshold.max(1) {
                    inner.state = BreakerState::Closed;
                    inner.opened_at = None;
                    inner.half_open_calls = 0;
                    inner.half_open_successes = 0;
                    inner.samples.clear();
                    self.metrics
                        .set_circuit_breaker_state(&self.key, BreakerState::Closed.metric_value());
                }
            } else {
                self.open(&mut inner, now);
            }
            inner.samples.push_back(Sample {
                at: now,
                success,
                slow,
            });
            return;
        }

        inner.samples.push_back(Sample {
            at: now,
            success,
            slow,
        });
        self.prune(&mut inner, now);

        if inner.state == BreakerState::Closed {
            let total = inner.samples.len();
            if total >= self.config.minimum_requests.max(1) {
                let failures = inner.samples.iter().filter(|s| !s.success).count();
                let slow_calls = inner.samples.iter().filter(|s| s.slow).count();
                let failure_rate = failures as f64 * 100.0 / total as f64;
                let slow_rate = slow_calls as f64 * 100.0 / total as f64;
                if failure_rate >= self.config.failure_rate_threshold
                    || slow_rate >= self.config.slow_call_rate_threshold
                {
                    self.open(&mut inner, now);
                }
            }
        }
    }

    fn open(&self, inner: &mut Inner, now: Instant) {
        inner.state = BreakerState::Open;
        inner.opened_at = Some(now);
        inner.half_open_calls = 0;
        inner.half_open_successes = 0;
        self.metrics
            .set_circuit_breaker_state(&self.key, BreakerState::Open.metric_value());
        tracing::warn!(breaker = %self.key, "circuit breaker opened");
    }

    fn prune(&self, inner: &mut Inner, now: Instant) {
        let window = self.config.window_duration;
        while let Some(front) = inner.samples.front() {
            if now.duration_since(front.at) > window {
                inner.samples.pop_front();
            } else {
                break;
            }
        }
        while inner.samples.len() > self.config.sliding_window_size.max(1) {
            inner.samples.pop_front();
        }
    }

    /// 熔断时使用的降级响应配置。
    pub fn fallback(&self) -> Option<&FallbackConfig> {
        self.config.fallback.as_ref()
    }

    /// 统计信息（管理 API）。
    pub fn stats(&self) -> BreakerStats {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        self.refresh_state(&mut inner);
        let total = inner.samples.len();
        let failures = inner.samples.iter().filter(|s| !s.success).count();
        let slow = inner.samples.iter().filter(|s| s.slow).count();
        BreakerStats {
            key: self.key.clone(),
            state: inner.state.as_str().to_string(),
            total_samples: total,
            failure_rate: if total == 0 {
                0.0
            } else {
                failures as f64 * 100.0 / total as f64
            },
            slow_call_rate: if total == 0 {
                0.0
            } else {
                slow as f64 * 100.0 / total as f64
            },
            failure_threshold: self.config.failure_rate_threshold,
            open_duration_secs: self.config.open_duration.as_secs_f64(),
        }
    }
}

/// 熔断器统计。
#[derive(Debug, Clone, serde::Serialize)]
pub struct BreakerStats {
    pub key: String,
    pub state: String,
    pub total_samples: usize,
    pub failure_rate: f64,
    pub slow_call_rate: f64,
    pub failure_threshold: f64,
    pub open_duration_secs: f64,
}

/// 熔断器注册表：按路由 / 上游服务隔离。
pub struct CircuitBreakerRegistry {
    breakers: DashMap<String, Arc<CircuitBreaker>>,
    metrics: Arc<Metrics>,
}

impl CircuitBreakerRegistry {
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            breakers: DashMap::new(),
            metrics,
        }
    }

    /// 获取或创建熔断器；配置变化时会替换实例。
    pub fn get_or_create(&self, key: &str, config: &CircuitBreakerConfig) -> Arc<CircuitBreaker> {
        if let Some(existing) = self.breakers.get(key) {
            if existing.config() == config {
                return existing.clone();
            }
        }
        let breaker = Arc::new(CircuitBreaker::new(
            key.to_string(),
            config.clone(),
            self.metrics.clone(),
        ));
        self.breakers.insert(key.to_string(), breaker.clone());
        breaker
    }

    pub fn stats(&self) -> Vec<BreakerStats> {
        self.breakers
            .iter()
            .map(|entry| entry.value().stats())
            .collect()
    }

    pub fn clear(&self) {
        self.breakers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            enabled: true,
            failure_rate_threshold: 50.0,
            minimum_requests: 4,
            sliding_window_size: 10,
            window_duration: Duration::from_secs(60),
            open_duration: Duration::from_millis(100),
            half_open_max_calls: 2,
            half_open_success_threshold: 2,
            slow_call_duration: Duration::from_secs(10),
            ..Default::default()
        }
    }

    fn breaker() -> CircuitBreaker {
        let metrics = Metrics::new().unwrap();
        CircuitBreaker::new("test".into(), config(), metrics)
    }

    #[test]
    fn opens_after_threshold() {
        let cb = breaker();
        assert_eq!(cb.state(), BreakerState::Closed);
        for _ in 0..4 {
            cb.allow().unwrap();
            cb.on_failure(Duration::from_millis(1));
        }
        assert_eq!(cb.state(), BreakerState::Open);
        assert!(cb.allow().is_err());
    }

    #[test]
    fn half_open_then_recover() {
        let cb = breaker();
        for _ in 0..4 {
            cb.allow().unwrap();
            cb.on_failure(Duration::from_millis(1));
        }
        assert_eq!(cb.state(), BreakerState::Open);

        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(cb.state(), BreakerState::HalfOpen);
        assert!(cb.allow().is_ok());
        cb.on_success(Duration::from_millis(1));
        assert!(cb.allow().is_ok());
        cb.on_success(Duration::from_millis(1));
        assert_eq!(cb.state(), BreakerState::Closed);
    }

    #[test]
    fn half_open_failure_reopens() {
        let cb = breaker();
        for _ in 0..4 {
            cb.allow().unwrap();
            cb.on_failure(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(120));
        assert_eq!(cb.state(), BreakerState::HalfOpen);
        cb.allow().unwrap();
        cb.on_failure(Duration::from_millis(1));
        assert_eq!(cb.state(), BreakerState::Open);
    }

    #[test]
    fn slow_calls_open_breaker() {
        let mut cfg = config();
        cfg.slow_call_duration = Duration::from_millis(10);
        cfg.slow_call_rate_threshold = 50.0;
        let metrics = Metrics::new().unwrap();
        let cb = CircuitBreaker::new("slow".into(), cfg, metrics);
        for _ in 0..4 {
            cb.allow().unwrap();
            cb.on_success(Duration::from_millis(50));
        }
        assert_eq!(cb.state(), BreakerState::Open);
    }
}
