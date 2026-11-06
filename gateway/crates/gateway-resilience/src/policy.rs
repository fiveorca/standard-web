//! 韧性策略编译：Timeout / Retry / CircuitBreaker。
//!
//! # 为什么三类策略都在这里
//! - Timeout / Retry 是 HTTP 客户端参数，Phase 2 下暂不由插件链执行
//!   （插件无法包裹上游 HTTP 调用），但 Runtime 消费它们时需要预编译。
//! - Circuit Breaker 是有状态组件（见 `circuit_breaker` 模块），
//!   编译后注册到 `CircuitBreakerRegistry`，插件按策略 ID 取用。
//!
//! 统一编译入口的好处：同一个 `CompiledResiliencePolicies` 里
//! 可以检查 "Route 引用的 resilience 策略是否都存在"。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use gateway_core::{CircuitBreakerPolicyConfig, RetryPolicyConfig, TimeoutPolicyConfig};

use crate::circuit_breaker::{CircuitBreaker, CircuitBreakerRegistry};

// ---------------------------------------------------------------------------
// 已编译的 Timeout 策略（HTTP 客户端直接使用）
// ---------------------------------------------------------------------------

/// 已编译的超时策略（纯数据结构，Runtime/Proxy 读取字段即可）。
#[derive(Debug, Clone)]
pub struct CompiledTimeoutPolicy {
    pub id: String,
    pub name: Option<String>,
    pub enabled: bool,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub idle_timeout: Option<Duration>,
}

impl CompiledTimeoutPolicy {
    /// 从配置编译。
    pub fn compile(config: &TimeoutPolicyConfig) -> Result<Self, String> {
        if config.id.is_empty() {
            return Err("id must not be empty".into());
        }
        if config.connect_timeout_ms == 0 {
            return Err("connect_timeout_ms must be greater than 0".into());
        }
        if config.request_timeout_ms == 0 {
            return Err("request_timeout_ms must be greater than 0".into());
        }
        if let Some(idle) = config.idle_timeout_ms {
            if idle == 0 {
                return Err("idle_timeout_ms must be greater than 0".into());
            }
        }

        Ok(Self {
            id: config.id.clone(),
            name: config.name.clone(),
            enabled: config.enabled,
            connect_timeout: Duration::from_millis(config.connect_timeout_ms),
            request_timeout: Duration::from_millis(config.request_timeout_ms),
            idle_timeout: config.idle_timeout_ms.map(Duration::from_millis),
        })
    }
}

// ---------------------------------------------------------------------------
// 已编译的 Retry 策略（HTTP 客户端直接使用）
// ---------------------------------------------------------------------------

/// 已编译的重试策略（纯数据结构，Runtime/Proxy 读取字段即可）。
///
/// 注意：`max_attempts` 包含首次请求，即 `max_attempts = 3` 表示
/// "首次 + 最多 2 次重试"。RetryPolicyConfig 的 validator 已确保
/// `retry_methods` 只含幂等方法、`retry_statuses` 不含 4xx。
#[derive(Debug, Clone)]
pub struct CompiledRetryPolicy {
    pub id: String,
    pub name: Option<String>,
    pub enabled: bool,
    /// 包含首次的最大尝试次数（≥ 1）
    pub max_attempts: u32,
    /// 允许重试的 Method 集合（小写规范化）
    pub retry_methods: Vec<String>,
    /// 触发重试的 HTTP 状态码集合
    pub retry_statuses: Vec<u16>,
    /// 连接错误是否重试
    pub retry_on_connection_error: bool,
    /// 退避参数（base_delay_ms / max_delay_ms 已是 Duration）
    pub backoff: CompiledBackoff,
    /// 允许缓冲重放的请求体上限（超过此值不重试）
    pub max_body_bytes: u64,
}

/// 编译后的退避配置（Duration 替换 u64 毫秒）。
#[derive(Debug, Clone, Copy)]
pub struct CompiledBackoff {
    pub strategy: gateway_core::BackoffStrategy,
    pub base_delay: Duration,
    pub max_delay: Duration,
}

impl CompiledRetryPolicy {
    /// 从配置编译。
    pub fn compile(config: &RetryPolicyConfig) -> Result<Self, String> {
        if config.id.is_empty() {
            return Err("id must not be empty".into());
        }
        if config.max_attempts == 0 {
            return Err("max_attempts must be greater than 0".into());
        }

        // Method 集合统一小写规范化，查询时直接 lower_eq
        let retry_methods: Vec<String> =
            config.retry_methods.iter().map(|m| m.to_ascii_uppercase()).collect();

        // 退避参数
        let backoff = CompiledBackoff {
            strategy: config.backoff.strategy,
            base_delay: Duration::from_millis(config.backoff.base_delay_ms),
            max_delay: Duration::from_millis(config.backoff.max_delay_ms),
        };

        Ok(Self {
            id: config.id.clone(),
            name: config.name.clone(),
            enabled: config.enabled,
            max_attempts: config.max_attempts,
            retry_methods,
            retry_statuses: config.retry_statuses.clone(),
            retry_on_connection_error: config.retry_on_connection_error,
            backoff,
            max_body_bytes: config.max_body_bytes,
        })
    }

    /// 判断给定 HTTP 状态码是否应触发重试。
    pub fn should_retry_status(&self, status: u16) -> bool {
        self.retry_statuses.contains(&status)
    }

    /// 判断给定 Method 是否允许重试。
    pub fn should_retry_method(&self, method: &str) -> bool {
        let upper = method.to_ascii_uppercase();
        self.retry_methods.iter().any(|m| m == &upper)
    }

    /// 计算第 n 次重试的退避延迟（n 从 1 开始，即首次重试 delay）。
    ///
    /// 参数：
    /// - `attempt`：重试序号（1 = 第一次重试）
    pub fn retry_delay(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        match self.backoff.strategy {
            gateway_core::BackoffStrategy::Fixed => self.backoff.base_delay,
            gateway_core::BackoffStrategy::Exponential => {
                // base * 2^(attempt-1)，封顶 max；shift 结果天然是 u64
                // u64 最大只能 shift 63 位，超过直接封顶（反正之后都会被 max_delay 截断）
                let exp = if attempt > 64 {
                    u64::MAX
                } else {
                    1u64 << (attempt - 1)
                };
                // saturating_mul 避免大数乘溢出：溢出时返回 u64::MAX，随后被 min 截断
                let base_ms = self.backoff.base_delay.as_millis() as u64;
                let ms = base_ms.saturating_mul(exp);
                let capped = ms.min(self.backoff.max_delay.as_millis() as u64);
                Duration::from_millis(capped)
            },
        }
    }
}

// ---------------------------------------------------------------------------
// 三类策略的统一集合
// ---------------------------------------------------------------------------

/// 全部韧性策略的编译结果。
#[derive(Debug, Default)]
pub struct CompiledResiliencePolicies {
    pub timeouts: HashMap<String, CompiledTimeoutPolicy>,
    pub retries: HashMap<String, CompiledRetryPolicy>,
    pub breakers: CircuitBreakerRegistry,
}

impl CompiledResiliencePolicies {
    /// 编译全部三类策略。
    ///
    /// 任一子集合编译失败都会让整个函数返回 `Err`（不做部分生效）。
    pub fn compile(
        timeouts: &[TimeoutPolicyConfig],
        retries: &[RetryPolicyConfig],
        breakers: &[CircuitBreakerPolicyConfig],
    ) -> Result<Self, String> {
        let mut timeouts_map = HashMap::new();
        for (idx, config) in timeouts.iter().enumerate() {
            if timeouts_map.contains_key(&config.id) {
                return Err(format!("duplicate timeout policy id '{}'", config.id));
            }
            let compiled = CompiledTimeoutPolicy::compile(config)
                .map_err(|reason| format!("timeout[{idx}] ('{}'): {reason}", config.id))?;
            timeouts_map.insert(config.id.clone(), compiled);
        }

        let mut retries_map = HashMap::new();
        for (idx, config) in retries.iter().enumerate() {
            if retries_map.contains_key(&config.id) {
                return Err(format!("duplicate retry policy id '{}'", config.id));
            }
            let compiled = CompiledRetryPolicy::compile(config)
                .map_err(|reason| format!("retry[{idx}] ('{}'): {reason}", config.id))?;
            retries_map.insert(config.id.clone(), compiled);
        }

        let mut breaker_registry = CircuitBreakerRegistry::new();
        for (idx, config) in breakers.iter().enumerate() {
            if breaker_registry.by_id.contains_key(&config.id) {
                return Err(format!("duplicate circuit breaker policy id '{}'", config.id));
            }
            if config.id.is_empty() {
                return Err(format!("circuit_breaker[{idx}].id must not be empty"));
            }
            if config.failure_threshold == 0 {
                return Err(format!(
                    "circuit_breaker[{idx}] ('{}').failure_threshold must be > 0",
                    config.id
                ));
            }
            if config.success_threshold == 0 {
                return Err(format!(
                    "circuit_breaker[{idx}] ('{}').success_threshold must be > 0",
                    config.id
                ));
            }
            if config.open_duration_secs == 0 {
                return Err(format!(
                    "circuit_breaker[{idx}] ('{}').open_duration_secs must be > 0",
                    config.id
                ));
            }

            breaker_registry.register(
                config.id.clone(),
                config.failure_threshold,
                config.success_threshold,
                Duration::from_secs(config.open_duration_secs),
                // failure_statuses 原样传入熔断器；为空时熔断器内部默认 5xx
                config.failure_statuses.clone(),
            );
        }

        Ok(Self {
            timeouts: timeouts_map,
            retries: retries_map,
            breakers: breaker_registry,
        })
    }

    pub fn get_timeout(&self, id: &str) -> Option<&CompiledTimeoutPolicy> {
        self.timeouts.get(id)
    }
    pub fn get_retry(&self, id: &str) -> Option<&CompiledRetryPolicy> {
        self.retries.get(id)
    }
    pub fn get_breaker(&self, id: &str) -> Option<Arc<CircuitBreaker>> {
        self.breakers.get(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_core::{BackoffConfig, BackoffStrategy};

    /// 辅助：最小 TimeoutPolicyConfig
    fn timeout(id: &str) -> TimeoutPolicyConfig {
        TimeoutPolicyConfig {
            id: id.into(),
            name: None,
            enabled: true,
            connect_timeout_ms: 5000,
            request_timeout_ms: 10000,
            idle_timeout_ms: None,
        }
    }

    /// 辅助：最小 RetryPolicyConfig
    fn retry(id: &str) -> RetryPolicyConfig {
        RetryPolicyConfig {
            id: id.into(),
            name: None,
            enabled: true,
            max_attempts: 3,
            retry_methods: vec!["GET".into()],
            retry_statuses: vec![502, 503, 504],
            retry_on_connection_error: true,
            backoff: BackoffConfig {
                strategy: BackoffStrategy::Exponential,
                base_delay_ms: 100,
                max_delay_ms: 1000,
            },
            max_body_bytes: 1024 * 1024,
        }
    }

    /// 辅助：最小 CircuitBreakerPolicyConfig
    fn cb(id: &str) -> CircuitBreakerPolicyConfig {
        CircuitBreakerPolicyConfig {
            id: id.into(),
            name: None,
            enabled: true,
            failure_threshold: 5,
            success_threshold: 3,
            open_duration_secs: 30,
            failure_statuses: vec![500, 502, 503, 504],
            count_connection_errors: true,
        }
    }

    /// 三类策略一起编译成功
    #[test]
    fn compile_all_types() {
        let result =
            CompiledResiliencePolicies::compile(&[timeout("t1")], &[retry("r1")], &[cb("cb1")]);
        let policies = result.expect("should compile");
        assert!(policies.get_timeout("t1").is_some());
        assert!(policies.get_retry("r1").is_some());
        assert!(policies.get_breaker("cb1").is_some());
    }

    /// 重复 ID 拒绝（跨类型独立，同类互斥）
    #[test]
    fn duplicate_ids_in_same_kind_rejected() {
        assert!(CompiledResiliencePolicies::compile(&[timeout("dup"), timeout("dup")], &[], &[])
            .is_err());

        assert!(
            CompiledResiliencePolicies::compile(&[], &[retry("dup"), retry("dup")], &[]).is_err()
        );

        assert!(CompiledResiliencePolicies::compile(&[], &[], &[cb("dup"), cb("dup")]).is_err());
    }

    /// Retry 的 status/method 判断正确
    #[test]
    fn retry_helpers() {
        let policy = CompiledRetryPolicy::compile(&retry("r1")).expect("compile");
        assert!(policy.should_retry_status(502));
        assert!(!policy.should_retry_status(200));
        assert!(!policy.should_retry_status(404));

        assert!(policy.should_retry_method("GET"));
        assert!(policy.should_retry_method("get")); // 小写也能匹配（查询时转大写）
        assert!(!policy.should_retry_method("POST"));
    }

    /// 指数退避计算正确：100 → 200 → 400 → 800 → 1000（封顶）
    #[test]
    fn exponential_backoff_capped() {
        let policy = CompiledRetryPolicy::compile(&retry("r1")).expect("compile");
        let ms = |attempt| policy.retry_delay(attempt).as_millis() as u64;
        assert_eq!(ms(1), 100);
        assert_eq!(ms(2), 200);
        assert_eq!(ms(3), 400);
        assert_eq!(ms(4), 800);
        assert_eq!(ms(5), 1000); // 封顶
        assert_eq!(ms(100), 1000);
    }

    /// Fixed 退避每次都一样
    #[test]
    fn fixed_backoff() {
        let mut cfg = retry("r1");
        cfg.backoff = BackoffConfig {
            strategy: BackoffStrategy::Fixed,
            base_delay_ms: 150,
            max_delay_ms: 1000,
        };
        let policy = CompiledRetryPolicy::compile(&cfg).expect("compile");
        let ms = |attempt| policy.retry_delay(attempt).as_millis() as u64;
        assert_eq!(ms(1), 150);
        assert_eq!(ms(2), 150);
        assert_eq!(ms(10), 150);
    }

    /// Circuit Breaker 的阈值/时长为 0 被拒绝
    #[test]
    fn zero_threshold_rejected() {
        let mut cfg = cb("cb1");
        cfg.failure_threshold = 0;
        assert!(CompiledResiliencePolicies::compile(&[], &[], &[cfg]).is_err());
    }
}
