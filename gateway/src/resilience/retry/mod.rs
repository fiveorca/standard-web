//! 重试策略。

use std::time::Duration;

use http::Method;
use rand::Rng;

use crate::config::model::RetryConfig;

/// 判断方法是否幂等（默认可安全重试）。
pub fn is_idempotent(method: &Method) -> bool {
    matches!(
        *method,
        Method::GET | Method::HEAD | Method::OPTIONS | Method::TRACE | Method::PUT | Method::DELETE
    )
}

/// 请求是否允许重试。
///
/// 默认只对幂等请求重试；非幂等请求（如 POST）必须显式开启
/// `allow_non_idempotent`，且请求体必须已完整缓冲。
pub fn is_retryable_request(method: &Method, config: &RetryConfig) -> bool {
    is_idempotent(method) || config.allow_non_idempotent
}

/// 计算第 `attempt` 次重试前的退避时间（attempt 从 1 开始）。
pub fn backoff_delay(attempt: u32, config: &RetryConfig) -> Duration {
    let multiplier = config.backoff_multiplier.max(1.0);
    let base =
        config.backoff_initial.as_secs_f64() * multiplier.powi(attempt.saturating_sub(1) as i32);
    let capped = base.min(config.backoff_max.as_secs_f64());
    let jitter = if config.jitter {
        let mut rng = rand::thread_rng();
        rng.gen_range(0.5..1.0)
    } else {
        1.0
    };
    Duration::from_secs_f64((capped * jitter).max(0.0))
}

/// 状态码是否触发重试。
pub fn should_retry_status(status: u16, config: &RetryConfig) -> bool {
    config.retry_on_status.contains(&status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotency_rules() {
        assert!(is_idempotent(&Method::GET));
        assert!(is_idempotent(&Method::PUT));
        assert!(!is_idempotent(&Method::POST));
        let config = RetryConfig {
            enabled: true,
            ..Default::default()
        };
        assert!(!is_retryable_request(&Method::POST, &config));
        let config = RetryConfig {
            enabled: true,
            allow_non_idempotent: true,
            ..Default::default()
        };
        assert!(is_retryable_request(&Method::POST, &config));
    }

    #[test]
    fn backoff_is_capped() {
        let config = RetryConfig {
            backoff_initial: Duration::from_millis(100),
            backoff_max: Duration::from_millis(300),
            backoff_multiplier: 10.0,
            jitter: false,
            ..Default::default()
        };
        assert_eq!(backoff_delay(1, &config), Duration::from_millis(100));
        assert_eq!(backoff_delay(3, &config), Duration::from_millis(300));
    }
}
