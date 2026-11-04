//! Token Bucket 限流器。
//!
//! 算法语义：
//!   - 桶容量 = `burst`（突发上限）
//!   - 每毫秒补充 `rate` 个令牌（rate 是"每秒请求数"）
//!   - 请求到来时扣 1 个令牌；桶空则拒绝
//!
//! # 并发安全
//! 用 `tokio::sync::Mutex` 保护桶状态（`tokens` + `last_refill`）。
//! 同一计数键的并发请求会串行化到该锁上，保证令牌计数精确。
//!
//! # 为什么不用无锁原子操作
//! 令牌补充依赖"当前时间"计算，无锁方案需要 CAS 循环且容易出现
//! 多线程同时 refill 导致超发；Mutex 的临界区极小（几次算术运算），
//! 实际开销可忽略。

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

/// 单个计数键的令牌桶状态。
#[derive(Debug)]
struct Bucket {
    /// 当前剩余令牌数（浮点以支持毫秒级补充的精度）
    tokens: f64,
    /// 上次补充时间
    last_refill: Instant,
    /// 桶容量（最大令牌数）
    capacity: f64,
    /// 每毫秒补充速率（rate / 1000.0）
    refill_per_ms: f64,
}

/// Token Bucket 限流器。
///
/// 内部按"计数键"分桶，每桶独立维护令牌数。
#[derive(Debug)]
pub struct TokenBucketLimiter {
    /// 计数键 → 桶状态
    buckets: Mutex<std::collections::HashMap<String, Bucket>>,
    /// 每秒补充的令牌数（策略配置）
    rate: u64,
    /// 桶容量（突发上限）
    burst: u64,
}

impl TokenBucketLimiter {
    /// 构造限流器。
    ///
    /// 参数：
    /// - `rate`：每秒允许的请求数（> 0）
    /// - `burst`：突发上限；未配置时按 `rate` 取值（即不允许突发）
    ///
    /// 返回 `Err` 当 `rate == 0`（无意义的限流策略）。
    pub fn new(rate: u64, burst: Option<u64>) -> Result<Arc<Self>, String> {
        if rate == 0 {
            return Err("rate must be greater than 0".into());
        }
        let burst = burst.unwrap_or(rate);
        Ok(Arc::new(Self {
            buckets: Mutex::new(std::collections::HashMap::new()),
            rate,
            burst,
        }))
    }

    /// 尝试为指定键扣减 1 个令牌。
    ///
    /// 参数：
    /// - `key`：计数键（client_ip / header value / route_id 等）
    ///
    /// 返回：
    /// - `true`：允许通过
    /// - `false`：限流触发，应返回 429
    pub async fn try_acquire(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut buckets = self.buckets.lock().await;

        let bucket = buckets.entry(key.to_string()).or_insert_with(|| Bucket {
            tokens: self.burst as f64,
            last_refill: now,
            capacity: self.burst as f64,
            refill_per_ms: self.rate as f64 / 1000.0,
        });

        // 1) 按 elapsed 补充令牌（封顶到 capacity）
        let elapsed = now.duration_since(bucket.last_refill);
        let refill = elapsed.as_millis() as f64 * bucket.refill_per_ms;
        bucket.tokens = (bucket.tokens + refill).min(bucket.capacity);
        bucket.last_refill = now;

        // 2) 扣减：有足够令牌则放行，否则拒绝
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// 计算距离下次可放行还需多少秒（用于 `Retry-After`）。
    ///
    /// 参数：
    /// - `key`：计数键
    ///
    /// 返回 `None` 表示当前已有可用令牌（不应触发限流）。
    pub async fn retry_after_secs(&self, key: &str) -> Option<u64> {
        let buckets = self.buckets.lock().await;

        let bucket = buckets.get(key)?;
        if bucket.tokens >= 1.0 {
            return None;
        }

        // 先按"上次补充以来的时间"把令牌数折算到当前，再计算缺口
        let elapsed_ms = bucket.last_refill.elapsed().as_millis() as f64;
        let current_tokens: f64 =
            (bucket.tokens + elapsed_ms * bucket.refill_per_ms).min(bucket.capacity);
        if current_tokens >= 1.0 {
            return None;
        }

        // 需要补充到 1.0 个令牌；refill_per_ms 与 tokens 都是 f64，
        // 这里显式标注避免编译器推断为未知浮点类型
        let deficit: f64 = 1.0 - current_tokens;
        let ms_needed = (deficit / bucket.refill_per_ms).ceil() as u64;
        // `div_ceil` 是整数向上取整除法（Rust 1.73+ 稳定）
        Some(ms_needed.div_ceil(1000))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    /// 辅助：构造 rate=2/s, burst=3 的限流器
    fn limiter() -> Arc<TokenBucketLimiter> {
        TokenBucketLimiter::new(2, Some(3)).expect("valid limiter")
    }

    /// 突发内放行，超出突发后限流
    #[tokio::test]
    async fn burst_then_limited() {
        let limiter = limiter();
        // 突发 3 个全部放行
        assert!(limiter.try_acquire("k1").await);
        assert!(limiter.try_acquire("k1").await);
        assert!(limiter.try_acquire("k1").await);
        // 第 4 个限流
        assert!(!limiter.try_acquire("k1").await);
    }

    /// 令牌补充后恢复放行
    #[tokio::test]
    async fn refill_allows_after_wait() {
        let limiter = limiter();
        // 打空桶
        assert!(limiter.try_acquire("k1").await);
        assert!(limiter.try_acquire("k1").await);
        assert!(limiter.try_acquire("k1").await);
        assert!(!limiter.try_acquire("k1").await);

        // 等 600ms：rate=2/s → 补充 1.2 个令牌
        sleep(Duration::from_millis(600)).await;
        assert!(limiter.try_acquire("k1").await);
    }

    /// 不同键独立计数
    #[tokio::test]
    async fn keys_are_independent() {
        let limiter = limiter();
        assert!(limiter.try_acquire("k1").await);
        assert!(limiter.try_acquire("k1").await);
        assert!(limiter.try_acquire("k1").await);
        assert!(!limiter.try_acquire("k1").await);
        // k2 是全新桶，仍允许
        assert!(limiter.try_acquire("k2").await);
    }

    /// retry_after_secs 在限流时返回正值
    #[tokio::test]
    async fn retry_after_is_positive_when_limited() {
        let limiter = limiter();
        for _ in 0..3 {
            assert!(limiter.try_acquire("k1").await);
        }
        assert!(!limiter.try_acquire("k1").await);
        let retry = limiter.retry_after_secs("k1").await;
        assert!(retry.is_some());
        assert!(retry.unwrap() >= 1);
    }

    /// rate=0 必须编译失败
    #[tokio::test]
    async fn zero_rate_is_rejected() {
        assert!(TokenBucketLimiter::new(0, None).is_err());
    }
}
