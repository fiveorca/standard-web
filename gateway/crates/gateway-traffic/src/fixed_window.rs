//! Fixed Window 限流器。
//!
//! 算法语义：
//!   - 每个时间窗口（`window_secs` 秒）内允许 `rate` 个请求
//!   - 窗口边界由"首次请求时间"决定（滑动窗口起点）
//!   - 窗口内计数达到 `rate` 后拒绝，直到下一个窗口开始
//!
//! # 与 Token Bucket 的区别
//!   - Token Bucket：允许突发（桶容量内立即放行），之后按恒定速率补充
//!   - Fixed Window：严格按窗口计数，窗口边界重置，无突发概念
//!
//! # 并发安全
//! 用 `tokio::sync::Mutex` 保护窗口状态（`window_start` + `count`）。
//! 同一计数键的并发请求会串行化到该锁上，保证窗口边界判断精确。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

/// 单个计数键的窗口状态。
#[derive(Debug)]
struct Window {
    /// 当前窗口开始时间
    start: Instant,
    /// 当前窗口内已计数请求数
    count: u64,
}

/// Fixed Window 限流器。
#[derive(Debug)]
pub struct FixedWindowLimiter {
    /// 计数键 → 窗口状态
    windows: Mutex<HashMap<String, Window>>,
    /// 每个窗口允许的请求数
    rate: u64,
    /// 窗口长度（秒）
    window_secs: u64,
}

impl FixedWindowLimiter {
    /// 构造限流器。
    ///
    /// 参数：
    /// - `rate`：每个窗口允许的请求数（> 0）
    /// - `window_secs`：窗口长度（秒，> 0）
    ///
    /// 返回 `Err` 当任一参数为 0（无意义的限流策略）。
    pub fn new(rate: u64, window_secs: u64) -> Result<Arc<Self>, String> {
        if rate == 0 {
            return Err("rate must be greater than 0".into());
        }
        if window_secs == 0 {
            return Err("window_secs must be greater than 0".into());
        }
        Ok(Arc::new(Self {
            windows: Mutex::new(HashMap::new()),
            rate,
            window_secs,
        }))
    }

    /// 尝试为指定键计数 1 次。
    ///
    /// 参数：
    /// - `key`：计数键
    ///
    /// 返回：
    /// - `true`：允许通过
    /// - `false`：限流触发，应返回 429
    pub async fn try_acquire(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut windows = self.windows.lock().await;

        let window = windows.entry(key.to_string()).or_insert_with(|| Window {
            start: now,
            count: 0,
        });

        // 1) 检查窗口是否过期：过期则重置
        let window_duration = std::time::Duration::from_secs(self.window_secs);
        if now.duration_since(window.start) >= window_duration {
            window.start = now;
            window.count = 0;
        }

        // 2) 计数：未达上限则放行，否则拒绝
        if window.count < self.rate {
            window.count += 1;
            true
        } else {
            false
        }
    }

    /// 计算距离下一个窗口还需多少秒（用于 `Retry-After`）。
    ///
    /// 参数：
    /// - `key`：计数键
    ///
    /// 返回 `None` 表示当前窗口未满（不应触发限流）。
    pub async fn retry_after_secs(&self, key: &str) -> Option<u64> {
        let now = Instant::now();
        let windows = self.windows.lock().await;

        let window = windows.get(key)?;
        if window.count < self.rate {
            return None;
        }

        let elapsed = now.duration_since(window.start);
        let window_duration = std::time::Duration::from_secs(self.window_secs);
        if elapsed >= window_duration {
            return None; // 窗口已过期，下一个请求会重置
        }

        let remaining = window_duration - elapsed;
        Some(remaining.as_secs().max(1)) // 至少返回 1 秒
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    /// 辅助：构造 rate=3, window=1s 的限流器
    fn limiter() -> Arc<FixedWindowLimiter> {
        FixedWindowLimiter::new(3, 1).expect("valid limiter")
    }

    /// 窗口内放行，超出后限流
    #[tokio::test]
    async fn window_limit_enforced() {
        let limiter = limiter();
        assert!(limiter.try_acquire("k1").await);
        assert!(limiter.try_acquire("k1").await);
        assert!(limiter.try_acquire("k1").await);
        // 第 4 个限流
        assert!(!limiter.try_acquire("k1").await);
    }

    /// 窗口过期后重置计数
    #[tokio::test]
    async fn window_resets_after_expiry() {
        let limiter = limiter();
        assert!(limiter.try_acquire("k1").await);
        assert!(limiter.try_acquire("k1").await);
        assert!(limiter.try_acquire("k1").await);
        assert!(!limiter.try_acquire("k1").await);

        // 等 1.1 秒：窗口过期
        sleep(Duration::from_millis(1100)).await;
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
        // k2 是全新窗口，仍允许
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

    /// rate=0 或 window=0 必须编译失败
    #[tokio::test]
    async fn zero_rate_or_window_is_rejected() {
        assert!(FixedWindowLimiter::new(0, 1).is_err());
        assert!(FixedWindowLimiter::new(1, 0).is_err());
    }
}
