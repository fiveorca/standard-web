//! 负载均衡器实现。
//!
//! 四个 P0 算法的实现：
//!   - `RoundRobinBalancer` —— 不考虑权重，轮流选
//!   - `WeightedRoundRobinBalancer` —— 按权重"轮数"分配轮询次数
//!   - `RandomBalancer` —— 均匀随机选
//!   - `WeightedRandomBalancer` —— 按权重概率分布随机选
//!
//! # 并发安全
//!
//! - Round Robin 用 `AtomicU64` 做全局计数器，fetch_add 原子性保证
//! - Weighted Round Robin 每个端点有自己的 `AtomicU32` current_weight
//! - Random 用 `std::sync::Mutex<Rng>` 保护 ThreadRng
//!
//! # 为什么输入是 `&[&Endpoint]` 而不是 `&[Endpoint]`
//!
//! gateway-core::LoadBalancer Trait 签名为：
//! ```rust,ignore
//! fn select<'a>(&self, healthy: &'a [&'a Endpoint]) -> Option<&'a Endpoint>;
//! ```
//! 这个签名让调用方负责过滤健康端点（这样 Balancer 不需要知道 HealthStatus）。
//! 所以输入是引用切片的切片，输出是原始引用。

use std::sync::atomic::{AtomicU64, Ordering};

use gateway_core::{Endpoint, LoadBalanceAlgorithm, LoadBalancer};

// ---------------------------------------------------------------------------
// RoundRobinBalancer
// ---------------------------------------------------------------------------

/// 轮询负载均衡器（不带权）。
///
/// 内部用 `AtomicU64` 计数器，每次 `select` 时 fetch_add(1)，然后用
/// counter % len 作为下标。并发场景下多个线程同时 fetch_add 也不会冲突——
/// Counter 会跳一些数（因为取模后下标一样会再被选到），但总体分布还是均匀的。
pub struct RoundRobinBalancer {
    /// 全局递增计数器，原子操作避免锁
    counter: AtomicU64,
}

impl RoundRobinBalancer {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

impl Default for RoundRobinBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for RoundRobinBalancer {
    fn select<'a>(&self, healthy: &'a [&'a Endpoint]) -> Option<&'a Endpoint> {
        if healthy.is_empty() {
            return None;
        }
        // Ordering::Relaxed —— 计数器不与其他数据同步，只要原子性就够了
        let count = self.counter.fetch_add(1, Ordering::Relaxed);
        let idx = (count as usize) % healthy.len();
        Some(healthy[idx])
    }

    fn algorithm(&self) -> LoadBalanceAlgorithm {
        LoadBalanceAlgorithm::RoundRobin
    }
}

// ---------------------------------------------------------------------------
// WeightedRoundRobinBalancer
// ---------------------------------------------------------------------------

/// 带权轮询负载均衡器。
///
/// 经典 WRR 算法（Nginx/Squid 都用这个）：
///
/// 对每个端点维护一个 `current_weight`（初始等于 `weight`）。
/// 每轮所有端点都被选 `current_weight` 次，选完的那个端点
/// current_weight 减 1；当所有端点的 current_weight 都减到 0，
/// 重置为原始权重。
///
/// 但这样需要端点集合不变化（否则权重重置逻辑会很复杂）。
/// Phase 1 中端点集合变化不频繁（健康状态变化时才调整），
/// 所以我们简化为：按权重比例分配"总轮数"。
///
/// **简化版 WRR 算法**（更简单且公平性可接受）：
/// ```text
/// 假设权重 [2, 3, 1]，总权重 6。
/// 第 1 轮：endpoint A 2 次，B 3 次，C 1 次，共 6 次
/// 第 2 轮：A 2 次，B 3 次，C 1 次...
/// ```
/// 用全局计数器 % 总权重，再累加找到下标。
/// 这样并发时也安全。
pub struct WeightedRoundRobinBalancer {
    counter: AtomicU64,
}

impl WeightedRoundRobinBalancer {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

impl Default for WeightedRoundRobinBalancer {
    fn default() -> Self {
        Self::new()
    }
}

impl LoadBalancer for WeightedRoundRobinBalancer {
    fn select<'a>(&self, healthy: &'a [&'a Endpoint]) -> Option<&'a Endpoint> {
        if healthy.is_empty() {
            return None;
        }
        let total_weight: u64 = healthy.iter().map(|e| e.weight as u64).sum();
        if total_weight == 0 {
            return None;
        }
        let pos = self.counter.fetch_add(1, Ordering::Relaxed) % total_weight;
        let mut accum: u64 = 0;
        for ep in healthy {
            accum += ep.weight as u64;
            if pos < accum {
                return Some(ep);
            }
        }
        // 所有 weight 之和刚好等于 total_weight，所以最后一个肯定命中
        // 走到这里是整数累加误差或最后一个端点 weight=0 的情况
        Some(healthy[healthy.len() - 1])
    }

    fn algorithm(&self) -> LoadBalanceAlgorithm {
        LoadBalanceAlgorithm::WeightedRoundRobin
    }
}

// ---------------------------------------------------------------------------
// RandomBalancer
// ---------------------------------------------------------------------------

/// 均匀随机负载均衡器。
///
/// rand::rngs::ThreadRng 是线程本地的，不需要加锁。
/// 用 rand::thread_rng() 在每次调用时获取线程本地 RNG。
pub struct RandomBalancer;

impl RandomBalancer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RandomBalancer {
    fn default() -> Self {
        Self
    }
}

impl LoadBalancer for RandomBalancer {
    fn select<'a>(&self, healthy: &'a [&'a Endpoint]) -> Option<&'a Endpoint> {
        if healthy.is_empty() {
            return None;
        }
        // rand::thread_rng() —— 返回当前线程的 ThreadRng（懒初始化）
        // gen_range 是 rand 的 trait method，需要 use rand::Rng
        use rand::Rng;
        let mut rng = rand::thread_rng();
        // gen_range(0..len) —— 半开区间，返回 [0, len-1] 中的随机整数
        let idx = rng.gen_range(0..healthy.len());
        Some(healthy[idx])
    }

    fn algorithm(&self) -> LoadBalanceAlgorithm {
        LoadBalanceAlgorithm::Random
    }
}

// ---------------------------------------------------------------------------
// WeightedRandomBalancer
// ---------------------------------------------------------------------------

/// 带权随机负载均衡器。
///
/// 算法：先算总权重 total，随机 [0, total)，累加找到第一个超过的端点。
/// 权重越大的端点，被选中的概率越高。
pub struct WeightedRandomBalancer;

impl WeightedRandomBalancer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WeightedRandomBalancer {
    fn default() -> Self {
        Self
    }
}

impl LoadBalancer for WeightedRandomBalancer {
    fn select<'a>(&self, healthy: &'a [&'a Endpoint]) -> Option<&'a Endpoint> {
        if healthy.is_empty() {
            return None;
        }
        let total_weight: u64 = healthy.iter().map(|e| e.weight as u64).sum();
        if total_weight == 0 {
            return None;
        }
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let pos = rng.gen_range(0..total_weight);
        let mut accum: u64 = 0;
        for ep in healthy {
            accum += ep.weight as u64;
            if pos < accum {
                return Some(ep);
            }
        }
        Some(healthy[healthy.len() - 1])
    }

    fn algorithm(&self) -> LoadBalanceAlgorithm {
        LoadBalanceAlgorithm::WeightedRandom
    }
}

// ---------------------------------------------------------------------------
// Balancer 构造函数（从 LoadBalanceAlgorithm 创建）
// ---------------------------------------------------------------------------

/// 根据 `LoadBalanceAlgorithm` 枚举构造对应的 LoadBalancer 实现。
///
/// 返回 `Box<dyn LoadBalancer>` 因为不同算法是不同类型。
pub fn make_balancer(algorithm: LoadBalanceAlgorithm) -> Box<dyn LoadBalancer> {
    match algorithm {
        LoadBalanceAlgorithm::RoundRobin => Box::new(RoundRobinBalancer::new()),
        LoadBalanceAlgorithm::WeightedRoundRobin => Box::new(WeightedRoundRobinBalancer::new()),
        LoadBalanceAlgorithm::Random => Box::new(RandomBalancer::new()),
        LoadBalanceAlgorithm::WeightedRandom => Box::new(WeightedRandomBalancer::new()),
        // P1 阶段：暂未实现的算法 fallback 到 Round Robin
        other => {
            tracing::warn!("algorithm {:?} not yet implemented, falling back to RoundRobin", other);
            Box::new(RoundRobinBalancer::new())
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_core::HealthStatus;

    #[allow(dead_code)]
    fn ep(weight: u32) -> Endpoint {
        Endpoint {
            runtime_id: "ep".into(),
            host: "127.0.0.1".into(),
            port: 9090,
            weight,
            zone: None,
            status: HealthStatus::Healthy,
        }
    }

    fn make_group(weights: &[u32]) -> Vec<Endpoint> {
        weights
            .iter()
            .enumerate()
            .map(|(i, w)| Endpoint {
                runtime_id: format!("ep-{i}"),
                host: "127.0.0.1".into(),
                port: 9000 + i as u16,
                weight: *w,
                zone: None,
                status: HealthStatus::Healthy,
            })
            .collect()
    }

    fn ref_group(group: &[Endpoint]) -> Vec<&Endpoint> {
        group.iter().collect()
    }

    #[test]
    fn round_robin_alternates() {
        let balancer = RoundRobinBalancer::new();
        let group = make_group(&[1, 1, 1]);
        let refs = ref_group(&group);
        // 轮 1: 0, 1, 2, 0, 1, 2
        assert_eq!(balancer.select(&refs).unwrap().runtime_id, "ep-0");
        assert_eq!(balancer.select(&refs).unwrap().runtime_id, "ep-1");
        assert_eq!(balancer.select(&refs).unwrap().runtime_id, "ep-2");
        assert_eq!(balancer.select(&refs).unwrap().runtime_id, "ep-0");
    }

    #[test]
    fn weighted_round_robin_respects_weights() {
        let balancer = WeightedRoundRobinBalancer::new();
        let group = make_group(&[2, 1]);
        let refs = ref_group(&group);
        // 总权重 3，应该是 0, 0, 1, 0, 0, 1...
        let mut counts = [0u32; 2];
        for _ in 0..300 {
            let chosen = balancer.select(&refs).unwrap();
            if chosen.runtime_id == "ep-0" {
                counts[0] += 1;
            } else {
                counts[1] += 1;
            }
        }
        // ep-0 的权重是 ep-1 的 2 倍，所以次数应接近 2:1
        let ratio = counts[0] as f64 / counts[1] as f64;
        assert!((ratio - 2.0).abs() < 0.2, "ratio should be ~2.0, got {ratio}");
    }

    #[test]
    fn weighted_random_respects_weights() {
        let balancer = WeightedRandomBalancer::new();
        let group = make_group(&[3, 1]);
        let refs = ref_group(&group);
        let mut counts = [0u32; 2];
        for _ in 0..10_000 {
            let chosen = balancer.select(&refs).unwrap();
            if chosen.runtime_id == "ep-0" {
                counts[0] += 1;
            } else {
                counts[1] += 1;
            }
        }
        let ratio = counts[0] as f64 / counts[1] as f64;
        assert!((ratio - 3.0).abs() < 0.3, "ratio should be ~3.0, got {ratio}");
    }

    #[test]
    fn balancer_returns_none_on_empty() {
        let balancer = RoundRobinBalancer::new();
        let empty: Vec<&Endpoint> = vec![];
        assert!(balancer.select(&empty).is_none());
    }

    #[test]
    fn make_balancer_constructs_correct_type() {
        let rr = make_balancer(LoadBalanceAlgorithm::RoundRobin);
        assert_eq!(rr.algorithm(), LoadBalanceAlgorithm::RoundRobin);
        let wrr = make_balancer(LoadBalanceAlgorithm::WeightedRoundRobin);
        assert_eq!(wrr.algorithm(), LoadBalanceAlgorithm::WeightedRoundRobin);
    }
}
