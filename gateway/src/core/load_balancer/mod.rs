//! 负载均衡。
//!
//! 所有实现都是无锁或近似无锁的，可以在高并发下安全共享。
//! 负载均衡器只依赖候选实例的权重与在途请求数，不感知服务发现细节。

use std::sync::atomic::{AtomicU64, Ordering};

use rand::Rng;

use crate::config::model::LbStrategy;

/// 候选实例视图。
#[derive(Debug, Clone, Copy)]
pub struct CandidateView {
    pub weight: u32,
    pub in_flight: usize,
}

/// 负载均衡器接口。
pub trait LoadBalancer: Send + Sync {
    fn strategy(&self) -> LbStrategy;
    /// 返回被选中候选的下标。
    fn pick(&self, candidates: &[CandidateView]) -> Option<usize>;
}

/// 根据策略创建负载均衡器。
pub fn create(strategy: LbStrategy) -> Box<dyn LoadBalancer> {
    match strategy {
        LbStrategy::RoundRobin => Box::new(RoundRobin::default()),
        LbStrategy::Random => Box::new(Random),
        LbStrategy::WeightedRoundRobin => Box::new(WeightedRoundRobin::default()),
        LbStrategy::WeightedRandom => Box::new(WeightedRandom),
        LbStrategy::LeastConnections => Box::new(LeastConnections::default()),
        LbStrategy::PowerOfTwoChoices => Box::new(PowerOfTwoChoices),
    }
}

fn total_weight(candidates: &[CandidateView]) -> u64 {
    candidates
        .iter()
        .map(|c| u64::from(c.weight.max(1)))
        .sum::<u64>()
}

/// 轮询。
#[derive(Debug, Default)]
pub struct RoundRobin {
    counter: AtomicU64,
}

impl LoadBalancer for RoundRobin {
    fn strategy(&self) -> LbStrategy {
        LbStrategy::RoundRobin
    }

    fn pick(&self, candidates: &[CandidateView]) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % candidates.len() as u64;
        Some(idx as usize)
    }
}

/// 随机。
#[derive(Debug, Default)]
pub struct Random;

impl LoadBalancer for Random {
    fn strategy(&self) -> LbStrategy {
        LbStrategy::Random
    }

    fn pick(&self, candidates: &[CandidateView]) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        let mut rng = rand::thread_rng();
        Some(rng.gen_range(0..candidates.len()))
    }
}

/// 加权轮询（按累计权重切片）。
#[derive(Debug, Default)]
pub struct WeightedRoundRobin {
    counter: AtomicU64,
}

impl LoadBalancer for WeightedRoundRobin {
    fn strategy(&self) -> LbStrategy {
        LbStrategy::WeightedRoundRobin
    }

    fn pick(&self, candidates: &[CandidateView]) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        let total = total_weight(candidates);
        if total == 0 {
            return Some(0);
        }
        let slot = self.counter.fetch_add(1, Ordering::Relaxed) % total;
        let mut cumulative = 0u64;
        for (idx, candidate) in candidates.iter().enumerate() {
            cumulative += u64::from(candidate.weight.max(1));
            if slot < cumulative {
                return Some(idx);
            }
        }
        Some(candidates.len() - 1)
    }
}

/// 加权随机。
#[derive(Debug, Default)]
pub struct WeightedRandom;

impl LoadBalancer for WeightedRandom {
    fn strategy(&self) -> LbStrategy {
        LbStrategy::WeightedRandom
    }

    fn pick(&self, candidates: &[CandidateView]) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        let total = total_weight(candidates);
        if total == 0 {
            return Some(0);
        }
        let mut rng = rand::thread_rng();
        let mut slot = rng.gen_range(0..total);
        for (idx, candidate) in candidates.iter().enumerate() {
            let weight = u64::from(candidate.weight.max(1));
            if slot < weight {
                return Some(idx);
            }
            slot -= weight;
        }
        Some(candidates.len() - 1)
    }
}

/// 最少连接数（相同连接数时轮询）。
#[derive(Debug, Default)]
pub struct LeastConnections {
    counter: AtomicU64,
}

impl LoadBalancer for LeastConnections {
    fn strategy(&self) -> LbStrategy {
        LbStrategy::LeastConnections
    }

    fn pick(&self, candidates: &[CandidateView]) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        let min = candidates.iter().map(|c| c.in_flight).min().unwrap_or(0);
        let ties: Vec<usize> = candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| c.in_flight == min)
            .map(|(idx, _)| idx)
            .collect();
        let pick = self.counter.fetch_add(1, Ordering::Relaxed) as usize % ties.len();
        Some(ties[pick])
    }
}

/// Power of Two Choices：随机取两个，选择在途请求更少的一个。
#[derive(Debug, Default)]
pub struct PowerOfTwoChoices;

impl LoadBalancer for PowerOfTwoChoices {
    fn strategy(&self) -> LbStrategy {
        LbStrategy::PowerOfTwoChoices
    }

    fn pick(&self, candidates: &[CandidateView]) -> Option<usize> {
        if candidates.is_empty() {
            return None;
        }
        if candidates.len() == 1 {
            return Some(0);
        }
        let mut rng = rand::thread_rng();
        let a = rng.gen_range(0..candidates.len());
        let mut b = rng.gen_range(0..candidates.len());
        if a == b {
            b = (b + 1) % candidates.len();
        }
        let ratio = |c: &CandidateView| c.in_flight as f64 / f64::from(c.weight.max(1));
        if ratio(&candidates[a]) <= ratio(&candidates[b]) {
            Some(a)
        } else {
            Some(b)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn candidates(weights: &[u32]) -> Vec<CandidateView> {
        weights
            .iter()
            .map(|w| CandidateView {
                weight: *w,
                in_flight: 0,
            })
            .collect()
    }

    #[test]
    fn round_robin_cycles() {
        let lb = RoundRobin::default();
        let c = candidates(&[1, 1, 1]);
        let picks: Vec<usize> = (0..6).map(|_| lb.pick(&c).unwrap()).collect();
        assert_eq!(picks, vec![0, 1, 2, 0, 1, 2]);
    }

    #[test]
    fn weighted_round_robin_distribution() {
        let lb = WeightedRoundRobin::default();
        let c = candidates(&[3, 1]);
        let mut counts = HashMap::new();
        for _ in 0..400 {
            *counts.entry(lb.pick(&c).unwrap()).or_insert(0) += 1;
        }
        assert_eq!(counts.get(&0), Some(&300));
        assert_eq!(counts.get(&1), Some(&100));
    }

    #[test]
    fn least_connections_prefers_idle() {
        let lb = LeastConnections::default();
        let c = vec![
            CandidateView {
                weight: 1,
                in_flight: 5,
            },
            CandidateView {
                weight: 1,
                in_flight: 0,
            },
        ];
        for _ in 0..10 {
            assert_eq!(lb.pick(&c), Some(1));
        }
    }

    #[test]
    fn p2c_picks_less_loaded() {
        let lb = PowerOfTwoChoices;
        let c = vec![
            CandidateView {
                weight: 1,
                in_flight: 100,
            },
            CandidateView {
                weight: 1,
                in_flight: 0,
            },
        ];
        let mut picked_low = 0;
        for _ in 0..200 {
            if lb.pick(&c) == Some(1) {
                picked_low += 1;
            }
        }
        assert!(picked_low > 100, "p2c should prefer the idle instance");
    }

    #[test]
    fn empty_candidates_return_none() {
        assert!(RoundRobin::default().pick(&[]).is_none());
    }
}
