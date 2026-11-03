//! # gateway-upstream
//!
//! 上游端点注册表与负载均衡。
//!
//! 职责：
//!   1. 为每个 Upstream 创建并维护一个 LoadBalancer 实例
//!   2. 维护端点运行时健康状态（供健康检查和上游请求失败回调更新）
//!   3. 提供 `pick_endpoint(upstream_id)` 供代理层挑选实例
//!
//! # 模块
//!
//! - [`balancer`]：LoadBalancer Trait 的四个实现（RR / WRR / Random / WeightedRandom）
//! - [`registry`]：UpstreamRegistry——集中管理所有 Upstream 的运行时状态

#![allow(clippy::needless_doctest_main)]

pub mod balancer;
pub mod registry;

pub use balancer::{
    RandomBalancer, RoundRobinBalancer, WeightedRandomBalancer, WeightedRoundRobinBalancer,
};
pub use registry::UpstreamRegistry;
