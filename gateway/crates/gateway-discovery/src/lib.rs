//! # gateway-discovery
//!
//! 服务发现 Provider 实现集合。
//!
//! Phase 1 只实现 StaticDiscoveryProvider（端点从 YAML 配置静态加载）。
//!
//! 后续扩展：
//!   - DnsDiscoveryProvider（定期解析 DNS SRV 记录）
//!   - K8sDiscoveryProvider（监听 EndpointSlice，Phase 6）
//!   - ConsulDiscoveryProvider / NacosDiscoveryProvider（P2）
//!
//! 所有 Provider 都实现 `ServiceDiscoveryProvider` Trait（定义在 gateway-core）。
//! 上游消费者只依赖 Trait，不依赖具体实现，所以可以无代价切换。

#![allow(clippy::needless_doctest_main)]

pub mod dns_provider;
pub mod k8s_provider;
pub mod static_provider;

pub use dns_provider::{
    DnsDiscoveryConfig, DnsDiscoveryProvider, DnsQueryKind,
};
pub use k8s_provider::{K8sDiscoveryConfig, K8sDiscoveryProvider, SharedK8sProvider};
pub use static_provider::StaticDiscoveryProvider;
