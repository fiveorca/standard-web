//! prelude —— gateway-core 常用类型统一 re-export。

pub use crate::models::{
    Endpoint, EndpointConfig, HeaderMatch, QueryMatch, RouteConfig, ServiceConfig, Upstream,
    UpstreamConfig,
};
pub use crate::request_context::RequestContext;
pub use crate::traits::{
    DiscoveryError, LoadBalancer, ServiceDiscoveryProvider, UpstreamError, UpstreamManager,
};
pub use crate::types::{DiscoveryHealth, HealthStatus, LoadBalanceAlgorithm, PathType};
pub use crate::RuntimeSnapshot;
