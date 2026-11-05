//! # gateway-core
//!
//! Gateway 核心领域模型与运行时抽象。
//!
//! 本 crate 是 Gateway 的"心脏"——它定义了所有模块都要依赖的：
//!   1. 领域模型（`RouteConfig`、`ServiceConfig`、`UpstreamConfig`、`Endpoint` 等）
//!   2. 运行时 Trait（`ServiceDiscoveryProvider`、`LoadBalancer`）
//!   3. 请求在 Pipeline 中携带的上下文（`RequestContext`）
//!   4. 通用枚举（`PathType`、`LoadBalanceAlgorithm`、`HealthStatus`）
//!
//! ## 架构约束（必须遵守）
//!
//!   - 本 crate **不依赖**任何 IO 框架（tokio/hyper/axum/tower）
//!   - 本 crate **不依赖**任何数据库（sqlx）
//!   - 本 crate **不依赖** gateway-config（配置加载在 config crate）
//!   - 本 crate 只依赖 gateway-common + serde + async-trait + http
//!
//! 这样做的目的是：让核心模型不受实现细节干扰，方便独立测试和替换底层框架。
//!
//! ## 模块
//!
//! - [`types`]：领域枚举（Path 类型、负载均衡算法、健康状态）
//! - [`models`]：配置模型和运行时模型（Route/Service/Upstream/Endpoint）
//! - [`policy`]：Phase 2 策略配置模型（鉴权/限流/超时/重试/熔断/CORS/转换）
//! - [`traits`]：运行时 Trait（ServiceDiscoveryProvider、LoadBalancer）
//! - [`request_context`]：请求上下文，贯穿整个 Pipeline
//! - [`prelude`]：常用类型 re-export

#![allow(clippy::needless_doctest_main)]

pub mod models;
pub mod platform;
pub mod policy;
pub mod prelude;
pub mod request_context;
pub mod traits;
pub mod types;

// 方便下游直接 use
pub use models::*;
pub use platform::*;
pub use policy::*;
pub use request_context::*;
pub use traits::*;
pub use types::*;
