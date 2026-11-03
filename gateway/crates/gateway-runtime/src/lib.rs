//! # gateway-runtime
//!
//! 数据面运行时组合根。
//!
//! 本 crate 负责：
//!   1. 启动时加载 YAML 配置 + 校验
//!   2. 编译 RouteTable + 构建 UpstreamRegistry
//!   3. 创建 ProxyClient
//!   4. 组装 Tower Service Pipeline（Route → Upstream → Proxy → AccessLog）
//!   5. 启动 Hyper Server（业务端口）
//!   6. 启动 Axum Admin Server（/health /ready /version）
//!   7. 监听 shutdown 信号，执行优雅关闭
//!
//! # 重要设计决策
//!
//! - Runtime 内部所有共享状态（RouteTable、UpstreamRegistry、ProxyClient）
//!   都用 `Arc<T>` 包装。Service 闭包 clone Arc 是 +1 引用计数，开销极小。
//! - Phase 1 中配置是一次性加载的；热更新（ArcSwap）留到 Phase 3 控制面。
//! - Hyper Server 用 HttpServer 封装（gateway-network）；Admin Server
//!   用 Axum（gateway-runtime 自己实现）——这符合"Axum 只做管理接口"的约束。

#![allow(clippy::needless_doctest_main)]

pub mod admin;
pub mod pipeline;
pub mod runtime;

pub use runtime::{Runtime, RuntimeHandle};
