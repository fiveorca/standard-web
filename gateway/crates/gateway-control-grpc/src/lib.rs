//! # gateway-control-grpc
//!
//! 控制面与数据面之间的 gRPC 配置分发（Phase 4）。
//!
//! ## 为什么独立成 crate
//!
//! - proto 代码生成需要 `tonic-build`，放在独立 crate 可以把 build
//!   依赖与业务 crate 隔离开；
//! - 控制面（server）与数据面（client）都依赖本 crate，但二者不依赖
//!   对方的业务 crate，避免 control-plane ↔ data-plane 的循环依赖。
//!
//! ## 模块
//!
//! - [`pb`]：protoc 生成的请求/响应类型与 gRPC 客户端/服务端骨架
//! - [`server`]：控制面侧服务实现（注册表 + 心跳 + 快照下发）
//! - [`client`]：数据面侧同步循环（心跳 → 拉取 → 应用 → ACK/NACK）

#![allow(clippy::needless_doctest_main)]
// tonic 生成的 trait 统一返回 Result<_, tonic::Status>；Status 体积较大，
// 但签名由协议固定，无法改为 Box，因此整 crate 豁免该 lint。
#![allow(clippy::result_large_err)]

/// protoc 生成的类型与 trait。
pub mod pb {
    // include_proto! 会在编译期把 build.rs 生成的代码展开到这里
    tonic::include_proto!("gateway.config.v1");
}

pub mod client;
pub mod server;

pub use client::{SyncClient, SyncOutcome};
pub use server::{ConfigDistributionService, InstanceState};
