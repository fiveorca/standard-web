//! # gateway-common
//!
//! 本 crate 是整个 Gateway workspace 最底层的共享库。
//! 它不依赖任何项目内其他 crate，只依赖 `thiserror`、`uuid` 和 `serde`。
//!
//! 职责：
//!   - 定义统一的 `GatewayError` 错误枚举，所有模块的错误最终都可映射到它
//!   - 定义 `ErrorCode` 错误码，作为 HTTP/JSON 错误响应中的 `code` 字段
//!   - 定义 `ErrorResponse` 统一 JSON 错误响应格式
//!   - 定义 `RequestId` 等通用值类型
//!
//! 约束：
//!   - 本 crate 不承载领域模型（领域模型在 gateway-core）
//!   - 本 crate 不依赖任何 IO 框架（tokio/hyper/axum/tower）
//!   - 本 crate 不依赖任何数据库（sqlx）
//!   - 不允许在这里写 unwrap/expect 处理错误
//!
//! ## 模块结构
//!
//! - [`error`]：错误码、错误类型、HTTP 状态码映射
//! - [`request_id`]：请求 ID 封装
//! - [`prelude`]：常用类型的统一 re-export
//!
//! 使用方式：
//! ```rust,ignore
//! use gateway_common::prelude::*;
//! ```

// ---------------------------------------------------------------------------
// #![deny(...)] — 本 crate 的全局 lint 指令
// 注意：这里不使用 deny(warnings)，以免开发期间阻碍编译。
//       阶段验收时通过 `cargo clippy -- -D warnings` 显式检查。
// ---------------------------------------------------------------------------
#![allow(clippy::needless_doctest_main)]

pub mod error;
pub mod prelude;
pub mod request_id;

// 从各子模块 re-export 常用类型，方便下游 crate 使用
pub use error::{ErrorCode, ErrorResponse, GatewayError};
pub use request_id::RequestId;
