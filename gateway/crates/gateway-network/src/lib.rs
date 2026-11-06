//! # gateway-network
//!
//! HTTP Server 接入层。
//!
//! 职责：
//!   1. 绑定监听地址，用 Hyper 启动 HTTP/1.1 + HTTP/2 Server
//!   2. 连接数限制、并发请求数限制（Bulkhead）
//!   3. 优雅关闭：收到 shutdown 信号后停止 accept、等待在途请求
//!
//! # 设计原则
//!
//! - 本 crate 不实现业务逻辑（不路由、不转发），业务逻辑在 Runtime 组合根
//! - 业务逻辑通过 `tower::Service` 注入，Network 层只负责 IO
//! - 支持明文 HTTP 与 TLS（HTTPS）接入，TLS 实现见 [`tls`]

#![allow(clippy::needless_doctest_main)]

pub mod server;
pub mod tls;

pub use server::{HttpServer, ServerOptions};
pub use tls::{LoadedCertificate, TlsRuntime};
