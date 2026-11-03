//! # gateway-proxy
//!
//! Hyper 流式反向代理核心。
//!
//! 职责：
//!   1. 维护一个 `hyper::Client` 实例（HTTP/1.1 + HTTP/2 自动协商）
//!   2. 接收网关侧的 `http::Request<ReqBody>`，转换为上游请求
//!   3. 正确处理 Hop-by-Hop Header（移除、不转发）
//!   4. 处理 `X-Forwarded-For` / `X-Forwarded-Proto` 等代理链头
//!   5. 流式请求体和响应体（不做全量缓冲）
//!   6. 上游错误统一映射到 `GatewayError`
//!
//! # 设计原则
//!
//! - 不做任何 IO 阻塞操作；hyper 和 tokio 都是全异步
//! - 请求体/响应体都是流式 Body，内存占用恒定
//! - 连接复用由 hyper client 自己管理（keep-alive、连接池）
//! - Phase 1 不实现 TLS 上游连接

#![allow(clippy::needless_doctest_main)]
// doc comment 里的长换行续接偶尔触发这个 lint，不影响文档质量
#![allow(clippy::doc_overindented_list_items)]
#![allow(clippy::doc_lazy_continuation)]

pub mod client;
pub mod headers;

pub use client::{ProxyClient, ProxyOptions};
