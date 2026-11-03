//! # gateway-observability
//!
//! 日志初始化和访问日志。
//!
//! Phase 1 只实现：
//!   1. `init_logging()` —— 一次性初始化 tracing-subscriber（JSON 格式）
//!   2. `AccessLog` —— 每次请求结束后输出一条 JSON 日志
//!
//! Phase 5 扩展：
//!   - Prometheus Metrics（prometheus crate）
//!   - OpenTelemetry Trace（opentelemetry crate）
//!   - OTLP 导出

#![allow(clippy::needless_doctest_main)]

pub mod access_log;
pub mod logging;

pub use access_log::{AccessLog, AccessLogEntry};
pub use logging::init_logging;
