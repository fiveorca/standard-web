//! Tracing 日志初始化。
//!
//! 使用 tracing-subscriber 的 JSON 格式输出。
//!
//! # 为什么用 tracing-subscriber
//!
//! - tracing 是 Tokio 官方推荐的可观测性库
//! - tracing-subscriber 是 tracing 的后端实现，支持：
//!   - env-filter：用 RUST_LOG 环境变量控制日志级别
//!   - json：结构化 JSON 输出，方便 ELK/Loki/Grafana 等系统采集
//!
//! # 初始化流程
//!
//! 1. 解析 RUST_LOG 环境变量（默认 info）
//! 2. 根据 format 参数选择 JSON 或 pretty
//! 3. 注册全局 subscriber（全局只能注册一次，重复注册会 panic，
//!    所以 init_logging 内部做了幂等保护）

use std::sync::Once;

use tracing_subscriber::EnvFilter;

static INIT_ONCE: Once = Once::new();

/// 初始化全局 tracing subscriber。
///
/// # 参数
/// - `level`：日志级别（"trace"/"debug"/"info"/"warn"/"error"）。
///   可以被 RUST_LOG 环境变量覆盖。
/// - `format`：日志格式（"json" / "pretty"）。
///
/// # 幂等性
///
/// 用 `Once` 保证整个进程内只初始化一次。重复调用不会 panic。
pub fn init_logging(level: &str, format: &str) {
    INIT_ONCE.call_once(|| {
        // 构造 EnvFilter：优先用 RUST_LOG 环境变量，fallback 到参数 level
        let env_filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new(format!("gateway={level},info")));

        // 根据 format 选择输出器
        match format {
            "pretty" => {
                tracing_subscriber::fmt()
                    .with_env_filter(env_filter)
                    .with_target(true)
                    .with_thread_ids(true)
                    .init();
            },
            _ => {
                // 默认 JSON 格式，适合生产环境采集
                tracing_subscriber::fmt()
                    .with_env_filter(env_filter)
                    .json()
                    .with_current_span(true)
                    .init();
            },
        }

        tracing::info!(
            target: "gateway_observability",
            level = level,
            format = format,
            "tracing subscriber initialized"
        );
    });
}
