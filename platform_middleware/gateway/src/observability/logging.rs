//! 结构化日志初始化。

use std::collections::HashSet;

use tracing_subscriber::EnvFilter;

use crate::config::model::LoggingConfig;

/// 初始化 tracing subscriber。
///
/// 默认输出 JSON，便于日志采集；`text` 模式用于本地开发。
pub fn init(config: &LoggingConfig) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(config.level.clone()));

    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(true)
        .with_thread_ids(false)
        .with_ansi(false);

    if config.format.eq_ignore_ascii_case("json") {
        let _ = builder.json().try_init();
    } else {
        let _ = builder.try_init();
    }
}

/// 需要脱敏的请求头集合（小写）。
pub fn redacted_headers(config: &LoggingConfig) -> HashSet<String> {
    config
        .redact_headers
        .iter()
        .map(|h| h.to_ascii_lowercase())
        .collect()
}
