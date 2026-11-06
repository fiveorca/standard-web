//! 通用工具模块。

pub mod duration;
pub mod http;
pub mod ip;
pub mod pattern;

use std::time::{SystemTime, UNIX_EPOCH};

/// 当前 Unix 毫秒时间戳。
pub fn unix_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

/// 生成短的随机 ID（16 位十六进制）。
pub fn short_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    hex::encode(bytes)
}

/// 生成请求 ID：当客户端提供合法 ID 时可复用，否则生成 UUID v4。
pub fn new_request_id(candidate: Option<&str>) -> String {
    if let Some(value) = candidate {
        let trimmed = value.trim();
        if !trimmed.is_empty()
            && trimmed.len() <= 128
            && trimmed
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ':'))
        {
            return trimmed.to_string();
        }
    }
    uuid::Uuid::new_v4().to_string()
}
