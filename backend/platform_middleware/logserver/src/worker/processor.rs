// ! 消息处理：JSON 解析 + LogEvent 校验 + 脱敏

use crate::config::SecurityConfig;
use crate::domain::{validate_log_event, LogEvent};
use crate::infrastructure::security::sanitizer::Sanitizer;
use chrono::Utc;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ProcessedMessage {
    pub event: LogEvent,
}

#[derive(Clone)]
pub struct MessageProcessor {
    sanitizer: Arc<Sanitizer>,
}

impl MessageProcessor {
    pub fn new(security_cfg: SecurityConfig) -> Self {
        Self {
            sanitizer: Arc::new(Sanitizer::new(security_cfg)),
        }
    }

    /// 尝试将原始 payload 解析为 LogEvent
    ///
    /// 失败返回原始 payload 字符串，由上层决定进 DLQ 还是重试
    pub fn parse(&self, payload: &[u8]) -> Result<ProcessedMessage, String> {
        let mut event: LogEvent = serde_json::from_slice(payload)
            .map_err(|e| format!("JSON 解析失败: {e}"))?;

        // 校验
        validate_log_event(&event).map_err(|e| format!("校验失败: {e}"))?;

        // 脱敏
        self.sanitizer.sanitize(&mut event);

        // 填充 received_at (如果没有)
        if event.received_at.is_none() {
            event.received_at = Some(Utc::now());
        }

        Ok(ProcessedMessage { event })
    }
}
