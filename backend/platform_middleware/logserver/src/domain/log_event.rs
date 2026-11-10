// ! 领域层: LogEvent 统一日志模型

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// 日志级别
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Fatal => "FATAL",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "TRACE" => Some(Self::Trace),
            "DEBUG" => Some(Self::Debug),
            "INFO" => Some(Self::Info),
            "WARN" => Some(Self::Warn),
            "ERROR" => Some(Self::Error),
            "FATAL" => Some(Self::Fatal),
            _ => None,
        }
    }

    pub fn severity(&self) -> u8 {
        match self {
            Self::Trace => 0,
            Self::Debug => 1,
            Self::Info => 2,
            Self::Warn => 3,
            Self::Error => 4,
            Self::Fatal => 5,
        }
    }
}

/// 异常详情
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExceptionInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<String>,
}

/// 统一 LogEvent 模型
///
/// 用于所有内部流转，是 Kafka / gRPC / ClickHouse 三方的唯一真实数据源。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LogEvent {
    /// schema 版本
    pub schema_version: String,
    /// 唯一事件 ID (调用方必须稳定)
    pub event_id: Uuid,
    /// 日志产生时间 (UTC)
    #[serde(rename = "@timestamp")]
    pub timestamp: DateTime<Utc>,
    /// 日志级别
    pub level: LogLevel,
    /// 服务名
    pub service_name: String,
    #[serde(default)]
    pub service_version: Option<String>,
    #[serde(default)]
    pub environment: Option<String>,
    #[serde(default)]
    pub host_name: Option<String>,
    #[serde(default)]
    pub logger: Option<String>,
    #[serde(default)]
    pub thread_name: Option<String>,
    /// 日志正文
    pub message: String,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub span_id: Option<String>,
    #[serde(default)]
    pub request_id: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exception: Option<ExceptionInfo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
    /// 服务端填充：接收时间 (不对外暴露，仅内部流转)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub received_at: Option<DateTime<Utc>>,
    /// 服务端填充：摄入版本 (ClickHouse 去重用)
    #[serde(default, skip_serializing)]
    pub ingest_version: Option<u64>,
}

impl LogEvent {
    /// 创建一个新事件 (带默认值)
    pub fn new(
        event_id: Uuid,
        timestamp: DateTime<Utc>,
        level: LogLevel,
        service_name: String,
        message: String,
    ) -> Self {
        Self {
            schema_version: "1.0".to_string(),
            event_id,
            timestamp,
            level,
            service_name,
            service_version: None,
            environment: None,
            host_name: None,
            logger: None,
            thread_name: None,
            message,
            trace_id: None,
            span_id: None,
            request_id: None,
            tenant_id: None,
            exception: None,
            attributes: None,
            received_at: None,
            ingest_version: None,
        }
    }

    /// 填充服务端接收时间
    pub fn with_received_at(mut self, t: DateTime<Utc>) -> Self {
        self.received_at = Some(t);
        self
    }

    pub fn with_ingest_version(mut self, v: u64) -> Self {
        self.ingest_version = Some(v);
        self
    }

    pub fn with_tenant(mut self, tenant: String) -> Self {
        self.tenant_id = Some(tenant);
        self
    }
}

// ---- 校验 ----

/// 校验 LogEvent，返回错误信息
pub fn validate_log_event(e: &LogEvent) -> Result<(), String> {
    if e.schema_version.is_empty() {
        return Err("schemaVersion 不能为空".into());
    }
    if e.service_name.is_empty() || e.service_name.len() > 128 {
        return Err("serviceName 必须非空且 <= 128".into());
    }
    if e.message.is_empty() {
        return Err("message 不能为空".into());
    }
    // 限制 attributes
    if let Some(attrs) = &e.attributes {
        if attrs.len() > 50 {
            return Err("attributes 字段数量超过 50 限制".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event() -> LogEvent {
        LogEvent::new(
            Uuid::new_v4(),
            Utc::now(),
            LogLevel::Info,
            "order-service".into(),
            "hello world".into(),
        )
    }

    #[test]
    fn validate_ok() {
        assert!(validate_log_event(&make_event()).is_ok());
    }

    #[test]
    fn empty_service_name_invalid() {
        let mut e = make_event();
        e.service_name.clear();
        assert!(validate_log_event(&e).is_err());
    }

    #[test]
    fn serde_roundtrip() {
        let e = make_event();
        let s = serde_json::to_string(&e).unwrap();
        let e2: LogEvent = serde_json::from_str(&s).unwrap();
        assert_eq!(e.event_id, e2.event_id);
        assert_eq!(e.message, e2.message);
        assert_eq!(e.level, e2.level);
    }
}
