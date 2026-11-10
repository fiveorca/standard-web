// ! HTTP 请求/响应 DTO

use crate::domain::LogLevel;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

// ====== 查询 ======

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryLogsRequest {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub levels: Option<Vec<LogLevel>>,
    pub service_names: Option<Vec<String>>,
    pub environments: Option<Vec<String>>,
    pub host_names: Option<Vec<String>>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub request_id: Option<String>,
    pub exception_type: Option<String>,
    pub keyword: Option<String>,
    pub page_size: Option<usize>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueryLogsResponse {
    pub rows: Vec<LogSummary>,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogSummary {
    pub event_id: Uuid,
    pub log_time: DateTime<Utc>,
    pub level: String,
    pub service_name: String,
    pub environment: String,
    pub host_name: String,
    pub message: String,
    pub trace_id: String,
    pub tenant_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LogDetailResponse {
    pub event_id: Uuid,
    pub schema_version: String,
    pub log_time: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub level: String,
    pub service_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logger: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_name: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<ExceptionInfoDto>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExceptionInfoDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stack_trace: Option<String>,
}

// ====== 分析 ======

#[derive(Debug, Deserialize)]
pub struct TimeRangeQuery {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Deserialize)]
pub struct TrendQuery {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    #[serde(default = "default_granularity")]
    pub granularity: String,
}

fn default_granularity() -> String {
    "hour".into()
}

#[derive(Debug, Deserialize)]
pub struct TopErrorsQuery {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OverviewResponse {
    pub total_count: u64,
    pub error_count: u64,
    pub fatal_count: u64,
    pub error_rate: f64,
    pub fatal_rate: f64,
    pub levels: Vec<LevelCountDto>,
    pub services: Vec<ServiceCountDto>,
}

#[derive(Debug, Serialize)]
pub struct LevelCountDto {
    pub level: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct ServiceCountDto {
    pub service_name: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct TrendBucketDto {
    pub bucket: DateTime<Utc>,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct TopErrorDto {
    pub error_key: String,
    pub count: u64,
    pub last_seen: DateTime<Utc>,
}

// ====== 通用 ======

#[derive(Debug, Serialize)]
pub struct ApiErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, String>>,
}
