// ! 查询服务

use crate::common::error::AppError;
use crate::config::QueryConfig;
use crate::domain::LogLevel;
use crate::infrastructure::clickhouse::repository::{LogQuery, LogRepository};
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

/// 查询请求 (HTTP 层到 application 层)
#[derive(Debug, Clone, Default)]
pub struct QueryLogsRequest {
    pub tenant_id: String,
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

pub struct QueryService {
    repo: Arc<LogRepository<'static>>,
    config: QueryConfig,
}

impl QueryService {
    pub fn new(repo: LogRepository<'static>, config: QueryConfig) -> Self {
        Self {
            repo: Arc::new(repo),
            config,
        }
    }

    pub async fn query_logs(&self, req: QueryLogsRequest) -> Result<crate::infrastructure::clickhouse::repository::QueryResult, AppError> {
        // 校验时间范围
        let now = Utc::now();
        let start = req.start_time.unwrap_or_else(|| now - Duration::hours(self.config.max_time_range_hours as i64));
        let end = req.end_time.unwrap_or(now);

        if end - start > Duration::hours(self.config.max_time_range_hours as i64) {
            return Err(AppError::Validation(format!(
                "查询时间范围超过 {} 小时限制",
                self.config.max_time_range_hours
            )));
        }

        let page_size = req.page_size.unwrap_or(self.config.default_page_size).min(self.config.max_page_size);

        let cursor = match req.cursor.as_deref() {
            Some(s) if !s.is_empty() => crate::infrastructure::clickhouse::repository::Cursor::decode(s),
            _ => None,
        };

        let q = LogQuery {
            start_time: Some(start),
            end_time: Some(end),
            levels: req.levels,
            service_names: req.service_names,
            environments: req.environments,
            host_names: req.host_names,
            trace_id: req.trace_id,
            span_id: req.span_id,
            request_id: req.request_id,
            exception_type: req.exception_type,
            keyword: req.keyword,
            page_size: Some(page_size),
            cursor,
            tenant_id_filter: None, // 强制用请求里的 tenant_id
        };

        self.repo.query(&req.tenant_id, &q).await
    }

    pub async fn get_log_by_id(
        &self,
        tenant_id: String,
        event_id: Uuid,
    ) -> Result<Option<crate::domain::LogEvent>, AppError> {
        self.repo.get_by_id(&tenant_id, event_id).await
    }
}
