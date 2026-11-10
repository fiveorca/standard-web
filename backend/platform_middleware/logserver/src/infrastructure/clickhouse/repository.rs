// ! ClickHouse Repository
//
// 负责:
// - 批量写入 (使用 Inserter)
// - 查询列表
// - 查询详情
// - 聚合分析
// - DLQ 写入

use chrono::{DateTime, Utc};
use clickhouse::Row;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::client::ClickHouse;
use crate::common::error::AppError;
use crate::domain::LogEvent;

// ===== 行模型 =====

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct LogRow {
    pub event_id: Uuid,
    pub schema_version: String,
    pub log_time: DateTime<Utc>,
    pub ingest_time: DateTime<Utc>,
    pub ingest_version: u64,
    pub level: String,
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub host_name: String,
    pub logger: String,
    pub thread_name: String,
    pub message: String,
    pub trace_id: String,
    pub span_id: String,
    pub request_id: String,
    pub tenant_id: String,
    pub exception_type: String,
    pub exception_message: String,
    pub stack_trace: String,
    pub attributes_json: String,
}

impl LogRow {
    pub fn from_event(event: &LogEvent, ingest_time: DateTime<Utc>, ingest_version: u64) -> Self {
        LogRow {
            event_id: event.event_id,
            schema_version: event.schema_version.clone(),
            log_time: event.timestamp,
            ingest_time,
            ingest_version,
            level: event.level.as_str().to_string(),
            service_name: event.service_name.clone(),
            service_version: event.service_version.clone().unwrap_or_default(),
            environment: event.environment.clone().unwrap_or_default(),
            host_name: event.host_name.clone().unwrap_or_default(),
            logger: event.logger.clone().unwrap_or_default(),
            thread_name: event.thread_name.clone().unwrap_or_default(),
            message: event.message.clone(),
            trace_id: event.trace_id.clone().unwrap_or_default(),
            span_id: event.span_id.clone().unwrap_or_default(),
            request_id: event.request_id.clone().unwrap_or_default(),
            tenant_id: event.tenant_id.clone().unwrap_or_default(),
            exception_type: event
                .exception
                .as_ref()
                .and_then(|e| e.r#type.clone())
                .unwrap_or_default(),
            exception_message: event
                .exception
                .as_ref()
                .and_then(|e| e.message.clone())
                .unwrap_or_default(),
            stack_trace: event
                .exception
                .as_ref()
                .and_then(|e| e.stack_trace.clone())
                .unwrap_or_default(),
            attributes_json: match &event.attributes {
                Some(attrs) => serde_json::to_string(attrs).unwrap_or_else(|_| "{}".into()),
                None => "{}".into(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct DlqRow {
    pub event_id: Option<Uuid>,
    pub original_payload: String,
    pub error_reason: String,
    pub error_stage: String,
    pub failed_at: DateTime<Utc>,
    pub kafka_topic: String,
    pub kafka_partition: i32,
    pub kafka_offset: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct LogRowLight {
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

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct LevelCount {
    pub level: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct ServiceCount {
    pub service_name: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct TrendBucket {
    pub bucket: DateTime<Utc>,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct TopError {
    pub error_key: String,
    pub count: u64,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct OverviewResult {
    pub total_count: u64,
    pub error_count: u64,
    pub fatal_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct LogDetailRow {
    pub event_id: Uuid,
    pub schema_version: String,
    pub log_time: DateTime<Utc>,
    pub level: String,
    pub service_name: String,
    pub service_version: String,
    pub environment: String,
    pub host_name: String,
    pub logger: String,
    pub thread_name: String,
    pub message: String,
    pub trace_id: String,
    pub span_id: String,
    pub request_id: String,
    pub tenant_id: String,
    pub exception_type: String,
    pub exception_message: String,
    pub stack_trace: String,
    pub attributes_json: String,
    pub ingest_time: DateTime<Utc>,
}

// ===== Repository =====

pub struct LogRepository<'a> {
    db: &'a ClickHouse,
}

impl Clone for LogRepository<'_> {
    fn clone(&self) -> Self {
        Self { db: self.db }
    }
}

impl LogRepository<'static> {
    pub fn leak_new(db: &ClickHouse) -> Self {
        let db_ref: &'static ClickHouse = Box::leak(Box::new(db.clone()));
        Self { db: db_ref }
    }
}

impl<'a> LogRepository<'a> {
    pub fn new(db: &'a ClickHouse) -> Self {
        Self { db }
    }

    /// 批量写入 - clickhouse 0.14 Inserter API
    pub async fn bulk_insert(&self, rows: &[LogRow]) -> Result<u64, AppError> {
        if rows.is_empty() {
            return Ok(0);
        }
        let table = format!("{}.logs", self.db.database);
        let mut inserter = self.db.client().inserter::<LogRow>(table.as_str());

        for row in rows {
            inserter
                .write(row)
                .await
                .map_err(|e| AppError::ClickHouse(format!("写入行失败: {e}")))?;
        }

        inserter
            .commit()
            .await
            .map_err(|e| AppError::ClickHouse(format!("批量提交失败: {e}")))?;

        Ok(rows.len() as u64)
    }

    /// 单条详情查询
    pub async fn get_by_id(
        &self,
        tenant_id: &str,
        event_id: Uuid,
    ) -> Result<Option<LogEvent>, AppError> {
        let sql = format!(
            "SELECT event_id, schema_version, log_time, level, service_name, service_version, \
             environment, host_name, logger, thread_name, message, trace_id, span_id, request_id, \
             tenant_id, exception_type, exception_message, stack_trace, attributes_json, ingest_time \
             FROM {}.logs \
             FINAL \
             WHERE tenant_id = ? AND event_id = ? \
             LIMIT 1",
            self.db.database
        );

        let row: Option<LogDetailRow> = self
            .db
            .client()
            .query(&sql)
            .bind(tenant_id)
            .bind(event_id)
            .fetch_optional()
            .await
            .map_err(|e| AppError::ClickHouse(format!("详情查询失败: {e}")))?;

        Ok(row.map(|r| r.to_log_event()))
    }

    /// 列表查询 (完整条件)
    pub async fn query(
        &self,
        tenant_id: &str,
        q: &LogQuery,
    ) -> Result<QueryResult, AppError> {
        let page_size = q.page_size.unwrap_or(100).min(1000);

        // 条件用参数占位符，安全防注入
        let mut conds: Vec<String> = vec!["tenant_id = ?".to_string()];

        if q.start_time.is_some() {
            conds.push("log_time >= ?".into());
        }
        if q.end_time.is_some() {
            conds.push("log_time <= ?".into());
        }
        if q.trace_id.is_some() {
            conds.push("trace_id = ?".into());
        }
        if q.span_id.is_some() {
            conds.push("span_id = ?".into());
        }
        if q.request_id.is_some() {
            conds.push("request_id = ?".into());
        }
        if q.exception_type.is_some() {
            conds.push("exception_type ILIKE ?".into());
        }
        if let Some(ref v) = q.keyword {
            conds.push("(message ILIKE ? OR attributes_json ILIKE ? OR stack_trace ILIKE ?)".into());
            let _ = v;
        }
        if q.cursor.is_some() {
            conds.push("(log_time < ? OR (log_time = ? AND event_id < ?))".into());
        }

        // IN 条件直接拼 SQL (值来自应用层，已安全过滤)
        if let Some(ref lv) = q.levels {
            let ors: Vec<String> = lv
                .iter()
                .map(|l| format!("level = '{}'", l.as_str()))
                .collect();
            conds.push(format!("({})", ors.join(" OR ")));
        }
        if let Some(ref svs) = q.service_names {
            let ors: Vec<String> = svs
                .iter()
                .map(|s| format!("service_name = '{}'", s.replace('\'', "''")))
                .collect();
            conds.push(format!("({})", ors.join(" OR ")));
        }
        if let Some(ref envs) = q.environments {
            let ors: Vec<String> = envs
                .iter()
                .map(|s| format!("environment = '{}'", s.replace('\'', "''")))
                .collect();
            conds.push(format!("({})", ors.join(" OR ")));
        }
        if let Some(ref hosts) = q.host_names {
            let ors: Vec<String> = hosts
                .iter()
                .map(|s| format!("host_name = '{}'", s.replace('\'', "''")))
                .collect();
            conds.push(format!("({})", ors.join(" OR ")));
        }

        let sql = format!(
            "SELECT event_id, log_time, level, service_name, environment, host_name, message, trace_id, tenant_id \
             FROM {}.logs \
             WHERE {} \
             ORDER BY log_time DESC, event_id DESC \
             LIMIT {}",
            self.db.database,
            conds.join(" AND "),
            page_size + 1
        );

        // 逐步 bind 参数
        let mut qb = self.db.client().query(&sql);
        qb = qb.bind(tenant_id.to_string());
        if let Some(t) = q.start_time {
            qb = qb.bind(t);
        }
        if let Some(t) = q.end_time {
            qb = qb.bind(t);
        }
        if let Some(ref v) = q.trace_id {
            qb = qb.bind(v.clone());
        }
        if let Some(ref v) = q.span_id {
            qb = qb.bind(v.clone());
        }
        if let Some(ref v) = q.request_id {
            qb = qb.bind(v.clone());
        }
        if let Some(ref v) = q.exception_type {
            qb = qb.bind(format!("%{}%", v));
        }
        if let Some(ref v) = q.keyword {
            let like = format!("%{}%", v);
            qb = qb.bind(like.clone()); // message
            qb = qb.bind(like.clone()); // attributes_json
            qb = qb.bind(like); // stack_trace
        }
        if let Some(c) = q.cursor {
            qb = qb.bind(c.0);
            qb = qb.bind(c.0);
            qb = qb.bind(c.1);
        }

        let rows: Vec<LogRowLight> = qb
            .fetch_all()
            .await
            .map_err(|e| AppError::ClickHouse(format!("列表查询失败: {e}")))?;

        let has_more = rows.len() > page_size;
        let mut rows = rows;
        rows.truncate(page_size);

        let next_cursor = if has_more {
            rows.last().map(|r| Cursor(r.log_time, r.event_id))
        } else {
            None
        };

        Ok(QueryResult {
            rows,
            has_more,
            next_cursor,
        })
    }

    // --- 分析 ---

    pub async fn overview(
        &self,
        tenant_id: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> Result<OverviewResult, AppError> {
        let mut sql = format!(
            "SELECT count() AS total_count, \
                    countIf(level = 'ERROR') AS error_count, \
                    countIf(level = 'FATAL') AS fatal_count \
             FROM {}.logs WHERE tenant_id = ?",
            self.db.database
        );
        if start_time.is_some() {
            sql.push_str(" AND log_time >= ?");
        }
        if end_time.is_some() {
            sql.push_str(" AND log_time <= ?");
        }
        let mut q = self.db.client().query(&sql).bind(tenant_id);
        if let Some(t) = start_time {
            q = q.bind(t);
        }
        if let Some(t) = end_time {
            q = q.bind(t);
        }
        q.fetch_one::<OverviewResult>()
            .await
            .map_err(|e| AppError::ClickHouse(format!("overview 查询失败: {e}")))
    }

    pub async fn level_counts(
        &self,
        tenant_id: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> Result<Vec<LevelCount>, AppError> {
        let mut sql = format!(
            "SELECT level, count() AS count FROM {}.logs WHERE tenant_id = ?",
            self.db.database
        );
        if start_time.is_some() {
            sql.push_str(" AND log_time >= ?");
        }
        if end_time.is_some() {
            sql.push_str(" AND log_time <= ?");
        }
        sql.push_str(" GROUP BY level ORDER BY count DESC");
        let mut q = self.db.client().query(&sql).bind(tenant_id);
        if let Some(t) = start_time {
            q = q.bind(t);
        }
        if let Some(t) = end_time {
            q = q.bind(t);
        }
        q.fetch_all::<LevelCount>()
            .await
            .map_err(|e| AppError::ClickHouse(format!("level counts 失败: {e}")))
    }

    pub async fn service_counts(
        &self,
        tenant_id: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> Result<Vec<ServiceCount>, AppError> {
        let mut sql = format!(
            "SELECT service_name, count() AS count FROM {}.logs WHERE tenant_id = ?",
            self.db.database
        );
        if start_time.is_some() {
            sql.push_str(" AND log_time >= ?");
        }
        if end_time.is_some() {
            sql.push_str(" AND log_time <= ?");
        }
        sql.push_str(" GROUP BY service_name ORDER BY count DESC");
        let mut q = self.db.client().query(&sql).bind(tenant_id);
        if let Some(t) = start_time {
            q = q.bind(t);
        }
        if let Some(t) = end_time {
            q = q.bind(t);
        }
        q.fetch_all::<ServiceCount>()
            .await
            .map_err(|e| AppError::ClickHouse(format!("service counts 失败: {e}")))
    }

    pub async fn trends(
        &self,
        tenant_id: &str,
        start_time: DateTime<Utc>,
        end_time: DateTime<Utc>,
        granularity: &str,
    ) -> Result<Vec<TrendBucket>, AppError> {
        let rounding = match granularity {
            "minute" => "toStartOfMinute",
            "day" => "toStartOfDay",
            _ => "toStartOfHour",
        };
        let sql = format!(
            "SELECT {rounding}(log_time) AS bucket, count() AS count \
             FROM {}.logs \
             WHERE tenant_id = ? AND log_time >= ? AND log_time <= ? \
             GROUP BY bucket ORDER BY bucket ASC",
            self.db.database
        );
        self.db
            .client()
            .query(&sql)
            .bind(tenant_id)
            .bind(start_time)
            .bind(end_time)
            .fetch_all::<TrendBucket>()
            .await
            .map_err(|e| AppError::ClickHouse(format!("trends 失败: {e}")))
    }

    pub async fn top_errors(
        &self,
        tenant_id: &str,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
        limit: usize,
    ) -> Result<Vec<TopError>, AppError> {
        let limit = limit.min(100);
        let mut sql = format!(
            "SELECT \
                multiIf( \
                    exception_type != '', concat(exception_type, ': ', exception_message), \
                    level IN ('ERROR','FATAL'), message, \
                    level \
                ) AS error_key, \
                count() AS count, \
                max(log_time) AS last_seen \
             FROM {}.logs \
             WHERE tenant_id = ? AND level IN ('ERROR','FATAL')",
            self.db.database
        );
        if start_time.is_some() {
            sql.push_str(" AND log_time >= ?");
        }
        if end_time.is_some() {
            sql.push_str(" AND log_time <= ?");
        }
        sql.push_str(&format!(
            " GROUP BY error_key ORDER BY count DESC LIMIT {}",
            limit
        ));
        let mut q = self.db.client().query(&sql).bind(tenant_id);
        if let Some(t) = start_time {
            q = q.bind(t);
        }
        if let Some(t) = end_time {
            q = q.bind(t);
        }
        q.fetch_all::<TopError>()
            .await
            .map_err(|e| AppError::ClickHouse(format!("top_errors 失败: {e}")))
    }

    /// DLQ 写入
    pub async fn insert_dlq(&self, row: &DlqRow) -> Result<(), AppError> {
        let table = format!("{}.dlq_logs", self.db.database);
        let mut inserter = self.db.client().inserter::<DlqRow>(table.as_str());
        inserter
            .write(row)
            .await
            .map_err(|e| AppError::ClickHouse(format!("DLQ write 失败: {e}")))?;
        inserter
            .commit()
            .await
            .map_err(|e| AppError::ClickHouse(format!("DLQ commit 失败: {e}")))?;
        Ok(())
    }
}

// ---- 查询模型 ----

#[derive(Debug, Clone, Default)]
pub struct LogQuery {
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub levels: Option<Vec<crate::domain::LogLevel>>,
    pub service_names: Option<Vec<String>>,
    pub environments: Option<Vec<String>>,
    pub host_names: Option<Vec<String>>,
    pub trace_id: Option<String>,
    pub span_id: Option<String>,
    pub request_id: Option<String>,
    pub tenant_id_filter: Option<String>,
    pub exception_type: Option<String>,
    pub keyword: Option<String>,
    pub page_size: Option<usize>,
    pub cursor: Option<Cursor>,
}

#[derive(Debug, Clone, Copy)]
pub struct Cursor(pub DateTime<Utc>, pub Uuid);

#[derive(Debug, Clone)]
pub struct QueryResult {
    pub rows: Vec<LogRowLight>,
    pub has_more: bool,
    pub next_cursor: Option<Cursor>,
}

impl Cursor {
    pub fn encode(&self) -> String {
        let t = self.0.timestamp_millis();
        format!("{t}:{}", self.1)
    }

    pub fn decode(s: &str) -> Option<Self> {
        let mut parts = s.splitn(2, ':');
        let t_str = parts.next()?;
        let id_str = parts.next()?;
        let t_ms: i64 = t_str.parse().ok()?;
        let id: Uuid = Uuid::parse_str(id_str).ok()?;
        let t = DateTime::<Utc>::from_timestamp_millis(t_ms)?;
        Some(Self(t, id))
    }
}

// ---- DetailRow 转换 ----

impl LogDetailRow {
    pub fn to_log_event(&self) -> LogEvent {
        let level = crate::domain::LogLevel::from_str(&self.level).unwrap_or(crate::domain::LogLevel::Info);
        let attributes = if self.attributes_json.is_empty() || self.attributes_json == "{}" {
            None
        } else {
            serde_json::from_str(&self.attributes_json).ok()
        };
        let exception = if self.exception_type.is_empty()
            && self.exception_message.is_empty()
            && self.stack_trace.is_empty()
        {
            None
        } else {
            Some(crate::domain::ExceptionInfo {
                r#type: Some(self.exception_type.clone()).filter(|s| !s.is_empty()),
                message: Some(self.exception_message.clone()).filter(|s| !s.is_empty()),
                stack_trace: Some(self.stack_trace.clone()).filter(|s| !s.is_empty()),
            })
        };
        LogEvent {
            schema_version: self.schema_version.clone(),
            event_id: self.event_id,
            timestamp: self.log_time,
            level,
            service_name: self.service_name.clone(),
            service_version: Some(self.service_version.clone()).filter(|s| !s.is_empty()),
            environment: Some(self.environment.clone()).filter(|s| !s.is_empty()),
            host_name: Some(self.host_name.clone()).filter(|s| !s.is_empty()),
            logger: Some(self.logger.clone()).filter(|s| !s.is_empty()),
            thread_name: Some(self.thread_name.clone()).filter(|s| !s.is_empty()),
            message: self.message.clone(),
            trace_id: Some(self.trace_id.clone()).filter(|s| !s.is_empty()),
            span_id: Some(self.span_id.clone()).filter(|s| !s.is_empty()),
            request_id: Some(self.request_id.clone()).filter(|s| !s.is_empty()),
            tenant_id: Some(self.tenant_id.clone()).filter(|s| !s.is_empty()),
            exception,
            attributes,
            received_at: Some(self.ingest_time),
            ingest_version: None,
        }
    }
}
