// ! 日志摄入服务
//
// 负责：
// - 校验 / 脱敏 / 转换 LogEvent
// - 通过 Kafka Producer 投递到 logs.raw.v1

use crate::common::error::AppError;
use crate::config::SecurityConfig;
use crate::domain::{validate_log_event, LogEvent};
use crate::infrastructure::kafka::producer::LogProducer;
use crate::infrastructure::security::sanitizer::Sanitizer;
use chrono::Utc;
use std::sync::Arc;

/// 单条日志摄入结果
#[derive(Debug, Clone)]
pub struct IngestResult {
    pub index: usize,
    pub accepted: bool,
    pub reason: Option<String>,
}

/// 批量摄入请求
#[derive(Debug, Clone)]
pub struct IngestBatch {
    pub request_id: String,
    pub tenant_id: String,
    pub events: Vec<LogEvent>,
}

/// 批量摄入响应
#[derive(Debug, Clone)]
pub struct IngestBatchResponse {
    pub request_id: String,
    pub accepted_count: u32,
    pub rejected_count: u32,
    pub rejected: Vec<IngestResult>,
}

#[derive(Clone)]
pub struct IngestionService {
    producer: Arc<LogProducer>,
    sanitizer: Arc<Sanitizer>,
}

impl IngestionService {
    pub fn new(producer: LogProducer, security_cfg: SecurityConfig) -> Self {
        Self {
            producer: Arc::new(producer),
            sanitizer: Arc::new(Sanitizer::new(security_cfg)),
        }
    }

    pub fn producer(&self) -> &Arc<LogProducer> {
        &self.producer
    }

    pub fn sanitizer(&self) -> &Arc<Sanitizer> {
        &self.sanitizer
    }

    /// 批量摄入
    pub async fn ingest_batch(
        &self,
        request_id: String,
        tenant_id: String,
        events: Vec<LogEvent>,
    ) -> Result<IngestBatchResponse, AppError> {
        let mut rejected = Vec::new();
        let mut accepted_events: Vec<LogEvent> = Vec::with_capacity(events.len());

        for (i, mut ev) in events.into_iter().enumerate() {
            // 租户覆盖 (服务端强制)
            ev = ev.with_tenant(tenant_id.clone());

            // 校验
            if let Err(msg) = validate_log_event(&ev) {
                rejected.push(IngestResult {
                    index: i,
                    accepted: false,
                    reason: Some(msg),
                });
                continue;
            }

            // 脱敏
            self.sanitizer.sanitize(&mut ev);

            // 填充 received_at
            ev = ev.with_received_at(Utc::now());

            accepted_events.push(ev);
        }

        // Kafka 投递
        let results = self.producer.send_batch(&accepted_events).await;
        // results 中的 index 是 accepted_events 内的 index，需要重新映射

        let mut batch_idx = 0usize;
        let mut ok_count = 0u32;
        for (i, _ev) in accepted_events.iter().enumerate() {
            let ok = results
                .iter()
                .find(|(idx, _)| *idx == i)
                .map(|(_, r)| r.is_ok())
                .unwrap_or(false);
            if ok {
                ok_count += 1;
            } else {
                rejected.push(IngestResult {
                    index: batch_idx,
                    accepted: false,
                    reason: Some("Kafka 投递失败".into()),
                });
            }
            batch_idx += 1;
        }

        // accepted 数量 = ok_count (实际 Kafka 确认成功)
        // rejected 数量 = 校验失败 + Kafka 失败
        let rejected_count = rejected.len() as u32;

        Ok(IngestBatchResponse {
            request_id,
            accepted_count: ok_count,
            rejected_count,
            rejected,
        })
    }
}
