// ! Kafka Producer (使用纯 Rust kafka crate)
//
// 同步 API 通过 tokio::task::spawn_blocking 包装为 async。

use crate::common::error::AppError;
use crate::config::KafkaConfig;
use crate::domain::LogEvent;
use kafka::producer::{Producer, Record, RequiredAcks};
use std::sync::Arc;
use tracing::info;

/// 异步 Kafka Producer 包装
#[derive(Clone)]
pub struct LogProducer {
    inner: Arc<std::sync::Mutex<Producer>>,
    raw_topic: String,
    dlq_topic: String,
}

impl LogProducer {
    pub fn new(cfg: &KafkaConfig) -> Result<Self, AppError> {
        let required_acks = match cfg.producer_acks.as_str() {
            "0" => RequiredAcks::None,
            "1" => RequiredAcks::One,
            _ => RequiredAcks::All,
        };

        let producer = Producer::from_hosts(vec![cfg.brokers.clone()])
            .with_required_acks(required_acks)
            .with_client_id("logserver".to_string())
            .create()
            .map_err(|e| AppError::Kafka(format!("创建 Producer 失败: {e}")))?;

        info!(topic = %cfg.raw_topic, "Kafka Producer 初始化");

        Ok(Self {
            inner: Arc::new(std::sync::Mutex::new(producer)),
            raw_topic: cfg.raw_topic.clone(),
            dlq_topic: cfg.dlq_topic.clone(),
        })
    }

    pub fn raw_topic(&self) -> &str {
        &self.raw_topic
    }

    pub fn dlq_topic(&self) -> &str {
        &self.dlq_topic
    }

    /// 投递到 logs.raw.v1
    pub async fn send_raw(&self, event: &LogEvent) -> Result<(), AppError> {
        let payload = serde_json::to_vec(event)
            .map_err(|e| AppError::Kafka(format!("序列化失败: {e}")))?;
        let key = event.event_id.to_string();
        self.do_send(&self.raw_topic, Some(key), &payload).await
    }

    /// 投递到 DLQ
    pub async fn send_dlq(&self, payload: &[u8], reason: &str, stage: &str) -> Result<(), AppError> {
        let key = format!("{stage}:{reason}");
        self.do_send(&self.dlq_topic, Some(key), payload).await
    }

    pub async fn send(
        &self,
        topic: &str,
        key: Option<String>,
        payload: &[u8],
    ) -> Result<(), AppError> {
        self.do_send(topic, key, payload).await
    }

    async fn do_send(
        &self,
        topic: &str,
        key: Option<String>,
        payload: &[u8],
    ) -> Result<(), AppError> {
        let topic = topic.to_string();
        let payload = payload.to_vec();
        let inner = self.inner.clone();

        tokio::task::spawn_blocking(move || {
            let mut producer = inner.lock().map_err(|e| {
                AppError::Kafka(format!("producer mutex 错误: {e}"))
            })?;
            // 统一使用 from_key_value 处理两种情况
            let record = Record::from_key_value(
                &topic,
                key.as_deref().unwrap_or(""),
                payload.as_slice(),
            );
            producer
                .send(&record)
                .map_err(|e| AppError::Kafka(format!("Kafka 投递失败: {e}")))?;
            Ok::<(), AppError>(())
        })
        .await
        .map_err(|e| AppError::Kafka(format!("任务 panicked: {e}")))?
    }

    /// 批量投递
    pub async fn send_batch(&self, events: &[LogEvent]) -> Vec<(usize, Result<(), AppError>)> {
        let mut results = Vec::with_capacity(events.len());
        for (i, ev) in events.iter().enumerate() {
            let r = self.send_raw(ev).await;
            results.push((i, r));
        }
        results
    }
}
