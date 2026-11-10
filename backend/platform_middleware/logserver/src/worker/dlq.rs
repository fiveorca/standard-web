// ! DLQ 写入

use crate::infrastructure::clickhouse::client::ClickHouse;
use crate::infrastructure::clickhouse::repository::{DlqRow, LogRepository};
use crate::infrastructure::kafka::producer::LogProducer;
use chrono::Utc;
use std::sync::Arc;
use tracing::{error, warn};

/// DLQ 写入器
///
/// 双写：ClickHouse dlq_logs 表 + Kafka logs.dlq.v1 topic
pub struct DlqWriter {
    db: Arc<ClickHouse>,
    producer: Arc<LogProducer>,
}

impl DlqWriter {
    pub fn new(db: Arc<ClickHouse>, producer: LogProducer) -> Self {
        Self {
            db,
            producer: Arc::new(producer),
        }
    }

    pub async fn write(
        &self,
        event_id: Option<uuid::Uuid>,
        payload: &[u8],
        reason: &str,
        stage: &str,
        kafka_topic: &str,
        kafka_partition: i32,
        kafka_offset: i64,
    ) {
        let row = DlqRow {
            event_id,
            original_payload: String::from_utf8_lossy(payload).to_string(),
            error_reason: reason.to_string(),
            error_stage: stage.to_string(),
            failed_at: Utc::now(),
            kafka_topic: kafka_topic.to_string(),
            kafka_partition,
            kafka_offset,
        };
        let db = self.db.clone();
        let _ = tokio::spawn(async move {
            let repo = LogRepository::leak_new(&db);
            if let Err(e) = repo.insert_dlq(&row).await {
                error!(?e, "ClickHouse DLQ 写入失败");
            }
        })
        .await;

        // Kafka DLQ topic 也尽力而为
        if let Err(e) = self.producer.send_dlq(payload, reason, stage).await {
            warn!(?e, "Kafka DLQ 投递失败");
        }
    }
}
