// ! Kafka 消费循环
//
// 核心可靠消费逻辑：
// 1. 从 Kafka 拉消息
// 2. JSON 解析 / 校验 / 脱敏
// 3. 成功 → 写入 batch buffer → 批量写 ClickHouse
// 4. 持久化成功后提交 Offset
// 5. 解析/校验失败 → DLQ + 跳过
// 6. ClickHouse 不可用 → 退避重试，保持 Offset 不提交

use crate::common::error::{AppError, DlqStage};
use crate::config::{BatchConfig, ClickHouseConfig, KafkaConfig, SecurityConfig};
use crate::infrastructure::clickhouse::ClickHouse;
use crate::infrastructure::kafka::consumer::LogConsumer;
use crate::infrastructure::kafka::producer::LogProducer;
use crate::worker::dlq::DlqWriter;
use crate::worker::processor::MessageProcessor;
use crate::worker::writer::LogWriter;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tracing::{error, info, warn};

/// 启动 Worker 消费循环
pub async fn run_consumer_loop(
    kafka_cfg: &KafkaConfig,
    clickhouse_cfg: &ClickHouseConfig,
    batch_cfg: BatchConfig,
    security_cfg: SecurityConfig,
) -> Result<(), AppError> {
    info!("=== Worker 启动 ===");

    let mut consumer = LogConsumer::new(kafka_cfg)?;
    let producer = LogProducer::new(kafka_cfg)?;
    let db = Arc::new(ClickHouse::new(clickhouse_cfg));
    let writer = LogWriter::new(db.clone(), batch_cfg.clone());
    let processor = MessageProcessor::new(security_cfg);
    let dlq = DlqWriter::new(db.clone(), producer);

    // 预先检查 ClickHouse 连通性 (失败不阻塞)
    if let Err(e) = db.ping().await {
        warn!(?e, "ClickHouse 初始 ping 失败，Worker 继续启动（运行中会重试）");
    } else {
        info!("ClickHouse 连通");
    }

    consumer.subscribe()?;

    // 任务：定时 flush
    let writer_clone = writer.clone();
    let flush_handle = tokio::spawn(async move {
        let tick = Duration::from_millis(batch_cfg.flush_interval_ms.max(100));
        let mut interval = tokio::time::interval(tick);
        loop {
            interval.tick().await;
            if let Err(e) = writer_clone.periodic_flush().await {
                error!(?e, "periodic flush 失败");
            }
        }
    });

    // 任务：消费循环
    let writer_for_loop = writer.clone();
    let consumer_handle = tokio::spawn(async move {
        run_inner(consumer, processor, writer_for_loop, dlq).await;
    });

    // 等待退出信号
    tokio::select! {
        _ = consumer_handle => {
            info!("消费循环结束");
        }
        _ = signal::ctrl_c() => {
            info!("收到 Ctrl+C，准备优雅关闭");
        }
    }

    flush_handle.abort();

    info!("Worker: 强制 flush 最后一批...");
    let _ = writer.force_flush().await;
    info!("Worker: 关闭完成");

    Ok(())
}

async fn run_inner(
    mut consumer: LogConsumer,
    processor: MessageProcessor,
    writer: LogWriter,
    dlq: DlqWriter,
) {
    loop {
        let raw = match consumer.next().await {
            Ok(m) => m,
            Err(AppError::Kafka(msg)) => {
                warn!("Kafka 消费错误: {msg}，退避重试");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
            Err(e) => {
                error!(?e, "Kafka 消费错误");
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }
        };

        let payload = &raw.payload;
        let event_id = raw.event_id.as_ref().and_then(|s| uuid::Uuid::parse_str(s).ok());

        // 1) JSON 解析 + 校验 + 脱敏
        let processed = match processor.parse(payload) {
            Ok(p) => p,
            Err(msg) => {
                error!(stage = DlqStage::Parse.as_str(), reason = %msg, "消息解析失败，进 DLQ");
                dlq.write(
                    event_id,
                    payload,
                    &msg,
                    DlqStage::Parse.as_str(),
                    &raw.topic,
                    raw.partition,
                    raw.offset,
                )
                .await;
                continue;
            }
        };

        // 2) 写入 ClickHouse
        match writer.accept(processed.event).await {
            Ok(_) => {}
            Err(AppError::ClickHouse(msg)) => {
                error!(?msg, "ClickHouse 不可用，退避重试");
                tokio::time::sleep(Duration::from_millis(2000)).await;
                continue;
            }
            Err(e) => {
                error!(?e, "Writer 错误，进 DLQ 后跳过");
                dlq.write(
                    event_id,
                    payload,
                    &e.to_string(),
                    DlqStage::ClickHouse.as_str(),
                    &raw.topic,
                    raw.partition,
                    raw.offset,
                )
                .await;
            }
        }
    }
}
