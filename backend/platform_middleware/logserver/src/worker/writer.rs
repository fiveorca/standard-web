// ! 批量写入 ClickHouse 的 Writer
//
// 在 Worker 消费循环中被调用，执行实际的批量 INSERT。

use crate::config::BatchConfig;
use crate::domain::LogEvent;
use crate::infrastructure::clickhouse::client::ClickHouse;
use crate::infrastructure::clickhouse::repository::{LogRepository, LogRow};
use crate::worker::batch_buffer::BatchBuffer;
use chrono::Utc;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{error, info};

#[derive(Clone)]
pub struct LogWriter {
    repo: LogRepository<'static>,
    buffer: BatchBuffer,
    concurrency: Arc<Semaphore>,
    ingest_counter: Arc<std::sync::atomic::AtomicU64>,
}

impl LogWriter {
    pub fn new(db: Arc<ClickHouse>, batch_cfg: BatchConfig) -> Self {
        // 使用 Box::leak 让 repo 拥有 'static 生命周期
        // 这在长生命周期进程中是可接受的
        let leaked_db: &'static ClickHouse = Box::leak(Box::new((*db).clone()));
        let repo = LogRepository::new(leaked_db);

        Self {
            repo,
            buffer: BatchBuffer::new(batch_cfg.clone()),
            concurrency: Arc::new(Semaphore::new(batch_cfg.max_concurrent_inserts.max(1))),
            ingest_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// 处理一条解析后的 LogEvent，写入 buffer，必要时 flush
    pub async fn accept(&self, event: LogEvent) -> Result<(), crate::common::error::AppError> {
        let ingest_time = Utc::now();
        let version = self
            .ingest_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let row = LogRow::from_event(&event, ingest_time, version);

        if let Some(batch) = self.buffer.push(row).await {
            self.write_batch(batch).await?;
        }
        Ok(())
    }

    /// 定时检查并 flush 缓冲
    pub async fn periodic_flush(&self) -> Result<(), crate::common::error::AppError> {
        if let Some(batch) = self.buffer.try_flush_if_elapsed().await {
            self.write_batch(batch).await?;
        }
        Ok(())
    }

    /// 关闭前强制 flush
    pub async fn force_flush(&self) -> Result<(), crate::common::error::AppError> {
        if let Some(batch) = self.buffer.force_flush().await {
            self.write_batch(batch).await?;
        }
        Ok(())
    }

    async fn write_batch(&self, batch: Vec<LogRow>) -> Result<(), crate::common::error::AppError> {
        let permit = self
            .concurrency
            .clone()
            .acquire_owned()
            .await
            .expect("semaphore must not be closed");

        let repo = self.repo.clone();
        let handle = tokio::spawn(async move {
            let _permit = permit;
            let start = std::time::Instant::now();
            match repo.bulk_insert(&batch).await {
                Ok(count) => {
                    info!(
                        rows = count,
                        batch_ms = start.elapsed().as_millis() as u64,
                        "ClickHouse 批量写入完成"
                    );
                    Ok(())
                }
                Err(e) => {
                    error!(?e, "ClickHouse 批量写入失败");
                    Err(e)
                }
            }
        });

        handle.await.map_err(|e| {
            crate::common::error::AppError::ClickHouse(format!("写入任务 panic: {e}"))
        })?
    }
}
