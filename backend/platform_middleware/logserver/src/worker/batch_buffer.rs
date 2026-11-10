// ! 批量缓冲器
//
// 按 batch_max_rows / batch_max_bytes / flush_interval_ms 触发 flush。
// 线程安全 (用 tokio::sync::Mutex + 条件变量)。

use crate::config::BatchConfig;
use crate::infrastructure::clickhouse::repository::LogRow;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

#[derive(Clone)]
pub struct BatchBuffer {
    inner: Arc<Mutex<BatchBufferInner>>,
    config: BatchConfig,
}

struct BatchBufferInner {
    rows: Vec<LogRow>,
    total_bytes: usize,
    last_flush: Instant,
}

impl BatchBuffer {
    pub fn new(config: BatchConfig) -> Self {
        Self {
            inner: Arc::new(Mutex::new(BatchBufferInner {
                rows: Vec::with_capacity(config.max_rows.min(1000)),
                total_bytes: 0,
                last_flush: Instant::now(),
            })),
            config,
        }
    }

    /// 添加一行，若触发 flush 条件则返回 Ok(Some(batch))，否则 Ok(None)
    pub async fn push(&self, row: LogRow) -> Option<Vec<LogRow>> {
        let mut inner = self.inner.lock().await;
        let row_bytes = estimate_row_size(&row);
        inner.rows.push(row);
        inner.total_bytes += row_bytes;

        let should_flush =
            inner.rows.len() >= self.config.max_rows
                || inner.total_bytes >= self.config.max_bytes_mb * 1024 * 1024
                || inner.last_flush.elapsed() >= Duration::from_millis(self.config.flush_interval_ms);

        if should_flush {
            Some(self.take(&mut inner))
        } else {
            None
        }
    }

    /// 主动 flush (超时驱动)
    pub async fn try_flush_if_elapsed(&self) -> Option<Vec<LogRow>> {
        let mut inner = self.inner.lock().await;
        if !inner.rows.is_empty()
            && inner.last_flush.elapsed() >= Duration::from_millis(self.config.flush_interval_ms)
        {
            Some(self.take(&mut inner))
        } else {
            None
        }
    }

    /// 强制 flush (进程关闭时调用)
    pub async fn force_flush(&self) -> Option<Vec<LogRow>> {
        let mut inner = self.inner.lock().await;
        if inner.rows.is_empty() {
            None
        } else {
            Some(self.take(&mut inner))
        }
    }

    fn take(&self, inner: &mut BatchBufferInner) -> Vec<LogRow> {
        let rows = std::mem::take(&mut inner.rows);
        inner.total_bytes = 0;
        inner.last_flush = Instant::now();
        rows
    }
}

fn estimate_row_size(row: &LogRow) -> usize {
    // 粗略估算：各字段字符串长度之和
    let mut s = row.message.len()
        + row.service_name.len()
        + row.schema_version.len()
        + row.level.len()
        + row.attributes_json.len()
        + row.trace_id.len()
        + row.request_id.len()
        + row.exception_message.len()
        + row.stack_trace.len();
    // 固定开销
    s += 256;
    s
}
