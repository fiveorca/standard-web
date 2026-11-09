//! 事务性 Outbox：业务写入与事件写入在同一数据库事务中，后台任务可靠投递。
//!
//! 消费端通过 Inbox 表按 `(event_id, consumer)` 幂等处理。当前采用 HTTP Webhook
//! 投递，可替换为 Kafka/RabbitMQ 等消息中间件而不改变业务代码。

use std::time::Duration;

use serde_json::json;
use sqlx::{PgPool, Postgres, Transaction};

use crate::config::EventsConfig;
use crate::domain::{DomainEvent, OutboxEventRow};
use crate::shared::{now, AppError, AppResult};

/// 在业务事务中写入事件。
pub async fn enqueue(tx: &mut Transaction<'_, Postgres>, event: &DomainEvent) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO outbox_events
            (id, event_type, aggregate_type, aggregate_id, payload, trace_id, version, occurred_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(event.event_id)
    .bind(&event.event_type)
    .bind(&event.aggregate_type)
    .bind(&event.aggregate_id)
    .bind(&event.payload)
    .bind(&event.trace_id)
    .bind(event.version)
    .bind(event.occurred_at)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub struct OutboxDispatcher {
    pool: PgPool,
    client: reqwest::Client,
    publish_urls: Vec<String>,
    service_token: String,
    batch_size: i64,
    max_attempts: i32,
    poll_interval: Duration,
    allow_http_targets: bool,
}

impl OutboxDispatcher {
    pub fn new(pool: PgPool, config: &EventsConfig) -> AppResult<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| AppError::server_error(format!("HTTP 客户端初始化失败: {error}")))?;
        Ok(Self {
            pool,
            client,
            publish_urls: config.publish_urls.clone(),
            service_token: config.service_token.clone(),
            batch_size: config.batch_size.clamp(1, 500),
            max_attempts: config.max_attempts.max(1),
            poll_interval: Duration::from_secs(config.poll_interval_secs.max(1)),
            allow_http_targets: config.allow_http_targets,
        })
    }

    /// 启动后台投递循环。
    pub fn spawn(self: std::sync::Arc<Self>) {
        tokio::spawn(async move {
            tracing::info!(
                targets = self.publish_urls.len(),
                "outbox dispatcher started"
            );
            loop {
                match self.dispatch_once().await {
                    Ok(processed) if processed > 0 => {
                        tracing::debug!(processed, "outbox batch dispatched");
                    }
                    Ok(_) => {}
                    Err(error) => {
                        tracing::error!(error = %error, "outbox dispatch cycle failed");
                    }
                }
                tokio::time::sleep(self.poll_interval).await;
            }
        });
    }

    pub async fn dispatch_once(&self) -> AppResult<usize> {
        let rows = self.claim_batch().await?;
        let count = rows.len();
        for row in rows {
            let event_id = row.id;
            match self.publish(&row).await {
                Ok(()) => {
                    sqlx::query(
                        "UPDATE outbox_events SET status = 'published', published_at = now(), last_error = NULL
                         WHERE id = $1",
                    )
                    .bind(event_id)
                    .execute(&self.pool)
                    .await?;
                }
                Err(error) => {
                    let message = error.to_string();
                    let attempts = row.attempts;
                    let dead = attempts >= self.max_attempts;
                    let backoff = backoff_seconds(attempts);
                    if dead {
                        tracing::error!(event_id = %event_id, event_type = %row.event_type, attempts, "outbox event moved to dead letter");
                    } else {
                        tracing::warn!(event_id = %event_id, attempts, error = %message, "outbox delivery failed, will retry");
                    }
                    sqlx::query(
                        "UPDATE outbox_events
                         SET status = $2,
                             last_error = $3,
                             next_attempt_at = now() + make_interval(secs => $4)
                         WHERE id = $1",
                    )
                    .bind(event_id)
                    .bind(if dead { "dead" } else { "pending" })
                    .bind(truncate(&message, 500))
                    .bind(backoff as f64)
                    .execute(&self.pool)
                    .await?;
                }
            }
        }
        Ok(count)
    }

    async fn claim_batch(&self) -> AppResult<Vec<OutboxEventRow>> {
        let rows = sqlx::query_as::<_, OutboxEventRow>(
            "WITH claimed AS (
                SELECT id FROM outbox_events
                WHERE status = 'pending' AND next_attempt_at <= now()
                ORDER BY occurred_at
                LIMIT $1
                FOR UPDATE SKIP LOCKED
             )
             UPDATE outbox_events o
             SET status = 'publishing', attempts = o.attempts + 1
             FROM claimed c
             WHERE o.id = c.id
             RETURNING o.id, o.event_type, o.aggregate_type, o.aggregate_id, o.payload,
                       o.trace_id, o.version, o.occurred_at, o.status, o.attempts,
                       o.last_error, o.next_attempt_at, o.published_at, o.created_at",
        )
        .bind(self.batch_size)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    async fn publish(&self, row: &OutboxEventRow) -> AppResult<()> {
        if self.publish_urls.is_empty() {
            tracing::debug!(event_id = %row.id, event_type = %row.event_type, "未配置事件投递地址，事件保留为已发布（单机模式）");
            return Ok(());
        }
        let payload = json!({
            "event_id": row.id,
            "event_type": row.event_type,
            "aggregate_type": row.aggregate_type,
            "aggregate_id": row.aggregate_id,
            "occurred_at": row.occurred_at,
            "version": row.version,
            "trace_id": row.trace_id,
            "payload": row.payload,
        });
        for url in &self.publish_urls {
            if !self.allow_http_targets {
                crate::security::redirect::validate_external_url(url, false)?;
            }
            let mut request = self.client.post(url).json(&payload);
            if !self.service_token.is_empty() {
                request = request.header("x-internal-token", &self.service_token);
            }
            let response = request
                .send()
                .await
                .map_err(|error| AppError::unavailable(format!("投递到 {url} 失败: {error}")))?;
            if !response.status().is_success() {
                return Err(AppError::unavailable(format!(
                    "投递到 {url} 返回状态 {}",
                    response.status()
                )));
            }
        }
        Ok(())
    }
}

fn backoff_seconds(attempts: i32) -> i64 {
    let exponent = attempts.clamp(1, 8) as u32;
    (2_i64.pow(exponent)).min(300)
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

/// 消费端 Inbox 辅助：返回 true 表示首次接收。
pub async fn inbox_accept(
    pool: &PgPool,
    consumer: &str,
    event_id: uuid::Uuid,
    event_type: &str,
    payload: &serde_json::Value,
) -> AppResult<bool> {
    let inserted: Option<(uuid::Uuid,)> = sqlx::query_as(
        "INSERT INTO inbox_events (event_id, consumer, event_type, payload)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (event_id, consumer) DO NOTHING
         RETURNING event_id",
    )
    .bind(event_id)
    .bind(consumer)
    .bind(event_type)
    .bind(payload)
    .fetch_optional(pool)
    .await?;
    if inserted.is_some() {
        return Ok(true);
    }
    let status: Option<(String,)> =
        sqlx::query_as("SELECT status FROM inbox_events WHERE event_id = $1 AND consumer = $2")
            .bind(event_id)
            .bind(consumer)
            .fetch_optional(pool)
            .await?;
    Ok(!matches!(
        status.as_ref().map(|s| s.0.as_str()),
        Some("processed")
    ))
}

pub async fn inbox_mark(
    pool: &PgPool,
    consumer: &str,
    event_id: uuid::Uuid,
    success: bool,
    error: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE inbox_events
         SET status = $3,
             attempts = attempts + 1,
             last_error = $4,
             processed_at = CASE WHEN $3 = 'processed' THEN now() ELSE processed_at END
         WHERE event_id = $1 AND consumer = $2",
    )
    .bind(event_id)
    .bind(consumer)
    .bind(if success { "processed" } else { "failed" })
    .bind(error.map(|value| truncate(value, 500)))
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn pending_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM outbox_events WHERE status IN ('pending', 'publishing')",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0)
}

pub fn event_now() -> chrono::DateTime<chrono::Utc> {
    now()
}
