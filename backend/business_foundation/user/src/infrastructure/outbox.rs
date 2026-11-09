//! 事务性 Outbox / Inbox 与事件投递。

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::config::Settings;
use crate::shared::{AppError, AppResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxEvent {
    #[serde(rename = "event_id")]
    pub id: Uuid,
    pub event_type: String,
    pub aggregate_type: String,
    pub aggregate_id: String,
    pub payload: Value,
    pub trace_id: Option<String>,
    pub version: i32,
    pub occurred_at: DateTime<Utc>,
}

impl OutboxEvent {
    pub fn new(
        event_type: impl Into<String>,
        aggregate_type: impl Into<String>,
        aggregate_id: impl Into<String>,
        payload: Value,
    ) -> Self {
        Self {
            id: Uuid::now_v7(),
            event_type: event_type.into(),
            aggregate_type: aggregate_type.into(),
            aggregate_id: aggregate_id.into(),
            payload,
            trace_id: None,
            version: 1,
            occurred_at: Utc::now(),
        }
    }

    pub fn with_trace(mut self, trace_id: Option<String>) -> Self {
        self.trace_id = trace_id;
        self
    }
}

pub async fn enqueue(tx: &mut Transaction<'_, Postgres>, event: &OutboxEvent) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO outbox_events
            (id, event_type, aggregate_type, aggregate_id, payload, trace_id, version, occurred_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(event.id)
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

pub async fn inbox_accept(
    pool: &PgPool,
    consumer: &str,
    event_id: Uuid,
    event_type: &str,
    payload: &Value,
) -> AppResult<bool> {
    let result = sqlx::query(
        "INSERT INTO inbox_events (event_id, consumer, event_type, payload, status)
         VALUES ($1, $2, $3, $4, 'failed')
         ON CONFLICT (event_id, consumer) DO NOTHING",
    )
    .bind(event_id)
    .bind(consumer)
    .bind(event_type)
    .bind(payload)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() == 1)
}

pub async fn inbox_mark(
    pool: &PgPool,
    consumer: &str,
    event_id: Uuid,
    success: bool,
    error: Option<&str>,
) -> AppResult<()> {
    sqlx::query(
        "UPDATE inbox_events
            SET status = $3, error = $4, processed_at = now()
          WHERE event_id = $1 AND consumer = $2",
    )
    .bind(event_id)
    .bind(consumer)
    .bind(if success { "processed" } else { "failed" })
    .bind(error)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Debug, FromRow)]
struct OutboxRow {
    id: Uuid,
    event_type: String,
    aggregate_type: String,
    aggregate_id: String,
    payload: Value,
    trace_id: Option<String>,
    version: i32,
    occurred_at: DateTime<Utc>,
    attempts: i32,
}

/// 事件投递器：将 Outbox 中的事件投递到认证中心。
pub struct OutboxDispatcher {
    pool: PgPool,
    client: reqwest::Client,
    endpoint: String,
    internal_token: String,
    interval: Duration,
    max_attempts: i32,
}

impl OutboxDispatcher {
    pub fn new(pool: PgPool, settings: &Settings, client: reqwest::Client) -> Arc<Self> {
        let endpoint = format!("{}/api/v1/internal/events", settings.auth_base_url());
        Arc::new(Self {
            pool,
            client,
            endpoint,
            internal_token: settings.auth.internal_token.clone(),
            interval: Duration::from_secs(settings.batch.outbox_poll_interval_secs.max(1)),
            max_attempts: settings.batch.outbox_max_attempts.max(1),
        })
    }

    pub fn spawn(self: Arc<Self>) {
        tokio::spawn(async move {
            tracing::info!(interval = ?self.interval, "用户中心 Outbox 投递器已启动");
            let mut ticker = tokio::time::interval(self.interval);
            loop {
                ticker.tick().await;
                match self.dispatch_once().await {
                    Ok(0) => {}
                    Ok(count) => tracing::debug!(count, "Outbox 事件已投递"),
                    Err(error) => tracing::error!(error = %error, "Outbox 投递周期失败"),
                }
            }
        });
    }

    async fn dispatch_once(&self) -> AppResult<usize> {
        if self.internal_token.is_empty() {
            return Ok(0);
        }
        let mut tx = self.pool.begin().await?;
        let rows: Vec<OutboxRow> = sqlx::query_as(
            "SELECT id, event_type, aggregate_type, aggregate_id, payload,
                    trace_id, version, occurred_at, attempts
               FROM outbox_events
              WHERE published_at IS NULL
                AND dead_lettered_at IS NULL
                AND next_attempt_at <= now()
              ORDER BY occurred_at
              LIMIT 20
                FOR UPDATE SKIP LOCKED",
        )
        .fetch_all(&mut *tx)
        .await?;
        if rows.is_empty() {
            tx.commit().await?;
            return Ok(0);
        }
        for row in &rows {
            sqlx::query(
                "UPDATE outbox_events SET next_attempt_at = now() + interval '60 seconds'
                  WHERE id = $1",
            )
            .bind(row.id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;

        let mut delivered = 0;
        for row in rows {
            match self.deliver(&row).await {
                Ok(()) => {
                    sqlx::query(
                        "UPDATE outbox_events
                            SET published_at = now(), last_error = NULL, attempts = attempts + 1
                          WHERE id = $1",
                    )
                    .bind(row.id)
                    .execute(&self.pool)
                    .await?;
                    delivered += 1;
                }
                Err(error) => {
                    let attempts = row.attempts + 1;
                    let message = error.to_string();
                    if attempts >= self.max_attempts {
                        sqlx::query(
                            "UPDATE outbox_events
                                SET attempts = $2, last_error = $3, dead_lettered_at = now()
                              WHERE id = $1",
                        )
                        .bind(row.id)
                        .bind(attempts)
                        .bind(&message)
                        .execute(&self.pool)
                        .await?;
                        tracing::error!(
                            event_id = %row.id,
                            event_type = %row.event_type,
                            attempts,
                            "Outbox 事件进入死信"
                        );
                    } else {
                        let backoff = (5_i64 * 2_i64.pow(attempts.min(6) as u32)).min(3600);
                        sqlx::query(
                            "UPDATE outbox_events
                                SET attempts = $2, last_error = $3,
                                    next_attempt_at = now() + make_interval(secs => $4)
                              WHERE id = $1",
                        )
                        .bind(row.id)
                        .bind(attempts)
                        .bind(&message)
                        .bind(backoff as f64)
                        .execute(&self.pool)
                        .await?;
                        tracing::warn!(
                            event_id = %row.id,
                            attempts,
                            error = %message,
                            "Outbox 投递失败，稍后重试"
                        );
                    }
                }
            }
        }
        Ok(delivered)
    }

    async fn deliver(&self, row: &OutboxRow) -> AppResult<()> {
        let envelope = OutboxEvent {
            id: row.id,
            event_type: row.event_type.clone(),
            aggregate_type: row.aggregate_type.clone(),
            aggregate_id: row.aggregate_id.clone(),
            payload: row.payload.clone(),
            trace_id: row.trace_id.clone(),
            version: row.version,
            occurred_at: row.occurred_at,
        };
        let response = self
            .client
            .post(&self.endpoint)
            .header("x-internal-token", &self.internal_token)
            .json(&envelope)
            .send()
            .await
            .map_err(|error| AppError::server_error(format!("投递事件失败: {error}")))?;
        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(AppError::server_error(format!(
                "认证中心拒绝事件 ({status}): {}",
                body.chars().take(200).collect::<String>()
            )));
        }
        Ok(())
    }
}
