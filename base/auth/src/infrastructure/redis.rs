//! Redis 连接、限流与缓存辅助。

use std::time::Duration;

use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::config::RedisConfig;
use crate::shared::{AppError, AppResult};

pub async fn connect(config: &RedisConfig) -> AppResult<Option<ConnectionManager>> {
    let client = redis::Client::open(config.url.as_str())
        .map_err(|error| AppError::server_error(format!("Redis 配置错误: {error}")))?;
    match client.get_connection_manager().await {
        Ok(manager) => Ok(Some(manager)),
        Err(error) if !config.required => {
            tracing::warn!(error = %error, "Redis 不可用，服务以降级模式启动");
            Ok(None)
        }
        Err(error) => Err(AppError::unavailable(format!("Redis 连接失败: {error}"))),
    }
}

pub async fn ping(manager: &ConnectionManager) -> bool {
    let mut conn = manager.clone();
    redis::cmd("PING")
        .query_async::<String>(&mut conn)
        .await
        .map(|value| value == "PONG")
        .unwrap_or(false)
}

pub async fn set_ex(
    manager: &ConnectionManager,
    key: &str,
    value: &str,
    ttl_secs: u64,
) -> AppResult<()> {
    let mut conn = manager.clone();
    let _: () = redis::cmd("SET")
        .arg(key)
        .arg(value)
        .arg("EX")
        .arg(ttl_secs.max(1))
        .query_async(&mut conn)
        .await?;
    Ok(())
}

pub async fn set_ex_nx(
    manager: &ConnectionManager,
    key: &str,
    value: &str,
    ttl_secs: u64,
) -> AppResult<bool> {
    let mut conn = manager.clone();
    let result: Option<String> = redis::cmd("SET")
        .arg(key)
        .arg(value)
        .arg("EX")
        .arg(ttl_secs.max(1))
        .arg("NX")
        .query_async(&mut conn)
        .await?;
    Ok(result.is_some())
}

pub async fn get(manager: &ConnectionManager, key: &str) -> AppResult<Option<String>> {
    let mut conn = manager.clone();
    let value: Option<String> = conn.get(key).await?;
    Ok(value)
}

pub async fn del(manager: &ConnectionManager, key: &str) -> AppResult<()> {
    let mut conn = manager.clone();
    let _: i64 = conn.del(key).await?;
    Ok(())
}

pub async fn ttl(manager: &ConnectionManager, key: &str) -> AppResult<i64> {
    let mut conn = manager.clone();
    let value: i64 = conn.ttl(key).await?;
    Ok(value)
}

pub async fn set_json<T: Serialize>(
    manager: &ConnectionManager,
    key: &str,
    value: &T,
    ttl_secs: u64,
) -> AppResult<()> {
    let encoded = serde_json::to_string(value)?;
    set_ex(manager, key, &encoded, ttl_secs).await
}

pub async fn get_json<T: DeserializeOwned>(
    manager: &ConnectionManager,
    key: &str,
) -> AppResult<Option<T>> {
    let value = get(manager, key).await?;
    match value {
        None => Ok(None),
        Some(raw) => serde_json::from_str(&raw).map(Some).map_err(|error| {
            tracing::warn!(error = %error, key = %key, "缓存的 JSON 数据损坏");
            AppError::server_error("缓存数据损坏")
        }),
    }
}

/// 简单的固定窗口限流。返回 `Some(retry_after)` 表示被限流。
pub async fn rate_limit(
    manager: &ConnectionManager,
    key: &str,
    max_attempts: u32,
    window_secs: u64,
) -> AppResult<Option<u64>> {
    let mut conn = manager.clone();
    let count: i64 = redis::cmd("INCR").arg(key).query_async(&mut conn).await?;
    if count == 1 {
        let _: i64 = redis::cmd("EXPIRE")
            .arg(key)
            .arg(window_secs.max(1))
            .query_async(&mut conn)
            .await?;
    }
    if count > i64::from(max_attempts) {
        let retry = ttl(manager, key).await.unwrap_or(window_secs as i64).max(1) as u64;
        Ok(Some(retry))
    } else {
        Ok(None)
    }
}

/// 分布式一次性标记，用于 SAML 断言等重放防护。
pub async fn mark_once(manager: &ConnectionManager, key: &str, ttl_secs: u64) -> AppResult<bool> {
    set_ex_nx(manager, key, "1", ttl_secs).await
}

pub async fn increment(manager: &ConnectionManager, key: &str, ttl_secs: u64) -> AppResult<i64> {
    let mut conn = manager.clone();
    let value: i64 = redis::cmd("INCR").arg(key).query_async(&mut conn).await?;
    if value == 1 && ttl_secs > 0 {
        let _: i64 = redis::cmd("EXPIRE")
            .arg(key)
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await?;
    }
    Ok(value)
}

pub fn prefixed_key(prefix: &str, parts: &[&str]) -> String {
    let mut key = String::from(prefix);
    for part in parts {
        key.push(':');
        key.push_str(part);
    }
    key
}

/// 生成带过期时间的 TTL（秒）。
pub fn seconds_until(target: chrono::DateTime<chrono::Utc>) -> u64 {
    let now = chrono::Utc::now();
    if target <= now {
        1
    } else {
        (target - now).num_seconds().max(1) as u64
    }
}

pub fn default_timeout() -> Duration {
    Duration::from_secs(5)
}
