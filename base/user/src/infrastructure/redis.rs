//! Redis 缓存访问（可选依赖）。

use redis::aio::ConnectionManager;
use redis::AsyncCommands;

use crate::shared::{AppError, AppResult};

pub async fn connect(url: &str) -> AppResult<Option<ConnectionManager>> {
    if url.trim().is_empty() {
        return Ok(None);
    }
    let client = redis::Client::open(url)
        .map_err(|error| AppError::server_error(format!("Redis 配置无效: {error}")))?;
    match client.get_connection_manager().await {
        Ok(manager) => Ok(Some(manager)),
        Err(error) => {
            tracing::warn!(error = %error, "Redis 连接失败，缓存功能降级");
            Ok(None)
        }
    }
}

pub async fn ping(manager: &ConnectionManager) -> bool {
    let mut connection = manager.clone();
    redis::cmd("PING")
        .query_async::<String>(&mut connection)
        .await
        .map(|value| value == "PONG")
        .unwrap_or(false)
}

pub async fn get(manager: &ConnectionManager, key: &str) -> AppResult<Option<String>> {
    let mut connection = manager.clone();
    connection
        .get(key)
        .await
        .map_err(|error| AppError::server_error(format!("Redis 读取失败: {error}")))
}

pub async fn set_ex(
    manager: &ConnectionManager,
    key: &str,
    value: &str,
    secs: u64,
) -> AppResult<()> {
    let mut connection = manager.clone();
    connection
        .set_ex::<_, _, ()>(key, value, secs.max(1))
        .await
        .map_err(|error| AppError::server_error(format!("Redis 写入失败: {error}")))
}

pub async fn del(manager: &ConnectionManager, key: &str) -> AppResult<()> {
    let mut connection = manager.clone();
    connection
        .del::<_, ()>(key)
        .await
        .map_err(|error| AppError::server_error(format!("Redis 删除失败: {error}")))
}
