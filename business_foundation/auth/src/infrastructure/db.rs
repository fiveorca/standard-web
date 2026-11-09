//! 数据库连接与迁移。

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::config::DatabaseConfig;
use crate::shared::{AppError, AppResult};

pub async fn connect(config: &DatabaseConfig) -> AppResult<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(Duration::from_secs(config.acquire_timeout_secs.max(1)))
        .connect(&config.url)
        .await
        .map_err(|error| AppError::server_error(format!("数据库连接失败: {error}")))?;

    if config.auto_migrate {
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(|error| AppError::server_error(format!("数据库迁移失败: {error}")))?;
    }
    Ok(pool)
}

pub async fn ping(pool: &PgPool) -> bool {
    sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(pool)
        .await
        .is_ok()
}
