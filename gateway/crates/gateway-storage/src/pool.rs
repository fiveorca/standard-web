//! PostgreSQL 连接池与迁移执行。
//!
//! # 约束
//!
//! - 连接串只在启动时读取，不写日志、不出现在错误信息的前端响应中
//! - 连接池参数有默认值，并做边界校验（`max_connections` 不能为 0）
//! - 迁移通过 `sqlx::migrate!` 在编译期嵌入，不依赖运行目录

use std::time::Duration;

use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use crate::error::StorageError;

/// 连接池配置。
#[derive(Debug, Clone)]
pub struct PoolSettings {
    /// 最大连接数（默认 10）
    pub max_connections: u32,
    /// 获取连接的超时（秒，默认 5）
    pub acquire_timeout_secs: u64,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            max_connections: 10,
            acquire_timeout_secs: 5,
        }
    }
}

/// 创建 PostgreSQL 连接池。
///
/// # 参数
/// - `database_url`：PostgreSQL 连接串（例如 `postgres://user:pass@host/db`）
/// - `settings`：连接池参数
///
/// # 返回
/// - `Ok(PgPool)`：连接池创建成功（不会立即建立连接）
/// - `Err(StorageError)`：参数非法或连接串格式错误
pub async fn create_pool(
    database_url: &str,
    settings: PoolSettings,
) -> Result<PgPool, StorageError> {
    // 参数校验：0 连接会让后续所有请求永久等待
    if settings.max_connections == 0 {
        return Err(StorageError::invalid_payload(
            "pool max_connections must be >= 1",
        ));
    }
    if database_url.trim().is_empty() {
        return Err(StorageError::invalid_payload("database url must not be empty"));
    }

    PgPoolOptions::new()
        .max_connections(settings.max_connections)
        .acquire_timeout(Duration::from_secs(settings.acquire_timeout_secs))
        .connect(database_url)
        .await
        // From<sqlx::Error> 已做敏感信息截断
        .map_err(StorageError::from)
}

/// 执行内置迁移。
///
/// `sqlx::migrate!` 在编译期把 `migrations/` 目录嵌入二进制，
/// 因此运行时不依赖工作目录，也不会因为缺少迁移文件而失败。
pub async fn run_migrations(pool: &PgPool) -> Result<(), StorageError> {
    sqlx::migrate!("./migrations")
        .run(pool)
        .await
        .map_err(|e| StorageError::Database {
            message: format!("migration failed: {e}"),
        })
}

/// 连接并执行迁移（控制面启动时的便捷入口）。
pub async fn connect_and_migrate(
    database_url: &str,
    settings: PoolSettings,
) -> Result<PgPool, StorageError> {
    let pool = create_pool(database_url, settings).await?;
    run_migrations(&pool).await?;
    tracing::info!("control plane database connected and migrated");
    Ok(pool)
}
