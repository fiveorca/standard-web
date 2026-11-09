//! 应用状态与基础设施装配。

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::redis::aio::ConnectionManager;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tokio::sync::Mutex;

use crate::auth_client::{AuthClient, AuthContext};
use crate::config::Settings;
use crate::infrastructure::{outbox::OutboxDispatcher, redis};
use crate::shared::{AppError, AppResult};

pub struct AppState {
    pub config: Settings,
    pub pool: PgPool,
    pub redis: Option<ConnectionManager>,
    pub auth: Arc<AuthClient>,
    pub outbox: Arc<OutboxDispatcher>,
    limits: Mutex<HashMap<String, (u32, Instant)>>,
    permission_cache: Mutex<HashMap<String, (bool, Instant)>>,
}

impl AppState {
    pub async fn new(config: Settings) -> AppResult<Arc<Self>> {
        let pool = PgPoolOptions::new()
            .max_connections(config.database.max_connections.max(1))
            .min_connections(config.database.min_connections)
            .acquire_timeout(Duration::from_secs(
                config.database.acquire_timeout_secs.max(1),
            ))
            .connect(&config.database.url)
            .await
            .map_err(|error| AppError::server_error(format!("连接数据库失败: {error}")))?;
        if config.database.auto_migrate {
            sqlx::migrate!("./migrations")
                .run(&pool)
                .await
                .map_err(|error| AppError::server_error(format!("执行数据库迁移失败: {error}")))?;
        }
        let redis_client = redis::connect(&config.redis.url).await?;
        if config.redis.required && redis_client.is_none() {
            return Err(AppError::server_error("Redis 为必需依赖但当前不可用"));
        }
        let auth = AuthClient::new(
            config.auth.clone(),
            redis_client.clone(),
            config.redis.clone(),
        );
        let outbox = OutboxDispatcher::new(pool.clone(), &config, reqwest::Client::new());
        Ok(Arc::new(Self {
            config,
            pool,
            redis: redis_client,
            auth,
            outbox,
            limits: Mutex::new(HashMap::new()),
            permission_cache: Mutex::new(HashMap::new()),
        }))
    }

    pub async fn readiness(&self) -> (bool, bool) {
        let db_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&self.pool)
            .await
            .is_ok();
        let redis_ok = match &self.redis {
            Some(manager) => redis::ping(manager).await,
            None => false,
        };
        (db_ok, redis_ok)
    }

    /// 固定窗口内存限流；用于注册与验证码触发等敏感入口。
    pub async fn allow(&self, key: &str, limit: u32, window: Duration) -> bool {
        let limit = limit.max(1);
        let mut guard = self.limits.lock().await;
        let now = Instant::now();
        let entry = guard.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) >= window {
            *entry = (1, now);
            return true;
        }
        if entry.0 >= limit {
            return false;
        }
        entry.0 += 1;
        true
    }

    /// 校验管理员权限：委托认证中心授权引擎并做短 TTL 缓存。
    pub async fn require_permission(&self, ctx: &AuthContext, permission: &str) -> AppResult<()> {
        if ctx.scopes.iter().any(|scope| scope == "internal") {
            return Ok(());
        }
        let cache_key = format!(
            "{}:perm:{}:{}:{}",
            self.config.redis.key_prefix, ctx.tenant_id, ctx.identity_id, permission
        );
        if let Some(manager) = &self.redis {
            if let Ok(Some(value)) = redis::get(manager, &cache_key).await {
                if value == "1" {
                    return Ok(());
                }
            }
        } else {
            let guard = self.permission_cache.lock().await;
            if let Some((allowed, expires_at)) = guard.get(&cache_key) {
                if *expires_at > Instant::now() {
                    if *allowed {
                        return Ok(());
                    }
                    return Err(AppError::forbidden("没有执行该操作的权限"));
                }
            }
        }

        let decision = self
            .auth
            .authorize(ctx.tenant_id, ctx.identity_id, permission, None)
            .await?;
        if let Some(manager) = &self.redis {
            let _ = redis::set_ex(
                manager,
                &cache_key,
                if decision.allowed { "1" } else { "0" },
                30,
            )
            .await;
        } else {
            let mut guard = self.permission_cache.lock().await;
            guard.insert(
                cache_key,
                (decision.allowed, Instant::now() + Duration::from_secs(30)),
            );
            if guard.len() > 4096 {
                let now = Instant::now();
                guard.retain(|_, (_, expires_at)| *expires_at > now);
            }
        }
        if decision.allowed {
            Ok(())
        } else {
            Err(AppError::forbidden("没有执行该操作的权限"))
        }
    }

    /// 使某租户或身份的权限缓存失效（本地 + Redis 短 TTL 自然过期）。
    pub async fn invalidate_permission_cache(&self, identity_id: Option<uuid::Uuid>) {
        let mut guard = self.permission_cache.lock().await;
        if let Some(identity_id) = identity_id {
            let marker = format!(":{identity_id}:");
            guard.retain(|key, _| !key.contains(&marker));
        } else {
            guard.clear();
        }
    }
}
