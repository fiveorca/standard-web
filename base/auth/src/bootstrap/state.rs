//! 应用状态与服务装配。

use std::sync::Arc;
use std::time::Duration;

use ::redis::aio::ConnectionManager;
use sqlx::PgPool;

use crate::authorization::AuthzEngine;
use crate::config::{decode_master_key, Settings};
use crate::infrastructure::db;
use crate::infrastructure::notifications::{build_provider, NotificationProvider};
use crate::infrastructure::outbox::OutboxDispatcher;
use crate::infrastructure::redis;
use crate::security::{CryptoBox, KeyManager, PasswordService, SigningAlgorithm, WebauthnService};
use crate::shared::{AppError, AppResult};

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Settings>,
    pub pool: PgPool,
    pub redis: Option<ConnectionManager>,
    pub crypto: Arc<CryptoBox>,
    pub password: PasswordService,
    pub dummy_password_hash: String,
    pub keys: Arc<KeyManager>,
    pub notifier: Arc<dyn NotificationProvider>,
    pub webauthn: Option<Arc<WebauthnService>>,
    pub http: reqwest::Client,
    pub authz: AuthzEngine,
    pub outbox: Arc<OutboxDispatcher>,
    pub saml_replay: Arc<saml::InMemoryReplayCache>,
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl AppState {
    pub async fn new(settings: Settings) -> AppResult<Self> {
        let pool = db::connect(&settings.database).await?;
        let redis = redis::connect(&settings.redis).await?;
        Self::with_connections(settings, pool, redis).await
    }

    pub async fn with_connections(
        settings: Settings,
        pool: PgPool,
        redis: Option<ConnectionManager>,
    ) -> AppResult<Self> {
        let master_key = decode_master_key(&settings.security.master_key)
            .map_err(|error| AppError::server_error(format!("主密钥无效: {error}")))?;
        let crypto = Arc::new(CryptoBox::new(&master_key));
        let password = PasswordService::new(&settings.security.password)?;
        let dummy_password_hash = password.hash(crate::shared::util::random_token(24)).await?;
        let algorithm = SigningAlgorithm::parse(&settings.security.signing_algorithm)?;
        let keys = Arc::new(
            KeyManager::init(
                pool.clone(),
                crypto.clone(),
                algorithm,
                settings.security.key_rotation_days,
                settings.security.key_retain_days,
            )
            .await?,
        );

        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent(concat!("auth-center/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|error| AppError::server_error(format!("HTTP 客户端初始化失败: {error}")))?;

        let notifier = build_provider(&settings.notifications, http.clone())?;
        let webauthn = WebauthnService::new(&settings.security.mfa.webauthn)?.map(Arc::new);
        let authz = AuthzEngine::new(
            pool.clone(),
            redis.clone(),
            settings.redis.key_prefix.clone(),
            120,
        );
        let outbox = Arc::new(OutboxDispatcher::new(pool.clone(), &settings.events)?);

        Ok(Self {
            config: Arc::new(settings),
            pool,
            redis,
            crypto,
            password,
            dummy_password_hash,
            keys,
            notifier,
            webauthn,
            http,
            authz,
            outbox,
            saml_replay: Arc::new(saml::InMemoryReplayCache::new(4096)),
            started_at: chrono::Utc::now(),
        })
    }

    pub fn redis_or_err(&self) -> AppResult<&ConnectionManager> {
        self.redis
            .as_ref()
            .ok_or_else(|| AppError::unavailable("需要 Redis 的功能当前不可用"))
    }

    pub fn keys_prefix(&self) -> &str {
        &self.config.redis.key_prefix
    }

    pub fn session_key(&self, session_id: uuid::Uuid) -> String {
        format!("{}:session:{session_id}", self.keys_prefix())
    }

    pub fn access_blacklist_key(&self, jti: &str) -> String {
        format!("{}:access_bl:{jti}", self.keys_prefix())
    }

    pub fn rate_key(&self, scope: &str, identifier: &str) -> String {
        format!("{}:rl:{scope}:{identifier}", self.keys_prefix())
    }

    pub fn cache_key(&self, parts: &[&str]) -> String {
        redis::prefixed_key(self.keys_prefix(), parts)
    }

    pub fn access_audience(&self) -> &str {
        &self.config.security.access_token_audience
    }

    pub async fn readiness(&self) -> (bool, bool) {
        let db_ok = db::ping(&self.pool).await;
        let redis_ok = match &self.redis {
            Some(manager) => redis::ping(manager).await,
            None => false,
        };
        (db_ok, redis_ok)
    }
}
