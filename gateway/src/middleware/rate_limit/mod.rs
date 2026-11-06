//! 限流：本地 Token Bucket + Redis Lua 原子限流。
//!
//! - 本地模式使用进程内令牌桶，适合单实例部署。
//! - Redis 模式使用 Lua 脚本原子地读取、补充并扣减令牌，适合集群部署。
//! - Redis 不可用时按照显式配置决定 fail-open 或 fail-closed，绝不静默放行。

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use http::HeaderMap;
use once_cell::sync::Lazy;
use redis::aio::ConnectionManager;
use tokio::sync::Mutex;

use crate::config::model::{
    GlobalRateLimitConfig, QuotaConfig, RateLimitKeyType, RateLimitMode, RedisConfig,
    RouteRateLimitConfig,
};
use crate::core::identity::Identity;

/// 原子令牌桶脚本。
///
/// KEYS[1] = 限流 Key
/// ARGV[1] = 每秒补充速率，ARGV[2] = 突发容量
/// ARGV[3] = 当前时间（毫秒），ARGV[4] = Key 过期时间（毫秒）
/// 返回 {allowed, remaining, retry_after_ms}
const TOKEN_BUCKET_LUA: &str = r#"
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local data = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(data[1])
local ts = tonumber(data[2])
if tokens == nil or ts == nil then
  tokens = burst
  ts = now
end

local elapsed = math.max(0, now - ts)
tokens = math.min(burst, tokens + (elapsed / 1000.0) * rate)

local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end

redis.call('HMSET', key, 'tokens', tostring(tokens), 'ts', tostring(now))
redis.call('PEXPIRE', key, ttl)

local retry = 0
if allowed == 0 then
  if rate > 0 then
    retry = math.ceil(((1 - tokens) / rate) * 1000)
  else
    retry = ttl
  end
end
return {allowed, math.floor(tokens), retry}
"#;

static SCRIPT: Lazy<redis::Script> = Lazy::new(|| redis::Script::new(TOKEN_BUCKET_LUA));

/// 限流判断结果。
#[derive(Debug, Clone)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub retry_after_secs: Option<u64>,
    pub key: String,
    pub error: Option<String>,
}

impl RateLimitDecision {
    fn allow(limit: u32, remaining: u32, key: String) -> Self {
        Self {
            allowed: true,
            limit,
            remaining,
            retry_after_secs: None,
            key,
            error: None,
        }
    }
}

struct LocalBucket {
    tokens: f64,
    last: Instant,
}

/// 本地令牌桶。
pub struct LocalRateLimiter {
    buckets: DashMap<String, Mutex<LocalBucket>>,
    max_keys: usize,
}

impl LocalRateLimiter {
    pub fn new(max_keys: usize) -> Self {
        Self {
            buckets: DashMap::new(),
            max_keys: max_keys.max(1),
        }
    }

    fn check(&self, key: &str, rate: f64, burst: u32) -> (bool, u32, u64) {
        if self.buckets.len() > self.max_keys {
            self.evict_stale();
        }
        let entry = self.buckets.entry(key.to_string()).or_insert_with(|| {
            Mutex::new(LocalBucket {
                tokens: burst as f64,
                last: Instant::now(),
            })
        });
        // 使用 try_lock 避免在异步上下文长时间阻塞；极端竞争时退化为允许。
        let mut bucket = match entry.try_lock() {
            Ok(guard) => guard,
            Err(_) => return (true, burst, 0),
        };
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst as f64);
        bucket.last = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            (true, bucket.tokens.floor() as u32, 0)
        } else {
            let retry_ms = if rate > 0.0 {
                (((1.0 - bucket.tokens) / rate) * 1000.0).ceil() as u64
            } else {
                1000
            };
            (false, 0, retry_ms)
        }
    }

    fn evict_stale(&self) {
        let now = Instant::now();
        self.buckets.retain(|_, bucket| {
            bucket
                .try_lock()
                .map(|b| now.duration_since(b.last) < Duration::from_secs(600))
                .unwrap_or(true)
        });
    }

    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

/// Redis 限流器。
pub struct RedisRateLimiter {
    conn: ConnectionManager,
    prefix: String,
}

impl RedisRateLimiter {
    pub async fn connect(config: &RedisConfig, prefix: &str) -> Result<Self, String> {
        if config.url.trim().is_empty() {
            return Err("redis url is empty".to_string());
        }
        let client = redis::Client::open(config.url.clone())
            .map_err(|e| format!("invalid redis url: {e}"))?;
        let conn = tokio::time::timeout(config.connect_timeout, ConnectionManager::new(client))
            .await
            .map_err(|_| "redis connect timeout".to_string())?
            .map_err(|e| format!("redis connect failed: {e}"))?;
        Ok(Self {
            conn,
            prefix: prefix.to_string(),
        })
    }

    async fn check(
        &self,
        key: &str,
        rate: f64,
        burst: u32,
        ttl: Duration,
        timeout: Duration,
    ) -> Result<(bool, u32, u64), String> {
        let mut conn = self.conn.clone();
        let now_ms = crate::utils::unix_millis();
        let ttl_ms = ttl.as_millis().max(1000) as u64;
        let script: &redis::Script = &SCRIPT;
        let mut cmd = script.key(format!("{}:{}", self.prefix, key));
        cmd.arg(rate).arg(burst).arg(now_ms as u64).arg(ttl_ms);
        let future = cmd.invoke_async::<(i64, i64, i64)>(&mut conn);
        let result = tokio::time::timeout(timeout, future)
            .await
            .map_err(|_| "redis command timeout".to_string())?
            .map_err(|e| format!("redis command failed: {e}"))?;
        Ok((
            result.0 == 1,
            result.1.max(0) as u32,
            result.2.max(0) as u64,
        ))
    }
}

/// 限流服务。
pub struct RateLimiter {
    local: Arc<LocalRateLimiter>,
    redis: Option<Arc<RedisRateLimiter>>,
    redis_config: RedisConfig,
    prefix: String,
}

impl RateLimiter {
    pub fn new(global: &GlobalRateLimitConfig) -> Arc<Self> {
        Arc::new(Self {
            local: Arc::new(LocalRateLimiter::new(global.max_keys)),
            redis: None,
            redis_config: RedisConfig::default(),
            prefix: global.redis_key_prefix.clone(),
        })
    }

    pub async fn with_redis(
        global: &GlobalRateLimitConfig,
        redis_config: &RedisConfig,
    ) -> Arc<Self> {
        let mut limiter = Self {
            local: Arc::new(LocalRateLimiter::new(global.max_keys)),
            redis: None,
            redis_config: redis_config.clone(),
            prefix: global.redis_key_prefix.clone(),
        };
        if !redis_config.url.trim().is_empty() {
            match RedisRateLimiter::connect(redis_config, &limiter.prefix).await {
                Ok(redis) => limiter.redis = Some(Arc::new(redis)),
                Err(err) => {
                    tracing::warn!(error = %err, "redis rate limiter unavailable");
                }
            }
        }
        Arc::new(limiter)
    }

    pub async fn reconnect_redis(&mut self) -> Result<(), String> {
        if self.redis_config.url.trim().is_empty() {
            return Err("redis url is empty".to_string());
        }
        let redis = RedisRateLimiter::connect(&self.redis_config, &self.prefix).await?;
        self.redis = Some(Arc::new(redis));
        Ok(())
    }

    pub fn redis_available(&self) -> bool {
        self.redis.is_some()
    }

    pub fn local_bucket_count(&self) -> usize {
        self.local.len()
    }

    /// 对单个 Key 执行限流。
    pub async fn check(
        &self,
        key: &str,
        quota: &QuotaConfig,
        mode: RateLimitMode,
        fail_open: bool,
    ) -> RateLimitDecision {
        let rate = quota.rate_per_second();
        let burst = quota.burst();
        match mode {
            RateLimitMode::Local => {
                let (allowed, remaining, retry_ms) = self.local.check(key, rate, burst);
                RateLimitDecision {
                    allowed,
                    limit: burst,
                    remaining,
                    retry_after_secs: if allowed {
                        None
                    } else {
                        Some(retry_ms.div_ceil(1000).max(1))
                    },
                    key: key.to_string(),
                    error: None,
                }
            }
            RateLimitMode::Redis => {
                let redis = match self.redis.as_ref() {
                    Some(redis) => redis,
                    None => {
                        let error = "redis rate limiter is unavailable".to_string();
                        if fail_open {
                            tracing::warn!(key, "redis rate limiter unavailable; fail-open");
                            return RateLimitDecision::allow(burst, burst, key.to_string());
                        }
                        return RateLimitDecision {
                            allowed: false,
                            limit: burst,
                            remaining: 0,
                            retry_after_secs: Some(1),
                            key: key.to_string(),
                            error: Some(error),
                        };
                    }
                };
                let ttl =
                    Duration::from_secs(((burst as f64 / rate.max(0.001)).ceil() as u64).max(2));
                match redis
                    .check(key, rate, burst, ttl, self.redis_config.command_timeout)
                    .await
                {
                    Ok((allowed, remaining, retry_ms)) => RateLimitDecision {
                        allowed,
                        limit: burst,
                        remaining,
                        retry_after_secs: if allowed {
                            None
                        } else {
                            Some(retry_ms.div_ceil(1000).max(1))
                        },
                        key: key.to_string(),
                        error: None,
                    },
                    Err(err) => {
                        if fail_open {
                            tracing::warn!(key, error = %err, "redis rate limit failed; fail-open");
                            RateLimitDecision::allow(burst, burst, key.to_string())
                        } else {
                            tracing::error!(key, error = %err, "redis rate limit failed; fail-closed");
                            RateLimitDecision {
                                allowed: false,
                                limit: burst,
                                remaining: 0,
                                retry_after_secs: Some(1),
                                key: key.to_string(),
                                error: Some(err),
                            }
                        }
                    }
                }
            }
        }
    }
}

/// 限流 Key 的上下文。
pub struct RateLimitContext<'a> {
    pub route_id: &'a str,
    pub client_ip: Option<std::net::IpAddr>,
    pub identity: Option<&'a Identity>,
    pub headers: &'a HeaderMap,
    pub query: Option<&'a str>,
}

/// 构造限流 Key。返回 `None` 表示无法构造（例如自定义头缺失），跳过限流。
pub fn build_key(
    key_type: RateLimitKeyType,
    template: Option<&str>,
    ctx: &RateLimitContext<'_>,
) -> Option<String> {
    let subject = ctx
        .identity
        .map(|i| i.subject.as_str())
        .unwrap_or("anonymous");
    let base = match key_type {
        RateLimitKeyType::Global => "global".to_string(),
        RateLimitKeyType::Ip => ctx
            .client_ip
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "unknown-ip".to_string()),
        RateLimitKeyType::User => subject.to_string(),
        RateLimitKeyType::Tenant => ctx
            .identity
            .and_then(|i| i.tenant.clone())
            .unwrap_or_else(|| "anonymous".to_string()),
        RateLimitKeyType::ApiKey => ctx
            .identity
            .and_then(|i| i.api_key_id.clone())
            .unwrap_or_else(|| "anonymous".to_string()),
        RateLimitKeyType::Custom => {
            let template = template.unwrap_or("literal:global");
            resolve_template(template, ctx)?
        }
    };
    Some(format!("{}:{}", ctx.route_id, base))
}

fn resolve_template(template: &str, ctx: &RateLimitContext<'_>) -> Option<String> {
    if let Some(name) = template.strip_prefix("header:") {
        return ctx
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.to_string());
    }
    if let Some(name) = template.strip_prefix("query:") {
        let query = ctx.query?;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            if k == name {
                return Some(percent_decode(v));
            }
        }
        return None;
    }
    if let Some(literal) = template.strip_prefix("literal:") {
        return Some(literal.to_string());
    }
    if let Some(name) = template.strip_prefix("cookie:") {
        let cookies = ctx.headers.get(http::header::COOKIE)?.to_str().ok()?;
        for part in cookies.split(';') {
            let (k, v) = part.trim().split_once('=')?;
            if k == name {
                return Some(v.to_string());
            }
        }
        return None;
    }
    if template == "ip" {
        return ctx.client_ip.map(|ip| ip.to_string());
    }
    if template == "user" {
        return Some(
            ctx.identity
                .map(|i| i.subject.clone())
                .unwrap_or_else(|| "anonymous".to_string()),
        );
    }
    if template == "tenant" {
        return Some(
            ctx.identity
                .and_then(|i| i.tenant.clone())
                .unwrap_or_else(|| "anonymous".to_string()),
        );
    }
    Some(template.to_string())
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(&value[i + 1..i + 3], 16) {
                out.push(byte);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

/// 计算路由级限流参数。
pub struct EffectiveLimit<'a> {
    pub key_type: RateLimitKeyType,
    pub template: Option<&'a str>,
    pub quota: &'a QuotaConfig,
    pub mode: RateLimitMode,
    pub fail_open: bool,
}

pub fn route_limit<'a>(
    route: &'a RouteRateLimitConfig,
    global: &'a GlobalRateLimitConfig,
) -> Option<EffectiveLimit<'a>> {
    if !route.enabled {
        return None;
    }
    let quota = if route.quota.requests_per_second.is_none()
        && route.quota.requests_per_minute.is_none()
        && route.quota.requests_per_hour.is_none()
        && route.quota.replenish_rate.is_none()
        && route.quota.burst_capacity.is_none()
    {
        &global.quota
    } else {
        &route.quota
    };
    Some(EffectiveLimit {
        key_type: route.key_type,
        template: route.key_template.as_deref(),
        quota,
        mode: route.mode.unwrap_or(global.mode),
        fail_open: route.fail_open.unwrap_or(global.fail_open),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quota(rate: f64, burst: u32) -> QuotaConfig {
        QuotaConfig {
            requests_per_second: Some(rate),
            burst_capacity: Some(burst),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn local_bucket_limits_burst() {
        let limiter = RateLimiter::new(&GlobalRateLimitConfig::default());
        let q = quota(0.01, 2);
        assert!(
            limiter
                .check("k", &q, RateLimitMode::Local, false)
                .await
                .allowed
        );
        assert!(
            limiter
                .check("k", &q, RateLimitMode::Local, false)
                .await
                .allowed
        );
        let denied = limiter.check("k", &q, RateLimitMode::Local, false).await;
        assert!(!denied.allowed);
        assert_eq!(denied.retry_after_secs, Some(100));
    }

    #[tokio::test]
    async fn redis_failure_is_fail_closed_by_default() {
        let limiter = RateLimiter::new(&GlobalRateLimitConfig::default());
        let decision = limiter
            .check("k", &quota(10.0, 10), RateLimitMode::Redis, false)
            .await;
        assert!(!decision.allowed);
        assert!(decision.error.is_some());
    }

    #[tokio::test]
    async fn redis_failure_can_fail_open() {
        let limiter = RateLimiter::new(&GlobalRateLimitConfig::default());
        let decision = limiter
            .check("k", &quota(10.0, 10), RateLimitMode::Redis, true)
            .await;
        assert!(decision.allowed);
    }

    #[test]
    fn key_templates() {
        let identity = Identity {
            subject: "u1".into(),
            scopes: vec![],
            roles: vec![],
            tenant: Some("acme".into()),
            auth_type: crate::core::identity::AuthType::Jwt,
            claims: serde_json::Map::new(),
            token: None,
            api_key_id: Some("key-1".into()),
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-app", "shop".parse().unwrap());
        let ctx = RateLimitContext {
            route_id: "r",
            client_ip: Some("1.2.3.4".parse().unwrap()),
            identity: Some(&identity),
            headers: &headers,
            query: Some("appid=42&x=1"),
        };
        assert_eq!(
            build_key(RateLimitKeyType::User, None, &ctx).unwrap(),
            "r:u1"
        );
        assert_eq!(
            build_key(RateLimitKeyType::Custom, Some("header:X-App"), &ctx).unwrap(),
            "r:shop"
        );
        assert_eq!(
            build_key(RateLimitKeyType::Custom, Some("query:appid"), &ctx).unwrap(),
            "r:42"
        );
        assert!(build_key(RateLimitKeyType::Custom, Some("header:X-Missing"), &ctx).is_none());
    }
}
