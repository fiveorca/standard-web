//! 配额插件（Phase 7）。
//!
//! # 与限流的区别
//!
//! 限流关注"单位时间速率"（如 100 rps），窗口通常很短；
//! 配额关注"一个较长周期内的总量"（如每天 10 万次），窗口是自然日/月，
//! 并且需要向客户端暴露剩余额度（`X-Quota-Remaining`）。
//!
//! # 计数维度
//!
//! | scope | 计数键 | 说明 |
//! |---|---|---|
//! | tenant | `tenant:{tenant_id}` | 同一租户共享配额 |
//! | consumer | `consumer:{consumer_id}` | 按认证主体独立配额 |
//! | route | `route:{route_id}` | 按路由汇总 |
//!
//! 拿不到维度值时 **fail open**：放行并记 debug 日志。这样未启用鉴权的
//! 路由不会因为缺少租户信息而全部 429。
//!
//! # 后端
//!
//! - `local`：进程内固定窗口计数（单实例准确）
//! - `redis`：多实例共享计数（INCR + EXPIRE）；Redis 故障时 fail open
//!
//! # 响应
//!
//! 每次判定都会写入配额 Header；超限时短路返回 429
//! `GATEWAY_QUOTA_EXCEEDED`。

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use gateway_core::{QuotaPeriod, QuotaPolicyConfig, QuotaScope, RateLimitBackend};
use gateway_plugin::{
    Plugin, PluginContext, PluginDecision, PluginError, PluginPhase, PluginResponse,
};
use http::header::HeaderValue;
use http::StatusCode;

use crate::redis_limiter::RedisLimiter;

/// 插件名。
pub const QUOTA_PLUGIN_NAME: &str = "quota";

/// 配额 Header：周期上限。
pub const HEADER_QUOTA_LIMIT: &str = "x-quota-limit";
/// 配额 Header：剩余额度。
pub const HEADER_QUOTA_REMAINING: &str = "x-quota-remaining";
/// 配额 Header：当前周期重置剩余秒数。
pub const HEADER_QUOTA_RESET: &str = "x-quota-reset";

/// 编译后的配额策略表。
#[derive(Default)]
pub struct CompiledQuotaPolicies {
    /// 只有 enabled 的策略会进入表
    by_id: HashMap<String, Arc<CompiledQuotaPolicy>>,
}

impl CompiledQuotaPolicies {
    /// 编译全部策略；重复 ID 与非法配置返回错误。
    pub fn compile(configs: &[QuotaPolicyConfig]) -> Result<Self, String> {
        let mut by_id = HashMap::new();
        for cfg in configs {
            let compiled = CompiledQuotaPolicy::compile(cfg)?;
            let id = compiled.id.clone();
            if by_id.insert(id.clone(), Arc::new(compiled)).is_some() {
                return Err(format!("duplicate quota policy id '{id}'"));
            }
        }
        Ok(Self { by_id })
    }

    /// 按 ID 取策略。
    pub fn get(&self, id: &str) -> Option<&Arc<CompiledQuotaPolicy>> {
        self.by_id.get(id)
    }

    /// 策略数量。
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

/// 编译后的单条配额策略。
pub struct CompiledQuotaPolicy {
    /// 策略 ID
    pub id: String,
    /// 是否启用
    pub enabled: bool,
    /// 周期上限
    pub limit: u64,
    /// 周期长度（秒）
    pub period_secs: u64,
    /// 计数维度
    pub scope: QuotaScope,
    /// 告警比例（0-100，0 表示关闭）
    pub warn_at_percent: u8,
    /// 进程内计数器
    local: LocalQuotaCounter,
    /// Redis 计数器（backend=redis 时存在）
    redis: Option<Arc<RedisLimiter>>,
}

impl CompiledQuotaPolicy {
    fn compile(cfg: &QuotaPolicyConfig) -> Result<Self, String> {
        if cfg.limit == 0 {
            return Err(format!("quota policy '{}': limit must be > 0", cfg.id));
        }
        let period_secs = match cfg.period {
            QuotaPeriod::Daily => 86_400,
            QuotaPeriod::Monthly => 30 * 86_400,
        };
        if cfg.warn_at_percent > 100 {
            return Err(format!("quota policy '{}': warn_at_percent must be within 0-100", cfg.id));
        }

        let redis = match cfg.backend {
            RateLimitBackend::Local => None,
            RateLimitBackend::Redis => {
                let url = cfg.redis_url.clone().ok_or_else(|| {
                    format!("quota policy '{}': redis_url is required for redis backend", cfg.id)
                })?;
                Some(Arc::new(RedisLimiter::new(url, cfg.limit, period_secs)))
            },
        };

        Ok(Self {
            id: cfg.id.clone(),
            enabled: cfg.enabled,
            limit: cfg.limit,
            period_secs,
            scope: cfg.scope,
            warn_at_percent: cfg.warn_at_percent,
            local: LocalQuotaCounter::new(period_secs),
            redis,
        })
    }

    /// 周期重置剩余秒数。
    fn reset_secs(&self, window_index: u64) -> u64 {
        let window_end = (window_index + 1) * self.period_secs;
        window_end.saturating_sub(now_secs()).max(1)
    }

    /// 计算告警阈值对应的计数。
    fn warn_threshold(&self) -> Option<u64> {
        if self.warn_at_percent == 0 || self.warn_at_percent > 100 {
            return None;
        }
        let threshold = (self.limit * self.warn_at_percent as u64).div_ceil(100);
        Some(threshold.max(1))
    }
}

/// 一次配额判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaDecision {
    /// 是否放行
    pub allowed: bool,
    /// 已使用次数（含本次）
    pub used: u64,
    /// 剩余次数
    pub remaining: u64,
    /// 周期重置剩余秒数
    pub reset_secs: u64,
    /// 是否恰好越过告警阈值（用于只告警一次）
    pub crossed_warn_threshold: bool,
}

impl QuotaDecision {
    fn new(
        allowed: bool,
        used: u64,
        limit: u64,
        reset_secs: u64,
        warn_threshold: Option<u64>,
    ) -> Self {
        Self {
            allowed,
            used,
            remaining: limit.saturating_sub(used),
            reset_secs,
            crossed_warn_threshold: warn_threshold.is_some_and(|t| used == t),
        }
    }
}

// ---------------------------------------------------------------------------
// 进程内固定窗口计数器
// ---------------------------------------------------------------------------

/// 进程内固定窗口计数器（按绝对时间对齐窗口边界）。
#[derive(Debug)]
pub struct LocalQuotaCounter {
    /// 窗口长度（秒）
    period_secs: u64,
    /// key → (窗口编号, 计数)
    windows: Mutex<HashMap<String, (u64, u64)>>,
}

impl LocalQuotaCounter {
    /// 创建计数器。
    pub fn new(period_secs: u64) -> Self {
        Self {
            period_secs: period_secs.max(1),
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// 递增计数并返回 `(计数, 窗口编号)`。
    pub fn increment(&self, key: &str) -> (u64, u64) {
        let window_index = now_secs() / self.period_secs;
        let mut guard = self.windows.lock().unwrap_or_else(|p| p.into_inner());

        // 顺带清理过期窗口，避免 key 无限增长
        if guard.len() > 1024 {
            guard.retain(|_, (window, _)| *window == window_index);
        }

        let entry = guard.entry(key.to_string()).or_insert((window_index, 0));
        if entry.0 != window_index {
            *entry = (window_index, 0);
        }
        entry.1 += 1;
        (entry.1, window_index)
    }

    /// 只读查询当前计数（测试/调试用）。
    pub fn count(&self, key: &str) -> u64 {
        let window_index = now_secs() / self.period_secs;
        let guard = self.windows.lock().unwrap_or_else(|p| p.into_inner());
        match guard.get(key) {
            Some((window, count)) if *window == window_index => *count,
            _ => 0,
        }
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// 插件
// ---------------------------------------------------------------------------

/// 配额插件。
pub struct QuotaPlugin {
    policies: Arc<CompiledQuotaPolicies>,
}

impl QuotaPlugin {
    /// 使用已编译策略构造。
    pub fn new(policies: Arc<CompiledQuotaPolicies>) -> Self {
        Self { policies }
    }

    /// 从配置编译。
    pub fn from_configs(configs: &[QuotaPolicyConfig]) -> Result<Self, PluginError> {
        let policies =
            CompiledQuotaPolicies::compile(configs).map_err(|message| PluginError::InitFailed {
                plugin: QUOTA_PLUGIN_NAME.to_string(),
                message,
            })?;
        Ok(Self::new(Arc::new(policies)))
    }
}

#[async_trait::async_trait]
impl Plugin for QuotaPlugin {
    fn name(&self) -> &'static str {
        QUOTA_PLUGIN_NAME
    }

    fn phase(&self) -> PluginPhase {
        // 鉴权之后、转发之前；与限流同阶段，priority 更大排在限流之后
        PluginPhase::RequestPostRoute
    }

    fn priority(&self) -> i32 {
        25
    }

    async fn execute(&self, ctx: &mut PluginContext<'_>) -> Result<PluginDecision, PluginError> {
        let route = match ctx.route.as_ref() {
            Some(route) => Arc::clone(route),
            None => {
                return Err(PluginError::ExecutionFailed {
                    plugin: QUOTA_PLUGIN_NAME.to_string(),
                    message: "quota phase invoked without a matched route".to_string(),
                });
            },
        };

        let Some(policy_id) = route.quota_policy_id.as_deref() else {
            return Ok(PluginDecision::Continue);
        };
        let Some(policy) = self.policies.get(policy_id) else {
            return Err(PluginError::ExecutionFailed {
                plugin: QUOTA_PLUGIN_NAME.to_string(),
                message: format!("quota policy '{policy_id}' was not compiled"),
            });
        };
        if !policy.enabled {
            return Ok(PluginDecision::Continue);
        }

        // 计数键：拿不到维度值时 fail open
        let Some(key) = resolve_key(policy.scope, &route.id, ctx) else {
            tracing::debug!(
                target: "traffic",
                request_id = ctx.request_id(),
                route = %route.id,
                policy = %policy.id,
                "quota dimension unavailable, skipping"
            );
            return Ok(PluginDecision::Continue);
        };

        let decision = evaluate(policy, &key).await?;

        if decision.crossed_warn_threshold {
            tracing::warn!(
                target: "traffic",
                policy = %policy.id,
                key = %key,
                used = decision.used,
                limit = policy.limit,
                warn_at_percent = policy.warn_at_percent,
                "quota usage crossed warning threshold"
            );
        }

        // 预置 Header：放行与拒绝都要能看到剩余额度
        let headers = [
            (HEADER_QUOTA_LIMIT, policy.limit),
            (HEADER_QUOTA_REMAINING, decision.remaining),
            (HEADER_QUOTA_RESET, decision.reset_secs),
        ];

        if decision.allowed {
            for (name, value) in headers {
                insert_header(ctx, name, value);
            }
            return Ok(PluginDecision::Continue);
        }

        tracing::warn!(
            target: "traffic",
            request_id = ctx.request_id(),
            route = %route.id,
            policy = %policy.id,
            key = %key,
            used = decision.used,
            limit = policy.limit,
            "quota exceeded"
        );

        let mut response = PluginResponse::from_error(
            StatusCode::TOO_MANY_REQUESTS,
            "GATEWAY_QUOTA_EXCEEDED",
            "quota exceeded",
            Some(ctx.request_id()),
        );
        for (name, value) in headers {
            if let (Ok(header), Ok(value)) = (
                http::HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(&value.to_string()),
            ) {
                response.headers.insert(header, value);
            }
        }
        Ok(PluginDecision::ShortCircuit(response))
    }
}

/// 把配额 Header 写入本次请求预置的响应 Header（放行路径）。
///
/// Runtime 会在写回上游响应前统一合并 `ctx.response_headers`，
/// 因此放行时也能让客户端看到剩余额度。
fn insert_header(ctx: &mut PluginContext<'_>, name: &str, value: u64) {
    if let (Ok(header), Ok(value)) = (
        http::HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(&value.to_string()),
    ) {
        ctx.ctx.response_headers.insert(header, value);
    }
}

/// 解析配额计数维度。
fn resolve_key(scope: QuotaScope, route_id: &str, ctx: &PluginContext<'_>) -> Option<String> {
    match scope {
        QuotaScope::Tenant => ctx.ctx.tenant_id.as_ref().map(|t| format!("tenant:{t}")),
        QuotaScope::Consumer => ctx.ctx.consumer_id.as_ref().map(|c| format!("consumer:{c}")),
        QuotaScope::Route => Some(format!("route:{route_id}")),
    }
}

/// 执行一次配额判定。
async fn evaluate(policy: &CompiledQuotaPolicy, key: &str) -> Result<QuotaDecision, PluginError> {
    let warn_threshold = policy.warn_threshold();

    match &policy.redis {
        Some(redis) => match redis.incr_window("quota", key).await {
            Ok((count, window_index)) => {
                let reset = policy.reset_secs(window_index);
                Ok(QuotaDecision::new(
                    count <= policy.limit,
                    count,
                    policy.limit,
                    reset,
                    warn_threshold,
                ))
            },
            // Redis 故障：fail open，保障可用性（配额是业务限制，不是安全边界）
            Err(err) => {
                tracing::warn!(
                    target: "traffic",
                    policy = %policy.id,
                    error = %err,
                    "redis quota backend unavailable, failing open"
                );
                Ok(QuotaDecision::new(true, 0, policy.limit, policy.period_secs, None))
            },
        },
        None => {
            let (count, window_index) = policy.local.increment(key);
            let reset = policy.reset_secs(window_index);
            Ok(QuotaDecision::new(
                count <= policy.limit,
                count,
                policy.limit,
                reset,
                warn_threshold,
            ))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::RequestId;
    use gateway_core::{RequestContext, RouteConfig};

    fn policy_config(id: &str, limit: u64, scope: QuotaScope) -> QuotaPolicyConfig {
        QuotaPolicyConfig {
            id: id.to_string(),
            name: None,
            enabled: true,
            period: QuotaPeriod::Daily,
            limit,
            scope,
            backend: RateLimitBackend::Local,
            redis_url: None,
            warn_at_percent: 50,
        }
    }

    fn route_with_quota(policy_id: &str) -> RouteConfig {
        let json = format!(
            r#"{{"id":"r1","path_value":"/","service_id":"svc","quota_policy_id":"{policy_id}"}}"#
        );
        serde_json::from_str(&json).expect("route config")
    }

    fn make_ctx(
        tenant: Option<&str>,
        consumer: Option<&str>,
    ) -> (http::request::Parts, RequestContext) {
        let mut request_ctx = RequestContext::new(RequestId::new());
        request_ctx.tenant_id = tenant.map(str::to_string);
        request_ctx.consumer_id = consumer.map(str::to_string);
        let (parts, _) = http::Request::builder().uri("/").body(()).expect("request").into_parts();
        (parts, request_ctx)
    }

    /// 执行一次插件并取回预置响应头。
    async fn run(
        plugin: &QuotaPlugin,
        route: &Arc<RouteConfig>,
        tenant: Option<&str>,
        consumer: Option<&str>,
    ) -> (PluginDecision, http::HeaderMap) {
        let (mut parts, mut request_ctx) = make_ctx(tenant, consumer);
        let mut ctx =
            PluginContext::new(&mut parts, &mut request_ctx, Some(Arc::clone(route)), None);
        let decision = plugin.execute(&mut ctx).await.expect("execute");
        (decision, ctx.ctx.response_headers.clone())
    }

    #[tokio::test]
    async fn quota_allows_then_blocks_and_sets_headers() {
        let plugin = QuotaPlugin::from_configs(&[policy_config("q1", 2, QuotaScope::Route)])
            .expect("compile");
        let route = Arc::new(route_with_quota("q1"));

        for expected_remaining in [1u64, 0] {
            let (decision, headers) = run(&plugin, &route, None, None).await;
            assert!(matches!(decision, PluginDecision::Continue));
            let remaining = headers
                .get(HEADER_QUOTA_REMAINING)
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok());
            assert_eq!(remaining, Some(expected_remaining));
            assert_eq!(headers.get(HEADER_QUOTA_LIMIT).and_then(|v| v.to_str().ok()), Some("2"));
        }

        // 第三次超限
        let (decision, _) = run(&plugin, &route, None, None).await;
        match decision {
            PluginDecision::ShortCircuit(response) => {
                assert_eq!(response.status, StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(
                    response.headers.get(HEADER_QUOTA_LIMIT).and_then(|v| v.to_str().ok()),
                    Some("2")
                );
                let reset = response
                    .headers
                    .get(HEADER_QUOTA_RESET)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<u64>().ok())
                    .expect("reset header");
                assert!(reset <= 86_400 && reset > 0, "unexpected reset: {reset}");
            },
            _ => panic!("expected short circuit"),
        }
    }

    #[tokio::test]
    async fn tenant_scope_without_tenant_fails_open() {
        let plugin = QuotaPlugin::from_configs(&[policy_config("q1", 1, QuotaScope::Tenant)])
            .expect("compile");
        let route = Arc::new(route_with_quota("q1"));

        // 无 tenant：全部放行，且不写配额 Header
        for _ in 0..5 {
            let (decision, headers) = run(&plugin, &route, None, None).await;
            assert!(matches!(decision, PluginDecision::Continue));
            assert!(!headers.contains_key(HEADER_QUOTA_REMAINING));
        }
    }

    #[tokio::test]
    async fn tenant_scope_counts_per_tenant() {
        let plugin = QuotaPlugin::from_configs(&[policy_config("q1", 1, QuotaScope::Tenant)])
            .expect("compile");
        let route = Arc::new(route_with_quota("q1"));

        // tenant-a 第一次放行
        assert!(matches!(
            run(&plugin, &route, Some("a"), None).await.0,
            PluginDecision::Continue
        ));

        // tenant-a 第二次超限
        assert!(matches!(
            run(&plugin, &route, Some("a"), None).await.0,
            PluginDecision::ShortCircuit(_)
        ));

        // tenant-b 独立计数，仍可放行
        assert!(matches!(
            run(&plugin, &route, Some("b"), None).await.0,
            PluginDecision::Continue
        ));
    }

    #[test]
    fn duplicate_and_invalid_policies_are_rejected() {
        let a = policy_config("dup", 1, QuotaScope::Route);
        let mut b = a.clone();
        b.limit = 2;
        assert!(CompiledQuotaPolicies::compile(&[a.clone(), b]).is_err());

        let mut zero = policy_config("zero", 0, QuotaScope::Route);
        zero.limit = 0;
        assert!(CompiledQuotaPolicies::compile(&[zero]).is_err());

        let mut bad_pct = policy_config("pct", 1, QuotaScope::Route);
        bad_pct.warn_at_percent = 101;
        assert!(CompiledQuotaPolicies::compile(&[bad_pct]).is_err());
    }

    #[test]
    fn local_counter_resets_on_new_window() {
        // 1 秒窗口：跨窗口后计数归零
        let counter = LocalQuotaCounter::new(1);
        assert_eq!(counter.increment("k"), (1, now_secs()));
        // 强制把记录改成上一个窗口
        {
            let mut guard = counter.windows.lock().expect("lock");
            let entry = guard.get_mut("k").expect("entry");
            entry.0 = entry.0.saturating_sub(1);
        }
        let (count, _) = counter.increment("k");
        assert_eq!(count, 1, "new window must reset the count");
    }
}
