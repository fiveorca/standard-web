//! 限流插件 —— 挂 `RequestPostRoute` 阶段。
//!
//! # 在 Pipeline 中的位置
//!
//! ```text
//! Route 匹配完成
//!     │
//!     ▼
//! RequestPostRoute（本插件，priority = 20）
//!     ├── route.rate_limit_policy_id = None ──▶ Continue（无限流）
//!     ├── 策略禁用（enabled=false）──▶ Continue
//!     ├── 计数键缺失 ──▶ Continue（fail open）
//!     ├── 限流器允许 ──▶ Continue
//!     └── 限流器拒绝 ──▶ ShortCircuit(429 + Retry-After)
//! ```
//!
//! # fail closed 约定
//!   - 路由引用了未编译的策略 → `Err`（500），不放行
//!   - 限流器内部错误（不可能发生，但兜底）→ `Err`
//!
//! # fail open 约定
//!   - 计数键缺失（client_ip / header / route 为 None）→ 放行
//!     这不是限流器的故障，而是"无法确定该请求属于哪个桶"。
//!     拒绝合法流量比放过少量异常流量更危险。

use std::sync::Arc;
use std::time::Duration;

use gateway_core::RateLimitPolicyConfig;
use gateway_plugin::{
    Plugin, PluginContext, PluginDecision, PluginError, PluginPhase, PluginResponse,
};
use http::header::RETRY_AFTER;
use http::HeaderValue;

use crate::key::resolve_key;
use crate::policy::{CompiledRateLimitPolicies, RateLimiter};

/// 插件唯一名称。
pub const RATE_LIMIT_PLUGIN_NAME: &str = "rate_limit";

/// 限流插件。
#[derive(Debug, Clone)]
pub struct RateLimitPlugin {
    /// 已编译的全部限流策略
    policies: Arc<CompiledRateLimitPolicies>,
}

impl RateLimitPlugin {
    /// 用已编译的策略表构造插件。
    pub fn new(policies: Arc<CompiledRateLimitPolicies>) -> Self {
        Self { policies }
    }

    /// 从配置直接编译并构造插件。
    ///
    /// 返回 `Err(PluginError::ConfigInvalid)` 表示策略配置非法，
    /// 调用方应阻止网关启动。
    pub fn from_configs(configs: &[RateLimitPolicyConfig]) -> Result<Self, PluginError> {
        let policies = CompiledRateLimitPolicies::compile(configs).map_err(|message| {
            PluginError::ConfigInvalid {
                plugin: RATE_LIMIT_PLUGIN_NAME.to_string(),
                message,
            }
        })?;
        Ok(Self::new(Arc::new(policies)))
    }

    /// 只读访问策略表（启动自检/管理接口用）。
    pub fn policies(&self) -> &CompiledRateLimitPolicies {
        &self.policies
    }
}

#[async_trait::async_trait]
impl Plugin for RateLimitPlugin {
    fn name(&self) -> &'static str {
        RATE_LIMIT_PLUGIN_NAME
    }

    /// 路由匹配之后、认证之前：此时已有 Route 信息，可按路由限流
    fn phase(&self) -> PluginPhase {
        PluginPhase::RequestPostRoute
    }

    /// 安全插件 priority=10，限流插件 priority=20（认证之后、业务之前）
    fn priority(&self) -> i32 {
        20
    }

    /// 单次执行超时：限流是纯内存操作，正常微秒级；100ms 兜底
    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_millis(100))
    }

    fn config_schema(&self) -> Option<&'static str> {
        None
    }

    fn validate_config(&self, _config: &serde_json::Value) -> Result<(), PluginError> {
        Ok(())
    }

    async fn init(&self) -> Result<(), PluginError> {
        tracing::info!(
            target: "traffic",
            plugin = RATE_LIMIT_PLUGIN_NAME,
            policies = self.policies.len(),
            "rate limit plugin initialized"
        );
        Ok(())
    }

    async fn execute(
        &self,
        ctx: &mut PluginContext<'_>,
    ) -> Result<PluginDecision, PluginError> {
        // 1) 必须已有路由（RequestPostRoute 阶段）
        let route = match ctx.route.as_ref() {
            Some(route) => Arc::clone(route),
            None => {
                return Err(PluginError::ExecutionFailed {
                    plugin: RATE_LIMIT_PLUGIN_NAME.to_string(),
                    message: "rate limit phase invoked without a matched route".to_string(),
                });
            },
        };

        // 2) 无限流策略：放行
        let Some(policy_id) = route.rate_limit_policy_id.as_deref() else {
            return Ok(PluginDecision::Continue);
        };

        // 3) 查找已编译策略
        let Some(policy) = self.policies.get(policy_id) else {
            return Err(PluginError::ExecutionFailed {
                plugin: RATE_LIMIT_PLUGIN_NAME.to_string(),
                message: format!("rate limit policy '{policy_id}' was not compiled"),
            });
        };

        // 4) 策略禁用：放行
        if !policy.enabled {
            return Ok(PluginDecision::Continue);
        }

        // 5) 提取计数键；缺失时放行（fail open）
        let Some(key) = resolve_key(&policy.key, ctx) else {
            tracing::debug!(
                target: "traffic",
                request_id = ctx.request_id(),
                route = %route.id,
                policy = %policy.id,
                "rate limit key unavailable, skipping"
            );
            return Ok(PluginDecision::Continue);
        };

        // 6) 执行限流
        let allowed = match &policy.limiter {
            RateLimiter::TokenBucket(limiter) => limiter.try_acquire(&key).await,
            RateLimiter::FixedWindow(limiter) => limiter.try_acquire(&key).await,
        };

        if allowed {
            return Ok(PluginDecision::Continue);
        }

        // 7) 限流触发：计算 Retry-After 并短路
        let retry_after = match &policy.limiter {
            RateLimiter::TokenBucket(limiter) => limiter.retry_after_secs(&key).await,
            RateLimiter::FixedWindow(limiter) => limiter.retry_after_secs(&key).await,
        };

        tracing::debug!(
            target: "traffic",
            request_id = ctx.request_id(),
            route = %route.id,
            policy = %policy.id,
            key = %key,
            retry_after = ?retry_after,
            "rate limit triggered"
        );

        let mut response = PluginResponse::from_error(
            http::StatusCode::TOO_MANY_REQUESTS,
            "GATEWAY_RATE_LIMITED",
            "rate limit exceeded",
            Some(ctx.request_id()),
        );

        // 带 Retry-After Header（RFC 6585）
        if let Some(secs) = retry_after {
            if let Ok(value) = HeaderValue::from_str(&secs.to_string()) {
                response.headers.insert(RETRY_AFTER, value);
            }
        }

        Ok(PluginDecision::ShortCircuit(response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::RequestId;
    use gateway_core::{RateLimitAlgorithm, RateLimitKeyKind, RateLimitKeySpec, RequestContext, RouteConfig};

    /// 辅助：构造带 rate_limit_policy_id 的路由
    fn route_with_policy(policy_id: Option<&str>) -> RouteConfig {
        let mut json = String::from(r#"{"id":"r1","path_value":"/","service_id":"svc""#);
        if let Some(id) = policy_id {
            json.push_str(&format!(r#","rate_limit_policy_id":"{id}""#));
        }
        json.push('}');
        serde_json::from_str(&json).expect("route config")
    }

    /// 辅助：构造限流插件（rate=2/s, burst=2, key=client_ip）
    fn plugin() -> RateLimitPlugin {
        RateLimitPlugin::from_configs(&[RateLimitPolicyConfig {
            id: "rl".into(),
            name: None,
            enabled: true,
            algorithm: RateLimitAlgorithm::TokenBucket,
            rate: 2,
            burst: Some(2),
            window_secs: 1,
            key: RateLimitKeySpec {
                kind: RateLimitKeyKind::ClientIp,
                header: None,
            },
            failure_mode: gateway_core::FailureMode::FailClosed,
        }])
        .expect("plugin should compile")
    }

    /// 辅助：构造请求上下文
    fn make_ctx() -> (http::request::Parts, RequestContext) {
        let mut request_ctx = RequestContext::new(RequestId::new());
        request_ctx.client_ip = Some("192.168.1.1:1234".parse().expect("addr"));
        let (parts, _) = http::Request::builder()
            .uri("/")
            .body(())
            .expect("request")
            .into_parts();
        (parts, request_ctx)
    }

    /// 限流触发后返回 429 + Retry-After
    #[tokio::test]
    async fn rate_limit_returns_429() {
        let plugin = plugin();
        let (mut parts, mut request_ctx) = make_ctx();
        let route = Arc::new(route_with_policy(Some("rl")));

        // 前 2 个放行（burst=2）
        for i in 0..2 {
            let mut ctx = PluginContext::new(&mut parts, &mut request_ctx, Some(route.clone()), None);
            let decision = plugin.execute(&mut ctx).await.expect("execute");
            assert!(decision.is_continue(), "request {i} should pass");
        }

        // 第 3 个限流
        let mut ctx = PluginContext::new(&mut parts, &mut request_ctx, Some(route.clone()), None);
        let decision = plugin.execute(&mut ctx).await.expect("execute");
        assert!(decision.is_short_circuit(), "request 3 should be limited");

        let response = decision.into_response().expect("response");
        assert_eq!(response.status, http::StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers.contains_key(RETRY_AFTER));
    }

    /// 无限流策略的路由直接放行
    #[tokio::test]
    async fn no_policy_passes() {
        let plugin = plugin();
        let (mut parts, mut request_ctx) = make_ctx();
        let route = Arc::new(route_with_policy(None));
        let mut ctx = PluginContext::new(&mut parts, &mut request_ctx, Some(route), None);
        let decision = plugin.execute(&mut ctx).await.expect("execute");
        assert!(decision.is_continue());
    }

    /// 禁用的策略直接放行
    #[tokio::test]
    async fn disabled_policy_passes() {
        let config = RateLimitPolicyConfig {
            id: "rl".into(),
            name: None,
            enabled: false, // 禁用
            algorithm: RateLimitAlgorithm::TokenBucket,
            rate: 1,
            burst: Some(1),
            window_secs: 1,
            key: RateLimitKeySpec {
                kind: RateLimitKeyKind::ClientIp,
                header: None,
            },
            failure_mode: gateway_core::FailureMode::FailClosed,
        };
        let plugin = RateLimitPlugin::from_configs(&[config]).expect("compile");
        let (mut parts, mut request_ctx) = make_ctx();
        let route = Arc::new(route_with_policy(Some("rl")));
        let mut ctx = PluginContext::new(&mut parts, &mut request_ctx, Some(route), None);
        let decision = plugin.execute(&mut ctx).await.expect("execute");
        assert!(decision.is_continue());
    }

    /// 引用不存在的策略：fail closed
    #[tokio::test]
    async fn unknown_policy_is_fail_closed() {
        let plugin = plugin();
        let (mut parts, mut request_ctx) = make_ctx();
        let route = Arc::new(route_with_policy(Some("missing")));
        let mut ctx = PluginContext::new(&mut parts, &mut request_ctx, Some(route), None);
        assert!(plugin.execute(&mut ctx).await.is_err());
    }

    /// client_ip 缺失时放行（fail open）
    #[tokio::test]
    async fn missing_client_ip_passes() {
        let plugin = plugin();
        let (mut parts, mut request_ctx) = make_ctx();
        request_ctx.client_ip = None; // 移除 client_ip
        let route = Arc::new(route_with_policy(Some("rl")));
        let mut ctx = PluginContext::new(&mut parts, &mut request_ctx, Some(route), None);
        let decision = plugin.execute(&mut ctx).await.expect("execute");
        assert!(decision.is_continue());
    }
}
