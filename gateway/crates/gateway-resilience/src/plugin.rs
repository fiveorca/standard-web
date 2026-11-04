//! 熔断插件 —— 两个实例挂两个阶段。
//!
//! | 实例 | Phase | 优先级 | 做什么 |
//! |---|---|---|---|
//! | `circuit_breaker_guard` | `RequestPreUpstream` | 15 | 检查熔断是否 OPEN → 短路 503 |
//! | `circuit_breaker_record` | `UpstreamResponse` | 30 | 按上游状态码记录成功/失败 |
//!
//! # 为什么需要两个实例
//! 熔断器有**前置检查**（不让请求进入已熔断的上游）和**后置记录**（根据上游结果更新状态）两件事，
//! 发生在 Pipeline 的不同阶段。单个 Plugin 只返回一个 `phase()`，
//! 所以需要两个独立实例，共享同一个 `CompiledResiliencePolicies`。
//!
//! # 判断"成功/失败"
//! 根据策略配置的 `failure_statuses`：
//!   - 上游状态码 ∈ failure_statuses → 失败
//!   - 其他状态码（含 2xx/3xx）→ 成功
//!
//! 连接错误会被代理层转成 502/503，同样会进入 `UpstreamResponse` 阶段
//! 并命中 failure_statuses——与 `count_connection_errors: true` 语义一致。

use std::sync::Arc;
use std::time::Duration;

use gateway_core::CircuitBreakerPolicyConfig;
use gateway_plugin::{
    Plugin, PluginContext, PluginDecision, PluginError, PluginPhase, PluginResponse,
};

use crate::policy::CompiledResiliencePolicies;

// ---------------------------------------------------------------------------
// 两个插件实例共享的类型
// ---------------------------------------------------------------------------

/// 插件方向标识。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbDirection {
    /// RequestPreUpstream：检查熔断
    Guard,
    /// UpstreamResponse：记录结果
    Record,
}

/// 熔断器插件。
#[derive(Debug, Clone)]
pub struct CircuitBreakerPlugin {
    /// 已编译的韧性策略集合
    policies: Arc<CompiledResiliencePolicies>,
    /// 本实例的方向
    direction: CbDirection,
}

impl CircuitBreakerPlugin {
    pub fn new(policies: Arc<CompiledResiliencePolicies>, direction: CbDirection) -> Self {
        Self { policies, direction }
    }

    /// 从配置直接编译并构造一对插件。
    pub fn from_configs(
        cb_configs: &[CircuitBreakerPolicyConfig],
    ) -> Result<(Self, Self), PluginError> {
        // Timeout / Retry 插件不单独实现，但编译入口是统一的；
        // 这里只给 breakers 部分填数据，其余传空切片
        let policies = CompiledResiliencePolicies::compile(&[], &[], cb_configs)
            .map_err(|message| PluginError::ConfigInvalid {
                plugin: PLUGIN_NAME.into(),
                message,
            })?;
        let policies = Arc::new(policies);
        Ok((
            Self::new(policies.clone(), CbDirection::Guard),
            Self::new(policies, CbDirection::Record),
        ))
    }

    /// 插件名（Registry 键；两个实例不同，避免 DuplicateName）
    fn name_for(direction: CbDirection) -> &'static str {
        match direction {
            CbDirection::Guard => "circuit_breaker_guard",
            CbDirection::Record => "circuit_breaker_record",
        }
    }

    /// 日志标签
    fn label_for(direction: CbDirection) -> &'static str {
        match direction {
            CbDirection::Guard => "guard",
            CbDirection::Record => "record",
        }
    }

    /// 只读访问策略集合
    pub fn policies(&self) -> &CompiledResiliencePolicies {
        &self.policies
    }

    /// 当前方向
    pub fn direction(&self) -> CbDirection {
        self.direction
    }
}

/// Plugin 接口实现。
#[async_trait::async_trait]
impl Plugin for CircuitBreakerPlugin {
    fn name(&self) -> &'static str {
        Self::name_for(self.direction)
    }

    fn phase(&self) -> PluginPhase {
        match self.direction {
            // 检查熔断：转发上游之前
            CbDirection::Guard => PluginPhase::RequestPreUpstream,
            // 记录结果：拿到上游响应之后
            CbDirection::Record => PluginPhase::UpstreamResponse,
        }
    }

    /// Guard priority=15（在 auth=10 之后、rate_limit=20 之前）
    /// Record priority=30（在 transform=25 之后）
    fn priority(&self) -> i32 {
        match self.direction {
            CbDirection::Guard => 15,
            CbDirection::Record => 30,
        }
    }

    /// 单次执行超时：熔断检查/记录都是互斥锁 + 几次比较，50ms 兜底
    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_millis(50))
    }

    fn config_schema(&self) -> Option<&'static str> {
        None
    }

    fn validate_config(&self, _config: &serde_json::Value) -> Result<(), PluginError> {
        Ok(())
    }

    async fn init(&self) -> Result<(), PluginError> {
        tracing::info!(
            target: "resilience",
            plugin = self.name(),
            direction = Self::label_for(self.direction),
            "circuit breaker plugin initialized"
        );
        Ok(())
    }

    async fn execute(
        &self,
        ctx: &mut PluginContext<'_>,
    ) -> Result<PluginDecision, PluginError> {
        // 1) 必须有 route
        let Some(route) = ctx.route.as_ref() else {
            return Err(PluginError::ExecutionFailed {
                plugin: self.name().to_string(),
                message: format!(
                    "cb({}) phase invoked without a matched route",
                    Self::label_for(self.direction)
                ),
            });
        };

        // 2) Route 没有引用熔断策略 → 直接放行
        let Some(policy_id) = route.circuit_breaker_policy_id.as_deref() else {
            return Ok(PluginDecision::Continue);
        };

        // 3) 查找已编译熔断器
        let Some(breaker) = self.policies.get_breaker(policy_id) else {
            return Err(PluginError::ExecutionFailed {
                plugin: self.name().to_string(),
                message: format!(
                    "circuit breaker policy '{policy_id}' was not compiled"
                ),
            });
        };

        // 4) 执行方向对应的逻辑
        match self.direction {
            // ---- Guard：检查是否允许请求进入 ----
            CbDirection::Guard => {
                if !breaker.allow_request().await {
                    tracing::debug!(
                        target: "resilience",
                        request_id = ctx.request_id(),
                        route = %route.id,
                        policy = policy_id,
                        "circuit breaker open, short-circuiting"
                    );

                    let response = PluginResponse::from_error(
                        http::StatusCode::SERVICE_UNAVAILABLE,
                        "GATEWAY_CIRCUIT_OPEN",
                        "upstream circuit is open",
                        Some(ctx.request_id()),
                    );
                    return Ok(PluginDecision::ShortCircuit(response));
                }
                Ok(PluginDecision::Continue)
            },

            // ---- Record：根据上游状态码记录结果 ----
            CbDirection::Record => {
                // UpstreamResponse 阶段应该有 response 视图
                let Some(response) = ctx.response.as_ref() else {
                    return Err(PluginError::ExecutionFailed {
                        plugin: self.name().to_string(),
                        message: "circuit breaker record invoked without response view"
                            .to_string(),
                    });
                };

                // 熔断器编译时已携带 failure_statuses，直接问熔断器即可：
                // is_failure_status 返回 true 表示这个状态码算失败
                let status = response.status.as_u16();
                breaker.record_result(!breaker.is_failure_status(status)).await;
                Ok(PluginDecision::Continue)
            },
        }
    }
}

/// 插件唯一族名（日志/错误用）
pub const PLUGIN_NAME: &str = "circuit_breaker";

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::RequestId;
    use gateway_core::RequestContext;
    use http::{HeaderMap, StatusCode};

    /// 辅助：构造 RouteConfig（带 circuit_breaker_policy_id）
    fn route_with_cb(id: Option<&str>) -> gateway_core::models::RouteConfig {
        let mut json = String::from(
            r#"{"id":"r1","path_value":"/","service_id":"svc"}"#,
        );
        if let Some(id) = id {
            json = format!(
                r#"{{"id":"r1","path_value":"/","service_id":"svc","circuit_breaker_policy_id":"{id}"}}"#
            );
        }
        serde_json::from_str(&json).expect("route")
    }

    /// 辅助：构造请求 Parts + ctx
    fn make_ctx() -> (http::request::Parts, RequestContext) {
        let ctx = RequestContext::new(RequestId::from_string("req-cb-1"));
        let (parts, _) = http::Request::builder()
            .method("GET")
            .uri("/")
            .body(())
            .expect("request")
            .into_parts();
        (parts, ctx)
    }

    /// 辅助：构造熔断插件对（failure_threshold=3, open_duration=50ms）
    fn make_plugin_pair() -> (CircuitBreakerPlugin, CircuitBreakerPlugin) {
        let json = r#"[{"id":"cb1","failure_threshold":3,"success_threshold":2,"open_duration_secs":1}]"#;
        let configs: Vec<CircuitBreakerPolicyConfig> =
            serde_json::from_str(json).expect("deserialize");
        CircuitBreakerPlugin::from_configs(&configs).expect("compile")
    }

    /// Guard：Closed 状态放行
    #[tokio::test]
    async fn guard_allows_in_closed() {
        let (guard, _) = make_plugin_pair();
        let (mut parts, mut ctx) = make_ctx();
        let route = Arc::new(route_with_cb(Some("cb1")));
        let mut plugin_ctx = PluginContext::new(&mut parts, &mut ctx, Some(route), None);

        let decision = guard.execute(&mut plugin_ctx).await.expect("execute");
        assert!(decision.is_continue());
    }

    /// Guard：Open 状态短路 503
    #[tokio::test]
    async fn guard_short_circuits_in_open() {
        let (guard, record) = make_plugin_pair();

        // 先用 Record 打满 3 次失败（让熔断器变 Open）
        let route = Arc::new(route_with_cb(Some("cb1")));
        for _ in 0..3 {
            let (mut parts, mut ctx) = make_ctx();
            let mut resp_parts = gateway_plugin::ResponseParts::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                HeaderMap::new(),
            );
            let mut plugin_ctx = PluginContext::new(
                &mut parts,
                &mut ctx,
                Some(route.clone()),
                Some(&mut resp_parts),
            );
            record.execute(&mut plugin_ctx).await.expect("record");
        }

        // 现在 Guard 应该返回 503
        let (mut parts, mut ctx) = make_ctx();
        let mut plugin_ctx = PluginContext::new(&mut parts, &mut ctx, Some(route), None);
        let decision = guard.execute(&mut plugin_ctx).await.expect("execute");
        let response = decision.into_response().expect("short circuit");
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);

        let payload: serde_json::Value =
            serde_json::from_slice(&response.body).expect("json");
        assert_eq!(payload["code"], "GATEWAY_CIRCUIT_OPEN");
    }

    /// Guard：Route 没有引用策略 → 放行
    #[tokio::test]
    async fn no_policy_passes() {
        let (guard, _) = make_plugin_pair();
        let (mut parts, mut ctx) = make_ctx();
        let route = Arc::new(route_with_cb(None));
        let mut plugin_ctx = PluginContext::new(&mut parts, &mut ctx, Some(route), None);
        let decision = guard.execute(&mut plugin_ctx).await.expect("execute");
        assert!(decision.is_continue());
    }

    /// Record：5xx 记录失败，2xx 记录成功
    #[tokio::test]
    async fn record_success_and_failure() {
        let (guard, record) = make_plugin_pair();
        let route = Arc::new(route_with_cb(Some("cb1")));

        // 连续 3 次 500 → Open
        for _ in 0..3 {
            let (mut parts, mut ctx) = make_ctx();
            let mut resp_parts = gateway_plugin::ResponseParts::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                HeaderMap::new(),
            );
            let mut plugin_ctx = PluginContext::new(
                &mut parts,
                &mut ctx,
                Some(route.clone()),
                Some(&mut resp_parts),
            );
            record.execute(&mut plugin_ctx).await.expect("record");
        }

        // Guard 应拒绝
        let (mut parts, mut ctx) = make_ctx();
        let mut plugin_ctx = PluginContext::new(&mut parts, &mut ctx, Some(route.clone()), None);
        assert!(guard.execute(&mut plugin_ctx).await.unwrap().is_short_circuit());

        // 等 open_duration 到期（配置 1s），再等
        tokio::time::sleep(Duration::from_millis(1100)).await;

        // 4 次 200 → HalfOpen 后恢复 Closed
        for _ in 0..4 {
            let (mut parts, mut ctx) = make_ctx();
            let mut resp_parts = gateway_plugin::ResponseParts::new(
                StatusCode::OK,
                HeaderMap::new(),
            );
            let mut plugin_ctx = PluginContext::new(
                &mut parts,
                &mut ctx,
                Some(route.clone()),
                Some(&mut resp_parts),
            );
            record.execute(&mut plugin_ctx).await.expect("record");
        }

        // Guard 应放行
        let (mut parts, mut ctx) = make_ctx();
        let mut plugin_ctx = PluginContext::new(&mut parts, &mut ctx, Some(route), None);
        assert!(guard.execute(&mut plugin_ctx).await.unwrap().is_continue());
    }
}
