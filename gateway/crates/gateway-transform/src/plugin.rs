//! Header 转换插件：请求方向 + 响应方向两个实例。
//!
//! # 为什么两个插件实例
//! `Plugin::phase()` 返回固定值，插件链按 phase 排序后只执行一次。
//! 所以需要：
//!
//! | 插件实例 | Phase | 处理什么 |
//! |---|---|---|
//! | `RequestTransformPlugin` | `RequestPreUpstream` | 改写请求 HeaderMap |
//! | `ResponseTransformPlugin` | `ResponsePreClient` | 改写响应 HeaderMap |
//!
//! 它们各自有独立的名字（`request_transform` / `response_transform`），
//! 但共享同一个已编译的策略表 `CompiledTransformPolicies`。
//! Route 上 `request_transform_id` / `response_transform_id` 分别引用
//! 同一策略集合中的条目。
//!
//! # fail closed 约定
//!   - Route 引用未编译的策略 → `Err`（500），不放行/不返回
//!   - Header 值替换后非法 → `Err`（500），避免注入型安全事故

use std::sync::Arc;
use std::time::Duration;

use gateway_core::TransformPolicyConfig;
use gateway_plugin::{
    Plugin, PluginContext, PluginDecision, PluginError, PluginPhase,
};

use crate::compile::CompiledTransformPolicies;
use crate::placeholder::PlaceholderEnv;

// ---------------------------------------------------------------------------
// 通用插件结构（请求/响应两个实例共享）
// ---------------------------------------------------------------------------

/// 方向标识：决定执行阶段、日志标签、Route 引用字段
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransformDirection {
    /// 请求方向：改写 `parts.headers`
    Request,
    /// 响应方向：改写 `response.headers`
    Response,
}

/// Header 转换插件（请求/响应方向两个实例共享同一类型）。
#[derive(Debug, Clone)]
pub struct TransformPlugin {
    /// 已编译的全部转换策略
    policies: Arc<CompiledTransformPolicies>,
    /// 本实例负责的方向
    direction: TransformDirection,
}

impl TransformPlugin {
    /// 构造插件。
    ///
    /// 参数：
    /// - `policies`：已编译的策略集合
    /// - `direction`：请求或响应方向
    pub fn new(policies: Arc<CompiledTransformPolicies>, direction: TransformDirection) -> Self {
        Self { policies, direction }
    }

    /// 从配置直接编译并构造一对插件（请求 + 响应）。
    ///
    /// 参数：
    /// - `request_configs`：`policies.request_transform` 段
    /// - `response_configs`：`policies.response_transform` 段
    ///
    /// 返回两个独立实例，可分别注册到 `PluginRegistry`。
    pub fn from_configs(
        request_configs: &[TransformPolicyConfig],
        response_configs: &[TransformPolicyConfig],
    ) -> Result<(Self, Self), PluginError> {
        // 请求和响应方向共享同一个编译函数——TransformPolicyConfig 结构相同
        let all: Vec<TransformPolicyConfig> = request_configs
            .iter()
            .chain(response_configs.iter())
            .cloned()
            .collect();
        let policies = CompiledTransformPolicies::compile(&all).map_err(|message| {
            PluginError::ConfigInvalid {
                plugin: PLUGIN_NAME.into(),
                message,
            }
        })?;
        let policies = Arc::new(policies);
        Ok((
            Self::new(policies.clone(), TransformDirection::Request),
            Self::new(policies, TransformDirection::Response),
        ))
    }

    /// 插件名（两个实例不同，避免 Registry 的 DuplicateName）
    fn name_for(direction: TransformDirection) -> &'static str {
        match direction {
            TransformDirection::Request => "request_transform",
            TransformDirection::Response => "response_transform",
        }
    }

    /// 日志标签
    fn label_for(direction: TransformDirection) -> &'static str {
        match direction {
            TransformDirection::Request => "request",
            TransformDirection::Response => "response",
        }
    }

    /// Route 上引用转换策略的字段名
    fn route_field(direction: TransformDirection) -> &'static str {
        match direction {
            TransformDirection::Request => "request_transform_id",
            TransformDirection::Response => "response_transform_id",
        }
    }

    /// 只读访问策略表
    pub fn policies(&self) -> &CompiledTransformPolicies {
        &self.policies
    }

    /// 当前方向
    pub fn direction(&self) -> TransformDirection {
        self.direction
    }
}

/// Plugin 接口实现
#[async_trait::async_trait]
impl Plugin for TransformPlugin {
    fn name(&self) -> &'static str {
        Self::name_for(self.direction)
    }

    fn phase(&self) -> PluginPhase {
        match self.direction {
            // 请求方向：转发给上游之前
            TransformDirection::Request => PluginPhase::RequestPreUpstream,
            // 响应方向：返回给客户端之前
            TransformDirection::Response => PluginPhase::ResponsePreClient,
        }
    }

    /// 通用 transform priority 25（在 auth=10、rate_limit=20 之后）
    fn priority(&self) -> i32 {
        25
    }

    /// 单次执行超时：Header 改写是纯内存操作，50ms 兜底
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
            target: "transform",
            plugin = self.name(),
            direction = Self::label_for(self.direction),
            policies = self.policies.len(),
            "transform plugin initialized"
        );
        Ok(())
    }

    async fn execute(
        &self,
        ctx: &mut PluginContext<'_>,
    ) -> Result<PluginDecision, PluginError> {
        // 1) 取 Route（请求方向必须存在；响应方向也必须存在，因为短路响应也经过）
        let Some(route) = ctx.route.as_ref() else {
            return Err(PluginError::ExecutionFailed {
                plugin: self.name().to_string(),
                message: format!(
                    "transform({}) phase invoked without a matched route",
                    Self::label_for(self.direction)
                ),
            });
        };

        // 2) 读取 Route 上对应方向的策略 ID
        let policy_id_opt = match self.direction {
            TransformDirection::Request => route.request_transform_id.as_deref(),
            TransformDirection::Response => route.response_transform_id.as_deref(),
        };

        let Some(policy_id) = policy_id_opt else {
            return Ok(PluginDecision::Continue);
        };

        // 3) 查找已编译策略
        let Some(policy) = self.policies.get(policy_id) else {
            return Err(PluginError::ExecutionFailed {
                plugin: self.name().to_string(),
                message: format!(
                    "{} policy '{policy_id}' was not compiled",
                    Self::route_field(self.direction)
                ),
            });
        };

        // 4) 策略禁用：直接跳过
        if !policy.enabled {
            return Ok(PluginDecision::Continue);
        }

        // 5) 组装占位符替换环境快照
        //
        // 这里先把 PluginContext 里需要的字段组装成独立的 PlaceholderEnv，
        // 这样后续 apply 就不需要再持有 &PluginContext——解决了响应方向
        // 分支中 `response.headers` 的可变借用与 `ctx` 不可变借用冲突的问题。
        let env = PlaceholderEnv::from_plugin_ctx(ctx);

        // 6) 执行 Header 改写
        let outcome = {
            match self.direction {
                TransformDirection::Request => {
                    let mut headers = ctx.parts.headers.clone();
                    let result = policy.apply(&mut headers, &env);
                    ctx.parts.headers = headers;
                    result
                },
                TransformDirection::Response => {
                    let Some(response) = ctx.response.as_mut() else {
                        return Err(PluginError::ExecutionFailed {
                            plugin: self.name().to_string(),
                            message:
                                "response transform invoked without a response view".to_string(),
                        });
                    };
                    let mut headers = response.headers.clone();
                    let result = policy.apply(&mut headers, &env);
                    response.headers = headers;
                    result
                },
            }
        };

        match outcome {
            Ok(_) => Ok(PluginDecision::Continue),
            // Header 值替换后非法 → fail closed（避免注入型安全事故）
            Err(reason) => Err(PluginError::ExecutionFailed {
                plugin: self.name().to_string(),
                message: reason,
            }),
        }
    }
}

/// 插件唯一族名（用于日志/错误）；两个实例用具体方向做区分
pub const PLUGIN_NAME: &str = "transform";

#[cfg(test)]
mod tests {
    use super::*;
    use gateway_common::RequestId;
    use gateway_core::RequestContext;
    use http::HeaderMap;

    /// 辅助：构造最小 RouteConfig（带 request_transform_id）
    fn route_with_transform_id(id: Option<&str>) -> gateway_core::models::RouteConfig {
        let mut json = String::from(
            r#"{"id":"r1","path_value":"/","service_id":"svc"}"#,
        );
        if let Some(id) = id {
            // 两个方向都指向同一策略 id（测试用）
            json = format!(
                r#"{{"id":"r1","path_value":"/","service_id":"svc",
"request_transform_id":"{id}","response_transform_id":"{id}"}}"#
            );
        }
        serde_json::from_str(&json).expect("route")
    }

    /// 辅助：构造请求 Parts + ctx
    fn make_ctx() -> (http::request::Parts, RequestContext) {
        let mut ctx = RequestContext::new(RequestId::from_string("req-t1"));
        ctx.client_ip = Some("10.0.0.1:8080".parse().expect("addr"));
        let (parts, _) = http::Request::builder()
            .method("GET")
            .uri("http://example.com/api")
            .body(())
            .expect("request")
            .into_parts();
        (parts, ctx)
    }

    /// 辅助：构造编译好的策略集合
    fn make_plugin_pair() -> (TransformPlugin, TransformPlugin) {
        let json = r#"[{"id":"t1","set_headers":[{"name":"X-Gateway","value":"gw"}],"remove_headers":["X-Internal"]}]"#;
        let configs: Vec<TransformPolicyConfig> = serde_json::from_str(json).expect("deserialize");
        TransformPlugin::from_configs(&configs, &[]).expect("compile")
    }

    /// 请求方向插件能改写 parts.headers
    #[tokio::test]
    async fn request_transform_modifies_parts_headers() {
        let (request_plugin, _) = make_plugin_pair();
        let (mut parts, mut ctx) = make_ctx();
        parts.headers.insert(
            http::HeaderName::from_static("x-internal"),
            http::HeaderValue::from_static("secret"),
        );
        let route = std::sync::Arc::new(route_with_transform_id(Some("t1")));
        let mut plugin_ctx = PluginContext::new(&mut parts, &mut ctx, Some(route), None);

        let decision = request_plugin
            .execute(&mut plugin_ctx)
            .await
            .expect("execute");
        assert!(decision.is_continue());

        // 验证：X-Internal 被删除，X-Gateway 被设置
        assert!(plugin_ctx.parts.headers.get("X-Internal").is_none());
        assert_eq!(
            plugin_ctx.parts.headers.get("X-Gateway").unwrap().as_bytes(),
            b"gw"
        );
    }

    /// 响应方向插件能改写 response.headers
    #[tokio::test]
    async fn response_transform_modifies_response_headers() {
        let (_, response_plugin) = make_plugin_pair();
        let (mut parts, mut ctx) = make_ctx();
        let route = std::sync::Arc::new(route_with_transform_id(Some("t1")));

        // ResponsePreClient 阶段会有 response 视图传入
        let mut resp_parts = gateway_plugin::ResponseParts::new(
            http::StatusCode::OK,
            HeaderMap::new(),
        );
        resp_parts.headers.insert(
            http::HeaderName::from_static("x-internal"),
            http::HeaderValue::from_static("secret"),
        );

        let mut plugin_ctx =
            PluginContext::new(&mut parts, &mut ctx, Some(route), Some(&mut resp_parts));

        let decision = response_plugin
            .execute(&mut plugin_ctx)
            .await
            .expect("execute");
        assert!(decision.is_continue());

        assert!(resp_parts.headers.get("X-Internal").is_none());
        assert_eq!(
            resp_parts.headers.get("X-Gateway").unwrap().as_bytes(),
            b"gw"
        );
    }

    /// 引用不存在策略 → fail closed（Err）
    #[tokio::test]
    async fn unknown_policy_is_fail_closed() {
        let (request_plugin, _) = make_plugin_pair();
        let (mut parts, mut ctx) = make_ctx();
        let route = std::sync::Arc::new(route_with_transform_id(Some("missing")));
        let mut plugin_ctx = PluginContext::new(&mut parts, &mut ctx, Some(route), None);

        assert!(request_plugin.execute(&mut plugin_ctx).await.is_err());
    }

    /// Route 没有引用策略 → 直接放行
    #[tokio::test]
    async fn no_policy_passes() {
        let (request_plugin, _) = make_plugin_pair();
        let (mut parts, mut ctx) = make_ctx();
        let route = std::sync::Arc::new(route_with_transform_id(None));
        let mut plugin_ctx = PluginContext::new(&mut parts, &mut ctx, Some(route), None);

        let decision = request_plugin
            .execute(&mut plugin_ctx)
            .await
            .expect("execute");
        assert!(decision.is_continue());
    }

    /// 响应方向插件在请求阶段（无 response 视图）被误调 → Err
    #[tokio::test]
    async fn response_plugin_without_response_view_is_err() {
        let (_, response_plugin) = make_plugin_pair();
        let (mut parts, mut ctx) = make_ctx();
        let route = std::sync::Arc::new(route_with_transform_id(Some("t1")));
        // 请求方向：没有 response 视图
        let mut plugin_ctx = PluginContext::new(&mut parts, &mut ctx, Some(route), None);

        assert!(response_plugin.execute(&mut plugin_ctx).await.is_err());
    }
}
