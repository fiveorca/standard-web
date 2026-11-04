//! 鉴权插件 —— 把已编译策略接到插件链的 `Authentication` 阶段。
//!
//! # 在 Pipeline 中的位置
//!
//! ```text
//! Route 匹配完成
//!     │
//!     ▼
//! Authentication（本插件，priority = 10）
//!     ├── route.auth_policy_id = None ──▶ Continue（公开路由）
//!     ├── 策略通过 ──▶ 写入 AuthIdentity 到 parts.extensions ──▶ Continue
//!     └── 策略失败 ──▶ ShortCircuit(401/403)，后续插件与上游全部跳过
//! ```
//!
//! # 为什么一个插件处理全部五类策略
//!
//! Route 只有一个 `auth_policy_id`，同一路由不会同时挂 Basic 与 JWT。
//! 因此按"策略类型"注册多个插件没有意义，反而会引入"哪个先执行"的歧义。
//! 用单一插件 + 已编译策略表，既保证只有一个认证结论，
//! 也让执行顺序对审计完全透明。
//!
//! # fail closed 约定
//!   - 找不到路由（装配错误）→ `Err`（Runtime 映射 500），不放行
//!   - 路由引用了未编译的策略（配置错误）→ `Err`，不放行
//!   - 策略执行返回拒绝 → `ShortCircuit`，不再进入上游

use std::sync::Arc;
use std::time::Duration;

use gateway_core::AuthPolicyConfig;
use gateway_plugin::{
    Plugin, PluginContext, PluginDecision, PluginError, PluginPhase, PluginResponse,
};
use http::header::WWW_AUTHENTICATE;
use http::HeaderValue;

use crate::model::AuthRequestView;
use crate::policy::CompiledAuthPolicies;

/// 插件唯一名称。
///
/// 同时是 `PluginRegistry` 的键与同优先级下的排序键，必须是编译期常量。
pub const AUTH_PLUGIN_NAME: &str = "auth";

/// 鉴权插件。
///
/// 持有只读的策略表；插件本身被 `Arc` 共享，跨请求并发调用无内部可变状态。
#[derive(Debug, Clone)]
pub struct AuthPlugin {
    /// 已编译的全部鉴权策略（启动期一次性构建）
    policies: Arc<CompiledAuthPolicies>,
}

impl AuthPlugin {
    /// 用已编译的策略表构造插件。
    ///
    /// 参数：
    /// - `policies`：`CompiledAuthPolicies`（通常与 Runtime 共享同一个 `Arc`）
    pub fn new(policies: Arc<CompiledAuthPolicies>) -> Self {
        Self { policies }
    }

    /// 从配置直接编译并构造插件。
    ///
    /// 参数：
    /// - `configs`：`policies.auth` 段配置
    ///
    /// 返回 `Err(PluginError::ConfigInvalid)` 表示策略配置非法，
    /// 调用方应阻止网关启动（安全策略不允许带着错误运行）。
    pub fn from_configs(configs: &[AuthPolicyConfig]) -> Result<Self, PluginError> {
        let policies = CompiledAuthPolicies::compile(configs).map_err(|message| {
            PluginError::ConfigInvalid {
                plugin: AUTH_PLUGIN_NAME.to_string(),
                message,
            }
        })?;
        Ok(Self::new(Arc::new(policies)))
    }

    /// 只读访问策略表（启动自检/管理接口用）。
    pub fn policies(&self) -> &CompiledAuthPolicies {
        &self.policies
    }
}

#[async_trait::async_trait]
impl Plugin for AuthPlugin {
    /// 插件名（注册表键）
    fn name(&self) -> &'static str {
        AUTH_PLUGIN_NAME
    }

    /// 认证阶段：必须在任何业务插件与上游转发之前完成
    fn phase(&self) -> PluginPhase {
        PluginPhase::Authentication
    }

    /// 安全插件使用较小的优先级值：确保它在同阶段内排在最前
    fn priority(&self) -> i32 {
        10
    }

    /// 单次执行超时。
    ///
    /// JWT 验签是纯 CPU 运算，正常耗时在微秒级；500ms 只用于兜底
    /// "异常超长 Token / 实现缺陷"导致的阻塞，超时后由链 fail closed。
    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_millis(500))
    }

    /// Phase 2 的插件由策略段驱动，没有独立的 JSON Schema。
    fn config_schema(&self) -> Option<&'static str> {
        None
    }

    /// 配置校验已在 `from_configs` 的编译阶段完成。
    fn validate_config(&self, _config: &serde_json::Value) -> Result<(), PluginError> {
        Ok(())
    }

    /// 初始化：策略表已编译完成，这里只输出一条自检日志。
    async fn init(&self) -> Result<(), PluginError> {
        tracing::info!(
            target: "security",
            plugin = AUTH_PLUGIN_NAME,
            policies = self.policies.len(),
            "auth plugin initialized"
        );
        Ok(())
    }

    /// 执行鉴权。
    async fn execute(
        &self,
        ctx: &mut PluginContext<'_>,
    ) -> Result<PluginDecision, PluginError> {
        // 1) 认证阶段在路由匹配之后执行；没有 route 说明 Runtime 装配顺序有误。
        //    此时无法确定该请求应适用哪条策略 → fail closed（不能默认放行）。
        let route = match ctx.route.as_ref() {
            Some(route) => Arc::clone(route),
            None => {
                return Err(PluginError::ExecutionFailed {
                    plugin: AUTH_PLUGIN_NAME.to_string(),
                    message: "authentication phase invoked without a matched route".to_string(),
                });
            },
        };

        // 2) 公开路由：没有配置鉴权策略，直接放行
        let Some(policy_id) = route.auth_policy_id.as_deref() else {
            return Ok(PluginDecision::Continue);
        };

        // 3) 查找已编译策略。查不到属于配置错误（validate_references 应已拦截），
        //    运行期仍 fail closed，避免"写错 id 导致鉴权静默失效"。
        let Some(policy) = self.policies.get(policy_id) else {
            return Err(PluginError::ExecutionFailed {
                plugin: AUTH_PLUGIN_NAME.to_string(),
                message: format!("auth policy '{policy_id}' was not compiled"),
            });
        };

        // 4) 构造只读视图并执行策略。
        //    把视图放在独立作用域，确保 `ctx.parts` 的不可变借用
        //    在下面写入 extensions 之前结束（借用检查器要求）。
        let outcome = {
            let view = AuthRequestView {
                headers: &ctx.parts.headers,
                uri: &ctx.parts.uri,
                client_ip: ctx.ctx.client_ip,
            };
            policy.evaluate(&view)
        };

        match outcome {
            // 通过：写入身份（若有），继续后续插件
            Ok(identity) => {
                if let Some(identity) = identity {
                    // 供 Authorization 阶段 / 后续业务插件读取；
                    // AuthIdentity 是 Clone + Send + Sync + 'static，满足 Extensions 约束
                    ctx.parts.extensions.insert(identity);
                }
                Ok(PluginDecision::Continue)
            },

            // 拒绝：短路，返回统一 JSON 错误
            Err(rejection) => {
                tracing::debug!(
                    target: "security",
                    request_id = ctx.request_id(),
                    route = %route.id,
                    policy = %policy.id,
                    status = rejection.status.as_u16(),
                    // 只记录机制与结论，绝不记录凭据原文
                    "authentication rejected"
                );

                // 复用 Runtime 的统一错误结构，保证客户端看到的格式一致
                let mut response = PluginResponse::from_error(
                    rejection.status,
                    rejection.code.as_str(),
                    &rejection.message,
                    Some(ctx.request_id()),
                );

                // 401 必须携带 WWW-Authenticate（RFC 7235 §3.1）；
                // 挑战值由策略构造，非法字符只可能是实现缺陷，失败时省略而不是 panic
                if let Some(challenge) = rejection.challenge.as_deref() {
                    if let Ok(value) = HeaderValue::from_str(challenge) {
                        response.headers.insert(WWW_AUTHENTICATE, value);
                    }
                }

                Ok(PluginDecision::ShortCircuit(response))
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use gateway_common::RequestId;
    use gateway_core::{AuthPolicySpec, BasicCredentialConfig, RequestContext, RouteConfig};
    use http::{HeaderMap, HeaderValue};

    /// 辅助：构造带 `auth_policy_id` 的最小 RouteConfig（其余字段用 serde 默认值）
    fn route_with_policy(policy_id: Option<&str>) -> RouteConfig {
        // 先写必填字段，再按需追加 auth_policy_id，最后补右花括号；
        // 避免用 "末尾逗号" 拼接方式导致 JSON 非法
        let mut json = String::from(r#"{"id":"r1","path_value":"/","service_id":"svc""#);
        if let Some(id) = policy_id {
            // 只拼接受控的测试常量，不涉及用户输入
            json.push_str(&format!(r#","auth_policy_id":"{id}""#));
        }
        json.push('}');
        serde_json::from_str(&json).expect("route config should deserialize")
    }

    /// 辅助：Basic 策略插件
    fn basic_plugin() -> AuthPlugin {
        AuthPlugin::from_configs(&[AuthPolicyConfig {
            id: "basic".into(),
            name: None,
            enabled: true,
            spec: AuthPolicySpec::Basic {
                credentials: vec![BasicCredentialConfig {
                    username: "alice".into(),
                    password: "s3cret".into(),
                }],
            },
        }])
        .expect("basic plugin should compile")
    }

    /// 辅助：构造请求 Parts 与空 body
    fn parts_with(headers: HeaderMap) -> http::request::Parts {
        let (mut parts, _body) = http::Request::builder()
            .method("GET")
            .uri("/api")
            .body(())
            .expect("request should build")
            .into_parts();
        parts.headers = headers;
        parts
    }

    /// 辅助：Authorization: Basic 头
    fn basic_headers(user: &str, password: &str) -> HeaderMap {
        let encoded = STANDARD.encode(format!("{user}:{password}"));
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).expect("valid header"),
        );
        headers
    }

    /// 缺少 route：装配错误 → fail closed（返回 Err）
    #[tokio::test]
    async fn missing_route_is_fail_closed() {
        let plugin = basic_plugin();
        let mut parts = parts_with(HeaderMap::new());
        let mut request_ctx = RequestContext::new(RequestId::from_string("req-1"));
        let mut ctx = PluginContext::new(&mut parts, &mut request_ctx, None, None);

        let result = plugin.execute(&mut ctx).await;
        assert!(result.is_err(), "no route must not silently pass");
    }

    /// 公开路由（没有 auth_policy_id）：直接放行
    #[tokio::test]
    async fn public_route_passes_without_policy() {
        let plugin = basic_plugin();
        let mut parts = parts_with(HeaderMap::new());
        let mut request_ctx = RequestContext::new(RequestId::from_string("req-2"));
        let route = Arc::new(route_with_policy(None));
        let mut ctx = PluginContext::new(&mut parts, &mut request_ctx, Some(route), None);

        let decision = plugin.execute(&mut ctx).await.expect("should execute");
        assert!(decision.is_continue());
    }

    /// 认证通过：Continue，并把身份写入 parts.extensions
    #[tokio::test]
    async fn valid_credentials_pass_and_insert_identity() {
        let plugin = basic_plugin();
        let mut parts = parts_with(basic_headers("alice", "s3cret"));
        let mut request_ctx = RequestContext::new(RequestId::from_string("req-3"));
        let route = Arc::new(route_with_policy(Some("basic")));
        let mut ctx = PluginContext::new(&mut parts, &mut request_ctx, Some(route), None);

        let decision = plugin.execute(&mut ctx).await.expect("should execute");
        assert!(decision.is_continue());

        // 身份必须可在 extensions 中读到（供授权阶段消费）
        let identity = parts
            .extensions
            .get::<crate::model::AuthIdentity>()
            .expect("identity should be inserted");
        assert_eq!(identity.subject.as_deref(), Some("alice"));
    }

    /// 认证失败：短路 401，带 WWW-Authenticate 与统一 JSON 错误体
    #[tokio::test]
    async fn invalid_credentials_short_circuit_with_401() {
        let plugin = basic_plugin();
        let mut parts = parts_with(basic_headers("alice", "wrong"));
        let mut request_ctx = RequestContext::new(RequestId::from_string("req-4"));
        let route = Arc::new(route_with_policy(Some("basic")));
        let mut ctx = PluginContext::new(&mut parts, &mut request_ctx, Some(route), None);

        let decision = plugin.execute(&mut ctx).await.expect("should execute");
        let response = decision.into_response().expect("must short circuit");

        assert_eq!(response.status, http::StatusCode::UNAUTHORIZED);
        // 401 必须带 Basic 挑战
        let challenge = response
            .headers
            .get(WWW_AUTHENTICATE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(challenge, "Basic realm=\"gateway\"");

        // 错误体与 Runtime 统一结构一致
        let payload: serde_json::Value =
            serde_json::from_slice(&response.body).expect("json body");
        assert_eq!(payload["code"], "GATEWAY_AUTHENTICATION_FAILED");
        assert_eq!(payload["request_id"], "req-4");
    }

    /// 路由引用未编译的策略：配置错误 → fail closed（返回 Err）
    #[tokio::test]
    async fn unknown_policy_is_fail_closed() {
        let plugin = basic_plugin();
        let mut parts = parts_with(HeaderMap::new());
        let mut request_ctx = RequestContext::new(RequestId::from_string("req-5"));
        let route = Arc::new(route_with_policy(Some("missing")));
        let mut ctx = PluginContext::new(&mut parts, &mut request_ctx, Some(route), None);

        assert!(plugin.execute(&mut ctx).await.is_err());
    }
}
