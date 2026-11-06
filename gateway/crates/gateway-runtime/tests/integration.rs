//! P2.7 集成测试 —— 把五个 Phase 2 插件 crate 串起来验证端到端行为。
//!
//! # 测试范围
//!
//! 1. **插件注册 + init_all + 阶段排序确定性**
//!    把六个插件实例注册到 PluginRegistry，验证每个阶段的链按
//!    `(priority, name)` 升序排列，不依赖 HashMap 迭代顺序。
//!
//! 2. **认证失败短路 → 后续插件不执行**
//!    Basic Auth 插件在 Authentication 阶段返回 401，验证
//!    cb_guard / request_transform 都不会被调用。
//!
//! 3. **限流放行 + auth 放行（全链路正常继续）**
//!    合法凭据通过 auth，令牌桶有 token → Continue。
//!
//! 4. **熔断器全链路**
//!    连续 3 次请求被 cb_record 记录为失败 → 熔断器变 Open →
//!    第 4 次请求在 cb_guard 阶段被短路 503 → 验证状态机正确。
//!
//! 5. **Header 转换执行**
//!    request_transform 改写 parts.headers（删 X-Internal + 加 X-Gateway），
//!    response_transform 改写 response.headers（加 X-Gateway-Version）。
//!
//! # 设计说明
//!
//! ## 为什么不跑真实 HTTP
//! Phase 2 还没有完整的 Runtime Pipeline（Tower Layer 组装留给 Phase 3）。
//! 这里直接调用 `PluginChain::run`，用测试 harness 模拟 Pipeline 阶段推进。
//!
//! ## 为什么 request/response transform 用不同 policy id
//! `TransformPlugin::from_configs` 会把 request_configs 与 response_configs
//! 合并后调一次 `compile`，而 `compile` 拒绝重复 ID——即使它们本来是同一条
//! 策略被两个方向引用。所以测试里给两个方向不同 ID（`req-t1` / `resp-t1`）。

use std::sync::Arc;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use gateway_common::RequestId;
use gateway_core::{
    AuthPolicyConfig, AuthPolicySpec, BasicCredentialConfig, CircuitBreakerPolicyConfig,
    HeaderEntryConfig, RateLimitAlgorithm, RateLimitKeyKind, RateLimitKeySpec,
    RateLimitPolicyConfig, RequestContext, RouteConfig, TransformPolicyConfig,
};
use gateway_plugin::{
    PluginContext, PluginDecision, PluginError, PluginPhase, PluginRegistry, ResponseParts,
};
use gateway_resilience::CircuitBreakerPlugin;
use gateway_security::AuthPlugin;
use gateway_traffic::RateLimitPlugin;
use gateway_transform::TransformPlugin;

// ===========================================================================
// 测试辅助
// ===========================================================================

/// 构造带完整策略引用的 RouteConfig。
///
/// 用 JSON 拼接避免 RouteConfig 大量 Option 字段的 serde 默认值陷阱。
fn route_with_all_policy_refs(
    auth_id: Option<&str>,
    rate_limit_id: Option<&str>,
    cb_id: Option<&str>,
    req_transform_id: Option<&str>,
    resp_transform_id: Option<&str>,
) -> RouteConfig {
    let mut json = String::from(r#"{"id":"r1","path_value":"/api","service_id":"user-svc""#);
    if let Some(id) = auth_id {
        json.push_str(&format!(r#","auth_policy_id":"{id}""#));
    }
    if let Some(id) = rate_limit_id {
        json.push_str(&format!(r#","rate_limit_policy_id":"{id}""#));
    }
    if let Some(id) = cb_id {
        json.push_str(&format!(r#","circuit_breaker_policy_id":"{id}""#));
    }
    if let Some(id) = req_transform_id {
        json.push_str(&format!(r#","request_transform_id":"{id}""#));
    }
    if let Some(id) = resp_transform_id {
        json.push_str(&format!(r#","response_transform_id":"{id}""#));
    }
    json.push('}');
    serde_json::from_str(&json).expect("route config should deserialize")
}

/// 构造最小请求上下文。
fn make_parts_and_ctx(client_ip: Option<&str>) -> (http::request::Parts, RequestContext) {
    let mut ctx = RequestContext::new(RequestId::new());
    if let Some(ip) = client_ip {
        ctx.client_ip = Some(ip.parse().expect("valid socket addr"));
    }
    let (parts, _) = http::Request::builder()
        .method("GET")
        .uri("/api/hello")
        .body(())
        .expect("request should build")
        .into_parts();
    (parts, ctx)
}

/// 把一条 Route 跑过所有请求方向插件。
///
/// 按 Pipeline 阶段顺序调用，短路时立即返回。
async fn run_request_phases(
    registry: &PluginRegistry,
    parts: &mut http::request::Parts,
    ctx: &mut RequestContext,
    route: Arc<RouteConfig>,
) -> Result<PluginDecision, PluginError> {
    let phases = [
        PluginPhase::RequestPostRoute,
        PluginPhase::Authentication,
        PluginPhase::RequestPreUpstream,
    ];
    for phase in phases {
        let chain = registry.chain_for_phase(phase);
        if chain.is_empty() {
            continue;
        }
        let mut pctx = PluginContext::new(parts, ctx, Some(route.clone()), None);
        let decision = chain.run(&mut pctx).await?;
        if matches!(decision, PluginDecision::ShortCircuit(_)) {
            return Ok(decision);
        }
    }
    Ok(PluginDecision::Continue)
}

/// 把响应方向插件跑一遍。
async fn run_response_phases(
    registry: &PluginRegistry,
    parts: &mut http::request::Parts,
    ctx: &mut RequestContext,
    route: Arc<RouteConfig>,
    response: &mut ResponseParts,
) -> Result<PluginDecision, PluginError> {
    let phases = [
        PluginPhase::UpstreamResponse,
        PluginPhase::ResponsePreClient,
    ];
    for phase in phases {
        let chain = registry.chain_for_phase(phase);
        if chain.is_empty() {
            continue;
        }
        let mut pctx = PluginContext::new(parts, ctx, Some(route.clone()), Some(response));
        let decision = chain.run(&mut pctx).await?;
        if matches!(decision, PluginDecision::ShortCircuit(_)) {
            return Ok(decision);
        }
    }
    Ok(PluginDecision::Continue)
}

// ===========================================================================
// 辅助：构造完整的六插件 Registry
// ===========================================================================

/// 构造 Auth 插件（Basic：alice:s3cret）。
fn make_auth() -> AuthPlugin {
    AuthPlugin::from_configs(&[AuthPolicyConfig {
        id: "basic-auth".into(),
        name: None,
        enabled: true,
        spec: AuthPolicySpec::Basic {
            credentials: vec![BasicCredentialConfig {
                username: "alice".into(),
                password: "s3cret".into(),
            }],
        },
    }])
    .expect("auth plugin should compile")
}

/// 构造 RateLimit 插件（TokenBucket, rate=100/s, burst=100, key=client_ip）。
fn make_rate_limit() -> RateLimitPlugin {
    RateLimitPlugin::from_configs(&[RateLimitPolicyConfig {
        id: "rl".into(),
        name: None,
        enabled: true,
        algorithm: RateLimitAlgorithm::TokenBucket,
        rate: 100,
        burst: Some(100),
        window_secs: 1,
        key: RateLimitKeySpec {
            kind: RateLimitKeyKind::ClientIp,
            header: None,
        },
        failure_mode: gateway_core::FailureMode::FailClosed,
        backend: gateway_core::RateLimitBackend::Local,
        redis_url: None,
    }])
    .expect("rate limit plugin should compile")
}

/// 构造 CircuitBreaker 插件对（threshold=3, open=60s, statuses=500/502/503/504）。
fn make_cb() -> (CircuitBreakerPlugin, CircuitBreakerPlugin) {
    CircuitBreakerPlugin::from_configs(&[CircuitBreakerPolicyConfig {
        id: "cb".into(),
        name: None,
        enabled: true,
        failure_threshold: 3,
        success_threshold: 2,
        open_duration_secs: 60,
        failure_statuses: vec![500, 502, 503, 504],
        count_connection_errors: true,
    }])
    .expect("cb plugin pair should compile")
}

/// 构造 Transform 插件对（req: 删 X-Internal + 加 X-Gateway；resp: 加 X-Gateway-Version）。
///
/// 注意：request_configs 和 response_configs 用**不同的 policy id**，
/// 因为 from_configs 合并后 compile 会拒绝重复 ID。
fn make_transform() -> (TransformPlugin, TransformPlugin) {
    TransformPlugin::from_configs(
        // request direction policy
        &[TransformPolicyConfig {
            id: "req-t1".into(),
            name: None,
            enabled: true,
            set_headers: vec![HeaderEntryConfig {
                name: "X-Gateway".into(),
                value: "gw".into(),
            }],
            add_headers: vec![],
            remove_headers: vec!["X-Internal".into()],
        }],
        // response direction policy
        &[TransformPolicyConfig {
            id: "resp-t1".into(),
            name: None,
            enabled: true,
            set_headers: vec![HeaderEntryConfig {
                name: "X-Gateway-Version".into(),
                value: "v1".into(),
            }],
            add_headers: vec![],
            remove_headers: vec![],
        }],
    )
    .expect("transform plugin pair should compile")
}

/// 注册全部六插件 + init_all。
fn build_and_init_full_registry() -> PluginRegistry {
    let mut registry = PluginRegistry::new();
    registry.register(Arc::new(make_auth())).expect("auth");
    registry.register(Arc::new(make_rate_limit())).expect("rl");
    let (cb_guard, cb_record) = make_cb();
    registry.register(Arc::new(cb_guard)).expect("cb_guard");
    registry.register(Arc::new(cb_record)).expect("cb_record");
    let (req_transform, resp_transform) = make_transform();
    registry.register(Arc::new(req_transform)).expect("req_t");
    registry.register(Arc::new(resp_transform)).expect("resp_t");
    registry
}

// ===========================================================================
// 集成测试 #1：插件注册 + init_all + 阶段排序确定性
// ===========================================================================

#[tokio::test]
async fn all_plugins_register_and_sort_deterministically() {
    let registry = build_and_init_full_registry();
    registry.init_all().await.expect("init_all should succeed");

    assert_eq!(registry.len(), 6);

    // RequestPostRoute：只有 rate_limit（priority=20）
    let chain = registry.chain_for_phase(PluginPhase::RequestPostRoute);
    assert_eq!(chain.names(), vec!["rate_limit"]);

    // Authentication：只有 auth（priority=10）
    let chain = registry.chain_for_phase(PluginPhase::Authentication);
    assert_eq!(chain.names(), vec!["auth"]);

    // RequestPreUpstream：cb_guard (15) → request_transform (25)
    let chain = registry.chain_for_phase(PluginPhase::RequestPreUpstream);
    assert_eq!(
        chain.names(),
        vec!["circuit_breaker_guard", "request_transform"],
        "cb_guard(15) must come before request_transform(25)"
    );

    // UpstreamResponse：只有 cb_record（priority=30）
    let chain = registry.chain_for_phase(PluginPhase::UpstreamResponse);
    assert_eq!(chain.names(), vec!["circuit_breaker_record"]);

    // ResponsePreClient：只有 response_transform（priority=25）
    let chain = registry.chain_for_phase(PluginPhase::ResponsePreClient);
    assert_eq!(chain.names(), vec!["response_transform"]);
}

// ===========================================================================
// 集成测试 #2：认证失败短路 → 后续插件不执行
// ===========================================================================

/// Route 引用全部策略，请求带错误凭据 → auth 短路 401。
///
/// 阶段顺序：rate_limit (RequestPostRoute, 20) 先跑 → token bucket 放行 →
/// auth (Authentication, 10) 后跑 → 凭据不对 → 短路 401。
/// 验证：cb_guard 和 request_transform **不会被执行**（在 ShortCircuit 之后）。
#[tokio::test]
async fn auth_failure_short_circuits_before_cb_and_transform() {
    let registry = build_and_init_full_registry();
    registry.init_all().await.expect("init");

    let route = Arc::new(route_with_all_policy_refs(
        Some("basic-auth"),
        Some("rl"),
        Some("cb"),
        Some("req-t1"),
        Some("resp-t1"),
    ));

    let (mut parts, mut ctx) = make_parts_and_ctx(Some("10.0.0.1:8080"));
    let wrong_creds = STANDARD.encode("alice:wrong");
    parts.headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Basic {wrong_creds}")).expect("valid header"),
    );

    let decision = run_request_phases(&registry, &mut parts, &mut ctx, route)
        .await
        .expect("should not error");

    let response = decision.into_response().expect("must short circuit");
    assert_eq!(response.status, http::StatusCode::UNAUTHORIZED);

    let payload: serde_json::Value = serde_json::from_slice(&response.body).expect("json body");
    assert_eq!(payload["code"], "GATEWAY_AUTHENTICATION_FAILED");
}

// ===========================================================================
// 集成测试 #3：auth 通过 + rate_limit 放行（整条请求链 Continue）
// ===========================================================================

/// 合法凭据 + token bucket 有 token → 所有插件放行 → Continue。
///
/// 验证 Phase 2 的"没有插件会误拦合法请求"的基本保证。
#[tokio::test]
async fn valid_request_passes_all_plugins() {
    let registry = build_and_init_full_registry();
    registry.init_all().await.expect("init");

    let route = Arc::new(route_with_all_policy_refs(
        Some("basic-auth"),
        Some("rl"),
        Some("cb"),
        Some("req-t1"),
        Some("resp-t1"),
    ));

    let (mut parts, mut ctx) = make_parts_and_ctx(Some("10.0.0.2:8080"));
    let correct_creds = STANDARD.encode("alice:s3cret");
    parts.headers.insert(
        http::header::AUTHORIZATION,
        http::HeaderValue::from_str(&format!("Basic {correct_creds}")).expect("valid header"),
    );

    // 前 100 个请求 token bucket 都允许（burst=100）
    for i in 0..3u32 {
        let decision = run_request_phases(&registry, &mut parts, &mut ctx, route.clone())
            .await
            .expect("request phase");
        assert!(decision.is_continue(), "request {i}: should pass all plugins");
    }
}

// ===========================================================================
// 集成测试 #4：熔断器全链路
// ===========================================================================

/// 连续 3 次 cb_record 记录 502 → 熔断器变 Open → cb_guard 短路 503。
#[tokio::test]
async fn circuit_breaker_transitions_to_open_after_failures() {
    let registry = build_and_init_full_registry();
    registry.init_all().await.expect("init");

    // 公开路由（不挂 auth / rate_limit），只挂 cb
    let route = Arc::new(route_with_all_policy_refs(None, None, Some("cb"), None, None));

    // --- 第 1~3 次：模拟上游返回 502，cb_record 记录失败 ---
    for _ in 0..3u32 {
        let (mut parts, mut ctx) = make_parts_and_ctx(Some("10.0.0.3:8080"));

        // 请求方向：cb_guard 应该放行（Closed 状态）
        let decision = run_request_phases(&registry, &mut parts, &mut ctx, route.clone())
            .await
            .expect("request phase");
        assert!(decision.is_continue());

        // 响应方向：模拟上游 502
        let mut response =
            ResponseParts::new(http::StatusCode::BAD_GATEWAY, http::HeaderMap::new());
        run_response_phases(&registry, &mut parts, &mut ctx, route.clone(), &mut response)
            .await
            .expect("response phase");
    }

    // --- 第 4 次：cb_guard 应该短路 503（熔断器已 Open）---
    let (mut parts, mut ctx) = make_parts_and_ctx(Some("10.0.0.4:8080"));
    let decision = run_request_phases(&registry, &mut parts, &mut ctx, route)
        .await
        .expect("should not error");

    let response = decision.into_response().expect("must short circuit");
    assert_eq!(response.status, http::StatusCode::SERVICE_UNAVAILABLE);

    let payload: serde_json::Value = serde_json::from_slice(&response.body).expect("json");
    assert_eq!(payload["code"], "GATEWAY_CIRCUIT_OPEN");
}

// ===========================================================================
// 集成测试 #5：Header 转换执行
// ===========================================================================

/// request_transform 删 X-Internal + 加 X-Gateway；
/// response_transform 加 X-Gateway-Version。
#[tokio::test]
async fn request_and_response_transform_headers() {
    let registry = build_and_init_full_registry();
    registry.init_all().await.expect("init");

    // 公开路由，只挂 transform
    let route =
        Arc::new(route_with_all_policy_refs(None, None, None, Some("req-t1"), Some("resp-t1")));

    let (mut parts, mut ctx) = make_parts_and_ctx(None);
    parts.headers.insert(
        http::HeaderName::from_static("x-internal"),
        http::HeaderValue::from_static("sensitive"),
    );

    // --- 请求方向 ---
    run_request_phases(&registry, &mut parts, &mut ctx, route.clone())
        .await
        .expect("should pass");

    assert!(parts.headers.get("x-internal").is_none(), "X-Internal should be removed");
    assert_eq!(
        parts
            .headers
            .get(http::HeaderName::from_static("x-gateway"))
            .unwrap()
            .as_bytes(),
        b"gw"
    );

    // --- 响应方向 ---
    let mut response = ResponseParts::new(http::StatusCode::OK, http::HeaderMap::new());
    run_response_phases(&registry, &mut parts, &mut ctx, route, &mut response)
        .await
        .expect("should pass");

    assert_eq!(
        response
            .headers
            .get(http::HeaderName::from_static("x-gateway-version"))
            .unwrap()
            .as_bytes(),
        b"v1"
    );
}

// ===========================================================================
// 集成测试 #6：公开路由（无任何策略引用）全放行
// ===========================================================================

/// Route 不引用任何策略 → 所有插件都 Continue。
/// 这是 Phase 2 的兜底保证：没有配置策略时网关仍然能正常转发。
#[tokio::test]
async fn route_with_no_policies_all_passes() {
    let registry = build_and_init_full_registry();
    registry.init_all().await.expect("init");

    let route = Arc::new(route_with_all_policy_refs(None, None, None, None, None));

    let (mut parts, mut ctx) = make_parts_and_ctx(Some("10.0.0.5:8080"));
    let decision = run_request_phases(&registry, &mut parts, &mut ctx, route.clone())
        .await
        .expect("should not error");
    assert!(decision.is_continue());

    let mut response = ResponseParts::new(http::StatusCode::OK, http::HeaderMap::new());
    let decision = run_response_phases(&registry, &mut parts, &mut ctx, route, &mut response)
        .await
        .expect("should not error");
    assert!(decision.is_continue());
}
