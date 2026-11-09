//! 请求处理管线。

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Body;
use axum::extract::{ConnectInfo, Request, State};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, ORIGIN, RETRY_AFTER};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use http_body::Body as HttpBody;
use http_body_util::{BodyExt, Limited};
use opentelemetry::trace::Span;

use crate::cache::{
    cache_key, cached_response, request_cacheable, response_cacheable, CachePolicy,
};
use crate::config::model::IdentityHeadersConfig;
use crate::core::filter::{FilterRequest, FilterResponse};
use crate::core::gateway::GatewayState;
use crate::core::predicate::PredicateRequest;
use crate::core::proxy::{ProxyBody, ProxyOptions, ProxyRequest};
use crate::error::{GatewayError, Result};
use crate::middleware::authorization::{
    enforce_route_requirements, inject_identity_headers, sanitize_identity_headers,
    AuthorizationRequest,
};
use crate::middleware::ip_filter::IpFilter;
use crate::middleware::rate_limit::{build_key, route_limit, RateLimitContext, RateLimitDecision};
use crate::middleware::request_id::{resolve_request_id, set_request_id};
use crate::middleware::security::{apply_security_headers, validate_host};
use crate::resilience::timeout::EffectiveTimeouts;
use crate::utils::http::{headers_size, host_without_port, is_websocket_upgrade, wants_upgrade};

#[derive(Default)]
struct RequestMeta {
    route_id: String,
    path: String,
    service: Option<String>,
    upstream: Option<String>,
    request_id: String,
    request_id_header: String,
    trace_id: Option<String>,
    error: Option<String>,
    cache_hit: bool,
    websocket: bool,
}

impl RequestMeta {
    fn new() -> Self {
        Self {
            route_id: "-".to_string(),
            ..Default::default()
        }
    }
}

/// Axum 兜底 Handler：所有未命中内置端点的请求都进入网关管线。
#[axum::debug_handler]
pub async fn handle_request(State(state): State<Arc<GatewayState>>, req: Request) -> Response {
    let started = Instant::now();
    let method = req.method().clone();
    let mut meta = RequestMeta::new();
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);

    state.metrics.inc_inflight(1);
    let result = process(&state, peer, req, &mut meta).await;
    state.metrics.inc_inflight(-1);

    let mut response = match result {
        Ok(response) => response,
        Err(err) => {
            meta.error = Some(err.to_string());
            err.into_response()
        }
    };

    let elapsed = started.elapsed();
    let status = response.status().as_u16();
    state.metrics.record_request(
        &meta.route_id,
        method.as_str(),
        status,
        elapsed.as_secs_f64(),
    );

    let snapshot = state.route_table.snapshot();
    let security = &snapshot.config.gateway.security;
    if security.add_security_headers {
        apply_security_headers(response.headers_mut(), &security.extra_headers);
    }
    if !meta.request_id.is_empty() {
        set_request_id(
            response.headers_mut(),
            &meta.request_id_header,
            &meta.request_id,
        );
    }
    if let Some(trace_id) = &meta.trace_id {
        if !trace_id.is_empty() {
            if let Ok(value) = HeaderValue::from_str(trace_id) {
                response.headers_mut().insert("x-trace-id", value);
            }
        }
    }

    if state.access_log {
        tracing::info!(
            request_id = %meta.request_id,
            trace_id = meta.trace_id.as_deref().unwrap_or(""),
            method = %method,
            path = %meta.path,
            route_id = %meta.route_id,
            upstream = meta.upstream.as_deref().unwrap_or(""),
            service = meta.service.as_deref().unwrap_or(""),
            status,
            duration_ms = elapsed.as_millis() as u64,
            cache_hit = meta.cache_hit,
            websocket = meta.websocket,
            error = meta.error.as_deref().unwrap_or(""),
            "request completed"
        );
    }

    response
}

async fn process(
    state: &Arc<GatewayState>,
    peer: Option<SocketAddr>,
    mut req: Request,
    meta: &mut RequestMeta,
) -> Result<Response> {
    let method = req.method().clone();
    let original_path = req.uri().path().to_string();
    let original_query = req.uri().query().map(|q| q.to_string());
    meta.path = original_path.clone();

    let snapshot = state.route_table.snapshot();
    let config = snapshot.config.clone();

    if headers_size(req.headers()) > config.gateway.server.limits.max_header_size {
        return Err(GatewayError::HeadersTooLarge);
    }
    validate_host(req.headers(), &config.gateway.security.host_validation)?;

    let security = &config.gateway.security;
    let request_id = resolve_request_id(
        req.headers(),
        &security.request_id_header,
        security.trust_client_request_id,
    );
    meta.request_id = request_id.clone();
    meta.request_id_header = security.request_id_header.clone();
    set_request_id(req.headers_mut(), &security.request_id_header, &request_id);

    // OpenTelemetry：提取父上下文并创建 Server Span。
    let parent = state.tracing.extract(req.headers());
    let mut span = state.tracing.start_server_span(
        &format!("{} {}", method, original_path),
        &parent,
        vec![
            opentelemetry::KeyValue::new("http.method", method.as_str().to_string()),
            opentelemetry::KeyValue::new("http.path", original_path.clone()),
        ],
    );
    meta.trace_id = crate::observability::tracing::TracingState::trace_id(&span);
    if let Some(span) = span.as_ref() {
        state.tracing.inject(span, req.headers_mut());
    }

    let peer_ip = peer.map(|addr| addr.ip());
    let client_ip = state.ip_resolver.resolve(peer_ip, req.headers());

    if !state.global_ip_filter.load().is_empty() {
        match client_ip {
            Some(ip) if state.global_ip_filter.load().allows(ip) => {}
            _ => return Err(GatewayError::Forbidden("client IP is not allowed".into())),
        }
    }

    let host = req
        .headers()
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|value| host_without_port(value).to_string())
        .or_else(|| req.uri().authority().map(|a| a.host().to_string()));

    let predicate_req = PredicateRequest {
        method: &method,
        path: &original_path,
        host: host.as_deref(),
        headers: req.headers(),
        query: original_query.as_deref(),
        client_ip,
        now: Utc::now(),
    };

    let matched = snapshot.match_route(&predicate_req);

    // CORS 预检：没有匹配路由时尝试用「忽略 Method」的路由或全局 CORS 应答。
    if matched.is_none() && method == Method::OPTIONS {
        let cors_config = snapshot
            .match_route_ignoring_method(&predicate_req)
            .and_then(|route| route.config.cors.clone())
            .or_else(|| config.gateway.cors.clone());
        if let Some(cors_config) = cors_config {
            if let Some(policy) = state.cors_cache.get(&cors_config) {
                if let Some(response) = policy.preflight(req.headers(), &method) {
                    return Ok(response);
                }
            }
        }
    }

    let route = match matched {
        Some(route) => route,
        None => return Err(GatewayError::RouteNotFound),
    };
    meta.route_id = route.id().to_string();

    if let Some(ip_config) = &route.config.ip_filter {
        let filter = IpFilter::new(ip_config)
            .map_err(|e| GatewayError::Config(format!("invalid route ip filter: {e}")))?;
        match client_ip {
            Some(ip) if filter.allows(ip) => {}
            _ => {
                return Err(GatewayError::Forbidden(
                    "client IP is not allowed by route policy".into(),
                ))
            }
        }
    }

    // 认证
    let auth = state.auth.load_full();
    let auth_config = route.config.authentication.clone().unwrap_or_default();
    let identity = auth
        .authenticate(req.headers(), auth_config.mode, auth_config.allow_api_key)
        .await?;
    enforce_route_requirements(identity.as_ref(), &auth_config.scopes, &auth_config.roles)?;

    // 先删除客户端伪造的身份头，再注入可信身份头。
    let identity_headers: IdentityHeadersConfig = auth.identity_headers().clone();
    sanitize_identity_headers(req.headers_mut(), &identity_headers);
    if let Some(identity) = identity.as_ref() {
        inject_identity_headers(req.headers_mut(), &identity_headers, identity);
    }

    let authz = state.authz.load_full();
    if let Some(policy) = &route.config.authorization {
        let authz_req = AuthorizationRequest {
            identity: identity.as_ref(),
            method: &method,
            path: &original_path,
            headers: req.headers(),
            route_id: route.id(),
            route_metadata: &route.config.metadata,
        };
        authz.authorize(&authz_req, policy).await?;
    }

    // 过滤器（请求阶段）
    let mut upstream_path;
    let upstream_query;
    let preserve_host;
    {
        let mut filter_req = FilterRequest {
            method: &method,
            path: original_path.clone(),
            query: original_query.clone(),
            headers: req.headers_mut(),
            identity: identity.as_ref(),
            metadata: &route.config.metadata,
            preserve_host: false,
        };
        for filter in &state.global_filters {
            filter.apply_request(&mut filter_req).await?;
        }
        for filter in &snapshot.global_filters {
            filter.apply_request(&mut filter_req).await?;
        }
        for filter in &route.filters {
            filter.apply_request(&mut filter_req).await?;
        }
        upstream_path = filter_req.path.clone();
        upstream_query = filter_req.query.clone();
        preserve_host = filter_req.preserve_host;
    }
    if !upstream_path.starts_with('/') {
        upstream_path.insert(0, '/');
    }

    // 限流：全局限流在前，路由限流在后。
    let rate_ctx = RateLimitContext {
        route_id: route.id(),
        client_ip,
        identity: identity.as_ref(),
        headers: req.headers(),
        query: upstream_query.as_deref(),
    };
    let global_limit = &config.gateway.rate_limit;
    if global_limit.enabled {
        let key = if matches!(
            global_limit.key_type,
            crate::config::model::RateLimitKeyType::Global
        ) {
            Some(format!("{}:global", route.id()))
        } else {
            build_key(global_limit.key_type, None, &rate_ctx)
        };
        if let Some(key) = key {
            let decision = state
                .rate_limiter
                .check(
                    &key,
                    &global_limit.quota,
                    global_limit.mode,
                    global_limit.fail_open,
                )
                .await;
            if let Some(response) = enforce_rate_limit(&decision, state, route.id()) {
                return Ok(response);
            }
        }
    }
    if let Some(route_limit_config) = &route.config.rate_limit {
        if let Some(limit) = route_limit(route_limit_config, global_limit) {
            if let Some(key) = build_key(limit.key_type, limit.template, &rate_ctx) {
                let decision = state
                    .rate_limiter
                    .check(&key, limit.quota, limit.mode, limit.fail_open)
                    .await;
                if let Some(response) = enforce_rate_limit(&decision, state, route.id()) {
                    return Ok(response);
                }
            }
        }
    }

    // 熔断
    let breaker_config = route.config.circuit_breaker.clone().or_else(|| {
        if config.gateway.circuit_breaker.enabled {
            Some(config.gateway.circuit_breaker.clone())
        } else {
            None
        }
    });
    let breaker = breaker_config.as_ref().map(|cfg| {
        state
            .breakers
            .get_or_create(&format!("route:{}", route.id()), cfg)
    });
    if let Some(breaker) = &breaker {
        state
            .metrics
            .set_circuit_breaker_state(route.id(), breaker.state() as i64);
        if breaker.allow().is_err() {
            if let Some(fallback) = breaker.fallback() {
                return Ok(fallback_response(fallback));
            }
            return Err(GatewayError::CircuitOpen(route.id().to_string()));
        }
    }

    // 响应缓存查询
    let cache_policy = route
        .config
        .cache
        .as_ref()
        .filter(|c| c.enabled)
        .map(CachePolicy::from_route)
        .or_else(|| {
            if config.gateway.cache.enabled {
                Some(CachePolicy::from_global(&config.gateway.cache))
            } else {
                None
            }
        });
    let cache_key_value = cache_policy.as_ref().and_then(|policy| {
        if request_cacheable(policy, &method, req.headers(), identity.as_ref()) {
            Some(cache_key(
                policy,
                route.id(),
                &method,
                &upstream_path,
                upstream_query.as_deref(),
                req.headers(),
                identity.as_ref(),
            ))
        } else {
            None
        }
    });

    if let (Some(policy), Some(key)) = (&cache_policy, &cache_key_value) {
        if let Some(entry) = state.cache.get(route.id(), policy, key).await {
            state.metrics.record_cache(true);
            meta.cache_hit = true;
            let mut response = cached_response(&entry);
            apply_response_filters(
                &route,
                snapshot.global_filters.as_slice(),
                &state.global_filters,
                &mut response,
            )?;
            finalize_route_response(state, &route, &config, req.headers(), &mut response);
            if let Some(mut span) = span.take() {
                span.end();
            }
            return Ok(response);
        }
        state.metrics.record_cache(false);
    }

    // 超时
    let timeouts = EffectiveTimeouts::resolve(
        &config.gateway.server.timeouts,
        route.config.timeout.as_ref(),
    );

    // 请求体大小检查与重试缓冲
    let max_body = config.gateway.server.limits.max_body_size;
    if max_body > 0 {
        if let Some(length) = req
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
        {
            if length > max_body {
                return Err(GatewayError::PayloadTooLarge);
            }
        }
    }

    let origin = req.headers().get(ORIGIN).cloned();
    let request_headers = req.headers().clone();
    let grpc = request_headers
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.starts_with("application/grpc"))
        .unwrap_or(false);
    let websocket = route
        .config
        .upstream
        .as_ref()
        .map(|u| u.websocket)
        .unwrap_or(true)
        && (is_websocket_upgrade(&request_headers) || wants_upgrade(&request_headers));

    let retry = route.config.retry.clone();
    let (parts, body) = req.into_parts();
    let mut extensions = parts.extensions;
    let upgrade = extensions.remove::<hyper::upgrade::OnUpgrade>();
    let mut request_headers = parts.headers;
    apply_request_id_header(
        &mut request_headers,
        &meta.request_id,
        &meta.request_id_header,
    );

    let body = prepare_body(body, retry.as_ref(), max_body).await?;

    let route_upstream = route.config.upstream.clone().unwrap_or_default();
    let options = ProxyOptions {
        strategy: route
            .config
            .load_balancer
            .or(Some(config.gateway.load_balancer.strategy)),
        protocol: route_upstream.protocol,
        tls: route_upstream.tls.clone(),
        timeouts,
        retry: retry.filter(|r| r.enabled),
        websocket: route_upstream.websocket,
    };

    let mut proxy_request = ProxyRequest {
        method: method.clone(),
        headers: request_headers,
        path: upstream_path.clone(),
        query: upstream_query.clone(),
        body,
        client_ip,
        peer_ip,
        downstream_scheme: if config.gateway.server.tls.enabled {
            "https".to_string()
        } else {
            "http".to_string()
        },
        original_host: host.clone(),
        preserve_host,
        upgrade,
        websocket,
        grpc,
    };

    let proxy_started = Instant::now();
    let proxy_result = state
        .proxy
        .execute(&mut proxy_request, &route.config.uri, &options)
        .await;

    let mut response = match proxy_result {
        Ok(outcome) => {
            meta.service = outcome.service.clone();
            meta.upstream = Some(outcome.upstream.clone());
            meta.websocket = websocket && outcome.status == StatusCode::SWITCHING_PROTOCOLS;
            let response = outcome.response;
            if let Some(breaker) = &breaker {
                if response.status().is_server_error() {
                    breaker.on_failure(proxy_started.elapsed());
                } else {
                    breaker.on_success(proxy_started.elapsed());
                }
            }
            response
        }
        Err(err) => {
            if let Some(breaker) = &breaker {
                breaker.on_failure(proxy_started.elapsed());
            }
            return Err(err);
        }
    };

    state.metrics.set_circuit_breaker_state(
        route.id(),
        breaker.as_ref().map(|b| b.state() as i64).unwrap_or(0),
    );

    // 缓存写入（在响应过滤器之前保存原始响应）。
    if let (Some(policy), Some(key)) = (&cache_policy, &cache_key_value) {
        response = maybe_store(state, route.id(), policy, key.clone(), response).await;
    }

    apply_response_filters(
        &route,
        snapshot.global_filters.as_slice(),
        &state.global_filters,
        &mut response,
    )?;

    if let Some(origin) = origin {
        let policy_config = route
            .config
            .cors
            .clone()
            .or_else(|| config.gateway.cors.clone());
        if let Some(policy_config) = policy_config {
            if let Some(policy) = state.cors_cache.get(&policy_config) {
                let mut origin_headers = HeaderMap::new();
                origin_headers.insert(ORIGIN, origin);
                policy.apply(&origin_headers, response.headers_mut());
            }
        }
    }

    if let Some(mut span) = span.take() {
        span.end();
    }
    Ok(response)
}

fn apply_request_id_header(headers: &mut HeaderMap, request_id: &str, header: &str) {
    if let (Ok(name), Ok(value)) = (
        http::HeaderName::from_bytes(header.as_bytes()),
        HeaderValue::from_str(request_id),
    ) {
        headers.insert(name, value);
    }
}

async fn prepare_body(
    body: Body,
    retry: Option<&crate::config::model::RetryConfig>,
    max_body: u64,
) -> Result<ProxyBody> {
    if let Some(config) = retry {
        if config.enabled
            && config.max_attempts > 1
            && body
                .size_hint()
                .exact()
                .map(|len| len as usize <= config.max_body_bytes)
                .unwrap_or(false)
        {
            let collected = body.collect().await.map_err(|e| {
                GatewayError::BadRequest(format!("failed to read request body: {e}"))
            })?;
            return Ok(ProxyBody::Bytes(collected.to_bytes()));
        }
    }
    if max_body > 0 {
        let limited = Limited::new(body, max_body as usize);
        Ok(ProxyBody::Stream(Body::new(limited)))
    } else {
        Ok(ProxyBody::Stream(body))
    }
}

fn enforce_rate_limit(
    decision: &RateLimitDecision,
    state: &Arc<GatewayState>,
    route_id: &str,
) -> Option<Response> {
    if decision.allowed {
        return None;
    }
    state.metrics.inc_rate_limited(route_id);
    if let Some(error) = &decision.error {
        tracing::error!(route = route_id, error = %error, "rate limiter failed (fail-closed)");
        let mut response =
            GatewayError::ServiceUnavailable("rate limiter is temporarily unavailable".to_string())
                .into_response();
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("1"));
        return Some(response);
    }
    let retry_after = decision.retry_after_secs.unwrap_or(1);
    let mut response = GatewayError::RateLimited {
        retry_after_secs: Some(retry_after),
    }
    .into_response();
    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&decision.limit.to_string()) {
        headers.insert("x-ratelimit-limit", value);
    }
    if let Ok(value) = HeaderValue::from_str(&decision.remaining.to_string()) {
        headers.insert("x-ratelimit-remaining", value);
    }
    if let Ok(value) = HeaderValue::from_str(&retry_after.to_string()) {
        headers.insert("x-ratelimit-reset", value);
    }
    Some(response)
}

fn fallback_response(config: &crate::config::model::FallbackConfig) -> Response {
    let status = StatusCode::from_u16(config.status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    let mut response = Response::new(Body::from(config.body.clone()));
    *response.status_mut() = status;
    if let Ok(value) = HeaderValue::from_str(&config.content_type) {
        response.headers_mut().insert(CONTENT_TYPE, value);
    }
    response
}

async fn maybe_store(
    state: &Arc<GatewayState>,
    route_id: &str,
    policy: &CachePolicy,
    key: String,
    response: Response,
) -> Response {
    let (parts, body) = response.into_parts();
    let length = parts
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        .or_else(|| body.size_hint().exact().map(|v| v as usize));

    let cacheable = length
        .map(|len| len <= policy.max_body_size)
        .unwrap_or(false)
        && response_cacheable(policy, parts.status, &parts.headers, length.unwrap_or(0));
    if !cacheable {
        return Response::from_parts(parts, body);
    }

    match body.collect().await {
        Ok(collected) => {
            let bytes = collected.to_bytes();
            state
                .cache
                .put(
                    route_id,
                    policy,
                    key,
                    parts.status,
                    &parts.headers,
                    bytes.clone(),
                )
                .await;
            state
                .metrics
                .set_cache_entries(state.cache.entry_count() as i64);
            let mut response = Response::from_parts(parts, Body::from(bytes));
            response.headers_mut().insert(
                http::header::HeaderName::from_static("x-cache"),
                HeaderValue::from_static("MISS"),
            );
            response
        }
        Err(err) => {
            tracing::warn!(error = %err, "failed to buffer response for caching");
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::BAD_GATEWAY;
            response
        }
    }
}

fn apply_response_filters(
    route: &crate::core::route::CompiledRoute,
    snapshot_filters: &[Arc<dyn crate::core::filter::GatewayFilter>],
    state_filters: &[Arc<dyn crate::core::filter::GatewayFilter>],
    response: &mut Response,
) -> Result<()> {
    let mut status = response.status();
    {
        let headers = response.headers_mut();
        let mut ctx = FilterResponse {
            status,
            headers,
            route_id: route.id(),
        };
        for filter in state_filters {
            filter.apply_response(&mut ctx)?;
        }
        for filter in snapshot_filters {
            filter.apply_response(&mut ctx)?;
        }
        for filter in &route.filters {
            filter.apply_response(&mut ctx)?;
        }
        status = ctx.status;
    }
    *response.status_mut() = status;
    Ok(())
}

fn finalize_route_response(
    state: &Arc<GatewayState>,
    route: &crate::core::route::CompiledRoute,
    config: &crate::config::model::GatewayConfig,
    request_headers: &HeaderMap,
    response: &mut Response,
) {
    if let Some(origin) = request_headers.get(ORIGIN) {
        let policy_config = route
            .config
            .cors
            .clone()
            .or_else(|| config.gateway.cors.clone());
        if let Some(policy_config) = policy_config {
            if let Some(policy) = state.cors_cache.get(&policy_config) {
                let mut origin_headers = HeaderMap::new();
                origin_headers.insert(ORIGIN, origin.clone());
                policy.apply(&origin_headers, response.headers_mut());
            }
        }
    }
}
