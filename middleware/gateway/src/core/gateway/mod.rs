//! 网关运行时：组装全部组件、构建 Axum Router、执行请求管线。

pub mod pipeline;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use http::StatusCode;

use crate::cache::ResponseCache;
use crate::config::model::{ExternalAuthzConfig, GatewayConfig, IdentityHeadersConfig};
use crate::core::filter::{FilterRegistry, GatewayFilter, GlobalFilter};
use crate::core::proxy::ProxyService;
use crate::core::route::table::RouteTable;
use crate::core::service_discovery::{ConsulDiscovery, DiscoveryProviders, StaticDiscovery};
use crate::core::upstream::UpstreamRegistry;
use crate::error::Result;
use crate::middleware::authentication::AuthService;
use crate::middleware::authorization::AuthorizationService;
use crate::middleware::ip_filter::IpFilter;
use crate::middleware::rate_limit::RateLimiter;
use crate::middleware::security::UpstreamGuard;
use crate::observability::metrics::Metrics;
use crate::observability::tracing::TracingState;
use crate::resilience::circuit_breaker::CircuitBreakerRegistry;
use crate::resilience::health_check::HealthRegistry;
use crate::utils::ip::ClientIpResolver;

/// 网关共享状态。
pub struct GatewayState {
    pub route_table: Arc<RouteTable>,
    pub metrics: Arc<Metrics>,
    pub health: Arc<HealthRegistry>,
    pub auth: ArcSwap<AuthService>,
    pub authz: ArcSwap<AuthorizationService>,
    pub rate_limiter: Arc<RateLimiter>,
    pub proxy: Arc<ProxyService>,
    pub cache: Arc<ResponseCache>,
    pub breakers: Arc<CircuitBreakerRegistry>,
    pub ip_resolver: ClientIpResolver,
    pub global_ip_filter: ArcSwap<IpFilter>,
    pub tracing: Arc<TracingState>,
    pub global_filters: Vec<Arc<dyn GatewayFilter>>,
    pub access_log: bool,
    pub redact_headers: Vec<String>,
    pub metrics_path: String,
    pub metrics_enabled: bool,
    pub cors_cache: CorsPolicyCache,
    pub started_at: Instant,
}

impl GatewayState {
    /// 配置热更新后重建认证、授权与全局 IP 过滤等派生组件。
    pub fn reload_derived(&self, config: &GatewayConfig) -> std::result::Result<(), String> {
        let auth = AuthService::new(&config.gateway.authentication)
            .map_err(|e| format!("failed to rebuild authentication: {e}"))?;
        let mut authz = AuthorizationService::new();
        for route in &config.routes {
            if let Some(authz_config) = &route.authorization {
                if authz_config.provider.eq_ignore_ascii_case("external") {
                    if let Some(external) = &authz_config.external {
                        authz
                            .register_external(external.clone())
                            .map_err(|e| format!("failed to rebuild authorization: {e}"))?;
                    }
                }
            }
        }
        let filter = IpFilter::new(&config.gateway.ip_filter)
            .map_err(|e| format!("failed to rebuild ip filter: {e}"))?;
        self.auth.store(auth);
        self.authz.store(Arc::new(authz));
        self.global_ip_filter.store(Arc::new(filter));
        Ok(())
    }

    pub fn identity_headers(&self) -> IdentityHeadersConfig {
        self.auth.load().identity_headers().clone()
    }
}

/// 构建参数。
pub struct GatewayOptions {
    pub registry: FilterRegistry,
    pub metrics: Arc<Metrics>,
    pub health: Arc<HealthRegistry>,
    pub tracing: Arc<TracingState>,
    pub global_filters: Vec<Arc<dyn GlobalFilter>>,
    pub hash: String,
    pub version: u64,
}

impl GatewayOptions {
    pub fn new(
        metrics: Arc<Metrics>,
        health: Arc<HealthRegistry>,
        tracing: Arc<TracingState>,
        hash: String,
    ) -> Self {
        Self {
            registry: FilterRegistry::builtin(),
            metrics,
            health,
            tracing,
            global_filters: Vec::new(),
            hash,
            version: 0,
        }
    }
}

/// 网关实例。
pub struct Gateway {
    pub state: Arc<GatewayState>,
    pub route_table: Arc<RouteTable>,
    pub upstreams: Arc<UpstreamRegistry>,
}

impl Gateway {
    pub async fn build(
        config: GatewayConfig,
        options: GatewayOptions,
    ) -> std::result::Result<Self, String> {
        let metrics = options.metrics.clone();
        let route_table = Arc::new(
            RouteTable::new(
                config.clone(),
                options.registry,
                options.hash.clone(),
                options.version,
            )
            .map_err(|e| format!("failed to compile routes: {e}"))?,
        );

        let static_services = config
            .gateway
            .services
            .iter()
            .map(|(name, service)| (name.clone(), service.instances.clone()))
            .collect::<HashMap<_, _>>();
        let static_discovery = Arc::new(
            StaticDiscovery::new(static_services)
                .map_err(|e| format!("invalid static service configuration: {e}"))?,
        );
        let consul = match &config.gateway.service_discovery.consul {
            Some(cfg) => Some(Arc::new(
                ConsulDiscovery::new(cfg.clone())
                    .map_err(|e| format!("invalid consul configuration: {e}"))?,
            )),
            None => None,
        };
        let providers = Arc::new(DiscoveryProviders {
            static_discovery,
            consul,
        });

        let upstreams = UpstreamRegistry::new(&config, providers, metrics.clone()).await?;
        upstreams.start();

        let auth = AuthService::new(&config.gateway.authentication)
            .map_err(|e| format!("failed to initialize authentication: {e}"))?;
        let mut authz = AuthorizationService::new();
        for external in external_authorizers(&config) {
            authz
                .register_external(external)
                .map_err(|e| format!("failed to initialize authorization: {e}"))?;
        }
        let global_ip_filter = IpFilter::new(&config.gateway.ip_filter)
            .map_err(|e| format!("invalid global ip filter: {e}"))?;

        let proxy = Arc::new(ProxyService::new(
            upstreams.clone(),
            config.gateway.upstream_tls.clone(),
            UpstreamGuard::new(config.gateway.security.block_private_upstreams),
            config.gateway.server.timeouts.idle,
            64,
        ));

        let rate_limiter = if config.gateway.redis.url.trim().is_empty() {
            RateLimiter::new(&config.gateway.rate_limit)
        } else {
            RateLimiter::with_redis(&config.gateway.rate_limit, &config.gateway.redis).await
        };

        let ip_resolver = ClientIpResolver::new(&config.gateway.server.trusted_proxies)
            .map_err(|e| format!("invalid trusted proxies: {e}"))?;

        let global_filters: Vec<Arc<dyn GatewayFilter>> = options
            .global_filters
            .iter()
            .map(|f| Arc::new(GlobalFilterAdapter(f.clone())) as Arc<dyn GatewayFilter>)
            .collect();

        let state = Arc::new(GatewayState {
            route_table: route_table.clone(),
            metrics: metrics.clone(),
            health: options.health,
            auth: ArcSwap::from(auth),
            authz: ArcSwap::from_pointee(authz),
            rate_limiter,
            proxy,
            cache: Arc::new(ResponseCache::new()),
            breakers: Arc::new(CircuitBreakerRegistry::new(metrics.clone())),
            ip_resolver,
            global_ip_filter: ArcSwap::from_pointee(global_ip_filter),
            tracing: options.tracing,
            global_filters,
            access_log: config.gateway.logging.access_log,
            redact_headers: config.gateway.logging.redact_headers.clone(),
            metrics_path: config.gateway.metrics.path.clone(),
            metrics_enabled: config.gateway.metrics.enabled,
            cors_cache: CorsPolicyCache::new(),
            started_at: Instant::now(),
        });

        Ok(Self {
            state,
            route_table,
            upstreams,
        })
    }

    /// 业务路由器（含健康检查与指标端点）。
    pub fn router(&self) -> Router {
        build_router(self.state.clone())
    }
}

/// 构造业务 Router。
pub fn build_router(state: Arc<GatewayState>) -> Router {
    let metrics_path = state.metrics_path.clone();
    let mut router = Router::new()
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready));
    if state.metrics_enabled && !metrics_path.is_empty() {
        router = router.route(&metrics_path, get(metrics_endpoint));
    }
    router.fallback(pipeline::handle_request).with_state(state)
}

async fn health_live(
    State(state): State<Arc<GatewayState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    (StatusCode::OK, Json(state.health.liveness()))
}

async fn health_ready(
    State(state): State<Arc<GatewayState>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let readiness = state.health.readiness().await;
    let status = if readiness.ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(
            serde_json::to_value(readiness).unwrap_or_else(|_| serde_json::json!({"ready": false})),
        ),
    )
}

async fn metrics_endpoint(
    State(state): State<Arc<GatewayState>>,
) -> (StatusCode, [(String, String); 1], String) {
    let entries = state.cache.entry_count();
    state.metrics.set_cache_entries(entries as i64);
    (
        StatusCode::OK,
        [(
            "content-type".to_string(),
            "text/plain; version=0.0.4; charset=utf-8".to_string(),
        )],
        state.metrics.render(),
    )
}

fn external_authorizers(config: &GatewayConfig) -> Vec<ExternalAuthzConfig> {
    config
        .routes
        .iter()
        .filter_map(|route| route.authorization.as_ref())
        .filter(|authz| authz.provider.eq_ignore_ascii_case("external"))
        .filter_map(|authz| authz.external.clone())
        .collect()
}

/// 把程序化注册的 GlobalFilter 适配为 GatewayFilter。
pub struct GlobalFilterAdapter(Arc<dyn GlobalFilter>);

#[async_trait]
impl GatewayFilter for GlobalFilterAdapter {
    fn name(&self) -> &'static str {
        self.0.name()
    }

    fn order(&self) -> i32 {
        self.0.order()
    }

    async fn apply_request(&self, ctx: &mut crate::core::filter::FilterRequest<'_>) -> Result<()> {
        self.0.apply_request(ctx).await
    }

    fn apply_response(&self, ctx: &mut crate::core::filter::FilterResponse<'_>) -> Result<()> {
        self.0.apply_response(ctx)
    }
}

/// 便于测试与扩展的 CORS 策略缓存。
pub struct CorsPolicyCache {
    entries: dashmap::DashMap<String, Arc<crate::middleware::cors::CorsPolicy>>,
}

impl CorsPolicyCache {
    pub fn new() -> Self {
        Self {
            entries: dashmap::DashMap::new(),
        }
    }

    pub fn get(
        &self,
        config: &crate::config::model::CorsConfig,
    ) -> Option<Arc<crate::middleware::cors::CorsPolicy>> {
        let key = serde_json::to_string(config).ok()?;
        if let Some(policy) = self.entries.get(&key) {
            return Some(policy.clone());
        }
        let policy = Arc::new(crate::middleware::cors::CorsPolicy::new(config).ok()?);
        self.entries.insert(key, policy.clone());
        Some(policy)
    }
}

impl Default for CorsPolicyCache {
    fn default() -> Self {
        Self::new()
    }
}

/// 配置中的默认超时（用于测试与文档示例）。
pub fn default_request_timeout(config: &GatewayConfig) -> Duration {
    config.gateway.server.timeouts.request
}
