//! 管理 API。
//!
//! 独立端口、独立认证、统一 JSON 响应；路由变更采用原子快照替换，
//! 并按配置持久化到 `routes.yaml`，同时通过 Redis Pub/Sub 广播给其他实例。

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::config::loader;
use crate::config::model::{GatewayConfig, RouteConfig};
use crate::config::validate::validate;
use crate::core::filter::FilterRegistry;
use crate::core::gateway::GatewayState;
use crate::core::route::table::RouteTable;
use crate::core::upstream::UpstreamRegistry;
use crate::error::GatewayError;
use crate::middleware::authentication::AuthService;

/// 管理 API 共享状态。
pub struct AdminState {
    pub gateway: Arc<GatewayState>,
    pub route_table: Arc<RouteTable>,
    pub upstreams: Arc<UpstreamRegistry>,
    pub root_dir: PathBuf,
    pub profile: Option<String>,
    pub sync: Option<Arc<ConfigSync>>,
    pub node_id: String,
    pub started_at: Instant,
    pub admin_jwt: tokio::sync::Mutex<Option<(String, Arc<AuthService>)>>,
}

impl AdminState {
    pub fn new(
        gateway: Arc<GatewayState>,
        route_table: Arc<RouteTable>,
        upstreams: Arc<UpstreamRegistry>,
        root_dir: PathBuf,
        profile: Option<String>,
        sync: Option<Arc<ConfigSync>>,
        node_id: String,
    ) -> Arc<Self> {
        Arc::new(Self {
            gateway,
            route_table,
            upstreams,
            root_dir,
            profile,
            sync,
            node_id,
            started_at: Instant::now(),
            admin_jwt: tokio::sync::Mutex::new(None),
        })
    }

    fn persistence_path(&self, config: &GatewayConfig) -> PathBuf {
        config
            .gateway
            .admin
            .persistence
            .path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| self.root_dir.join("routes.yaml"))
    }
}

/// 构造管理 API Router。
pub fn router(state: Arc<AdminState>) -> Router {
    Router::new()
        .route("/admin/v1/routes", get(list_routes).post(create_route))
        .route(
            "/admin/v1/routes/{id}",
            get(get_route).put(update_route).delete(delete_route),
        )
        .route("/admin/v1/routes/{id}/enable", post(enable_route))
        .route("/admin/v1/routes/{id}/disable", post(disable_route))
        .route("/admin/v1/config/reload", post(reload_config))
        .route("/admin/v1/config/status", get(config_status))
        .route("/admin/v1/services", get(list_services))
        .route("/admin/v1/upstreams", get(list_upstreams))
        .route("/admin/v1/circuit-breakers", get(list_breakers))
        .route("/admin/v1/metrics/summary", get(metrics_summary))
        .route("/health/live", get(admin_health_live))
        .route("/health/ready", get(admin_health_ready))
        .route("/metrics", get(admin_metrics))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(state, admin_guard))
}

// ---------------------------------------------------------------------------
// 统一响应
// ---------------------------------------------------------------------------

fn ok(data: serde_json::Value) -> Response {
    Json(json!({"success": true, "data": data})).into_response()
}

fn fail(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({
            "success": false,
            "error": {"code": code, "message": message.into()}
        })),
    )
        .into_response()
}

fn gateway_fail(err: GatewayError) -> Response {
    fail(err.status_code(), err.code(), err.to_string())
}

// ---------------------------------------------------------------------------
// 认证守卫
// ---------------------------------------------------------------------------

async fn admin_guard(State(state): State<Arc<AdminState>>, req: Request, next: Next) -> Response {
    let config = state.route_table.snapshot().config.clone();
    let admin = &config.gateway.admin;

    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0);

    if !admin.allowed_ips.is_empty() {
        let allowed = peer
            .and_then(|addr| {
                let ip = addr.ip();
                admin
                    .allowed_ips
                    .iter()
                    .filter_map(|value| value.parse::<IpNet>().ok())
                    .any(|net| net.contains(&ip))
                    .then_some(())
            })
            .is_some();
        if !allowed {
            return fail(
                StatusCode::FORBIDDEN,
                "ADMIN_IP_FORBIDDEN",
                "management API is not accessible from this IP",
            );
        }
    }

    match admin.auth.mode.as_str() {
        "none" => {}
        "jwt" => {
            let jwt_config = match &admin.auth.jwt {
                Some(config) => config,
                None => {
                    return fail(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ADMIN_AUTH_NOT_CONFIGURED",
                        "admin JWT is not configured",
                    )
                }
            };
            let service = match admin_jwt_service(&state, jwt_config).await {
                Ok(service) => service,
                Err(response) => return response,
            };
            match service
                .authenticate(
                    req.headers(),
                    crate::config::model::AuthMode::Authenticated,
                    false,
                )
                .await
            {
                Ok(Some(_)) => {}
                Ok(None) => {
                    return fail(
                        StatusCode::UNAUTHORIZED,
                        "UNAUTHORIZED",
                        "admin JWT is required",
                    )
                }
                Err(err) => return gateway_fail(err),
            }
        }
        _ => {
            let header = &admin.auth.header;
            let provided = req
                .headers()
                .get(header.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            if provided.is_empty()
                || !admin
                    .auth
                    .api_keys
                    .iter()
                    .any(|expected| constant_time_eq(expected, provided))
            {
                return fail(
                    StatusCode::UNAUTHORIZED,
                    "UNAUTHORIZED",
                    "invalid or missing admin API key",
                );
            }
        }
    }

    next.run(req).await
}

#[allow(clippy::result_large_err)]
async fn admin_jwt_service(
    state: &Arc<AdminState>,
    jwt: &crate::config::model::JwtConfig,
) -> std::result::Result<Arc<AuthService>, Response> {
    let fingerprint = serde_json::to_string(jwt).unwrap_or_default();
    let mut guard = state.admin_jwt.lock().await;
    if let Some((cached, service)) = guard.as_ref() {
        if cached == &fingerprint {
            return Ok(service.clone());
        }
    }
    let auth_config = crate::config::model::AuthConfig {
        jwt: Some(jwt.clone()),
        ..Default::default()
    };
    match AuthService::new(&auth_config) {
        Ok(service) => {
            *guard = Some((fingerprint, service.clone()));
            Ok(service)
        }
        Err(err) => Err(fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ADMIN_AUTH_ERROR",
            err.to_string(),
        )),
    }
}

fn constant_time_eq(expected: &str, provided: &str) -> bool {
    let a = Sha256::digest(expected.as_bytes());
    let b = Sha256::digest(provided.as_bytes());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// 路由管理
// ---------------------------------------------------------------------------

async fn list_routes(State(state): State<Arc<AdminState>>) -> Response {
    let snapshot = state.route_table.snapshot();
    ok(json!({
        "version": snapshot.version,
        "total": snapshot.config.routes.len(),
        "routes": snapshot.config.routes,
    }))
}

async fn get_route(State(state): State<Arc<AdminState>>, Path(id): Path<String>) -> Response {
    let snapshot = state.route_table.snapshot();
    match snapshot.config.routes.iter().find(|r| r.id == id) {
        Some(route) => ok(json!(route)),
        None => fail(
            StatusCode::NOT_FOUND,
            "ROUTE_NOT_FOUND",
            format!("route `{id}` not found"),
        ),
    }
}

async fn create_route(
    State(state): State<Arc<AdminState>>,
    payload: std::result::Result<Json<RouteConfig>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(route) = match payload {
        Ok(payload) => payload,
        Err(rejection) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "INVALID_ROUTE",
                rejection.body_text(),
            )
        }
    };
    let snapshot = state.route_table.snapshot();
    let mut config = snapshot.config.as_ref().clone();
    if config.routes.iter().any(|r| r.id == route.id) {
        return fail(
            StatusCode::CONFLICT,
            "ROUTE_EXISTS",
            format!("route `{}` already exists", route.id),
        );
    }
    config.routes.push(route.clone());
    match apply_config(&state, config).await {
        Ok(version) => ok(json!({"id": route.id, "version": version})),
        Err(response) => response,
    }
}

async fn update_route(
    State(state): State<Arc<AdminState>>,
    Path(id): Path<String>,
    payload: std::result::Result<Json<RouteConfig>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(mut route) = match payload {
        Ok(payload) => payload,
        Err(rejection) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "INVALID_ROUTE",
                rejection.body_text(),
            )
        }
    };
    route.id = id.clone();
    let snapshot = state.route_table.snapshot();
    let mut config = snapshot.config.as_ref().clone();
    match config.routes.iter_mut().find(|r| r.id == id) {
        Some(existing) => *existing = route,
        None => {
            return fail(
                StatusCode::NOT_FOUND,
                "ROUTE_NOT_FOUND",
                format!("route `{id}` not found"),
            )
        }
    }
    match apply_config(&state, config).await {
        Ok(version) => ok(json!({"id": id, "version": version})),
        Err(response) => response,
    }
}

async fn delete_route(State(state): State<Arc<AdminState>>, Path(id): Path<String>) -> Response {
    let snapshot = state.route_table.snapshot();
    let mut config = snapshot.config.as_ref().clone();
    let before = config.routes.len();
    config.routes.retain(|r| r.id != id);
    if config.routes.len() == before {
        return fail(
            StatusCode::NOT_FOUND,
            "ROUTE_NOT_FOUND",
            format!("route `{id}` not found"),
        );
    }
    match apply_config(&state, config).await {
        Ok(version) => {
            state.gateway.cache.purge_route(&id);
            ok(json!({"id": id, "version": version}))
        }
        Err(response) => response,
    }
}

async fn enable_route(State(state): State<Arc<AdminState>>, Path(id): Path<String>) -> Response {
    set_enabled(&state, &id, true).await
}

async fn disable_route(State(state): State<Arc<AdminState>>, Path(id): Path<String>) -> Response {
    set_enabled(&state, &id, false).await
}

async fn set_enabled(state: &Arc<AdminState>, id: &str, enabled: bool) -> Response {
    let snapshot = state.route_table.snapshot();
    let mut config = snapshot.config.as_ref().clone();
    match config.routes.iter_mut().find(|r| r.id == id) {
        Some(route) => route.enabled = enabled,
        None => {
            return fail(
                StatusCode::NOT_FOUND,
                "ROUTE_NOT_FOUND",
                format!("route `{id}` not found"),
            )
        }
    }
    match apply_config(state, config).await {
        Ok(version) => {
            if !enabled {
                state.gateway.cache.purge_route(id);
            }
            ok(json!({"id": id, "enabled": enabled, "version": version}))
        }
        Err(response) => response,
    }
}

/// 校验 → 原子替换 → 持久化 → 广播。
#[allow(clippy::result_large_err)]
async fn apply_config(
    state: &Arc<AdminState>,
    config: GatewayConfig,
) -> std::result::Result<u64, Response> {
    let report = validate(&config, &FilterRegistry::builtin());
    if report.has_errors() {
        let issues = report
            .issues
            .iter()
            .filter(|issue| matches!(issue.severity, crate::config::validate::Severity::Error))
            .map(|issue| issue.message.clone())
            .collect::<Vec<_>>();
        return Err(fail(
            StatusCode::BAD_REQUEST,
            "INVALID_CONFIG",
            issues.join("; "),
        ));
    }
    let hash = config_hash(&config);
    let version = match state.route_table.replace(config.clone(), hash) {
        Ok(version) => version,
        Err(err) => return Err(fail(StatusCode::BAD_REQUEST, "INVALID_CONFIG", err)),
    };
    if let Err(err) = state.gateway.reload_derived(&config) {
        return Err(fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "CONFIG_APPLY_FAILED",
            err,
        ));
    }
    if config.gateway.admin.persistence.enabled {
        let path = state.persistence_path(&config);
        if let Err(err) = loader::save_routes(&path, &config.routes).await {
            tracing::error!(path = %path.display(), error = %err, "failed to persist routes");
        }
    }
    if let Some(sync) = &state.sync {
        if let Err(err) = sync.publish(version, &config.routes).await {
            tracing::warn!(error = %err, "failed to publish config change");
        }
    }
    Ok(version)
}

// ---------------------------------------------------------------------------
// 配置与只读接口
// ---------------------------------------------------------------------------

async fn reload_config(State(state): State<Arc<AdminState>>) -> Response {
    let loaded = match loader::load(&state.root_dir, state.profile.as_deref()).await {
        Ok(loaded) => loaded,
        Err(err) => {
            return fail(
                StatusCode::BAD_REQUEST,
                "CONFIG_LOAD_FAILED",
                err.to_string(),
            )
        }
    };
    let report = validate(&loaded.config, &FilterRegistry::builtin());
    if report.has_errors() {
        let issues = report
            .issues
            .iter()
            .filter(|issue| matches!(issue.severity, crate::config::validate::Severity::Error))
            .map(|issue| issue.message.clone())
            .collect::<Vec<_>>();
        return fail(StatusCode::BAD_REQUEST, "INVALID_CONFIG", issues.join("; "));
    }
    let hash = loaded.hash.clone();
    match state.route_table.replace(loaded.config.clone(), hash) {
        Ok(version) => {
            if let Err(err) = state.gateway.reload_derived(&loaded.config) {
                return fail(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CONFIG_APPLY_FAILED",
                    err,
                );
            }
            ok(json!({"version": version, "routes": loaded.config.routes.len()}))
        }
        Err(err) => fail(StatusCode::BAD_REQUEST, "INVALID_CONFIG", err),
    }
}

async fn config_status(State(state): State<Arc<AdminState>>) -> Response {
    let snapshot = state.route_table.snapshot();
    let uptime = state.started_at.elapsed().as_secs();
    ok(json!({
        "version": snapshot.version,
        "hash": snapshot.hash,
        "routes": snapshot.routes.len(),
        "enabled_routes": snapshot.config.routes.iter().filter(|r| r.enabled).count(),
        "profile": state.profile,
        "config_dir": state.root_dir.display().to_string(),
        "node_id": state.node_id,
        "uptime_secs": uptime,
        "loaded_at": snapshot.loaded_at.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_secs()),
    }))
}

async fn list_services(State(state): State<Arc<AdminState>>) -> Response {
    ok(json!({
        "static_services": state.route_table.snapshot().config.gateway.services.keys().cloned().collect::<Vec<_>>(),
        "upstreams": state.upstreams.snapshots(),
        "routes": state.route_table.snapshot().config.routes.iter()
            .map(|r| r.uri.clone()).collect::<Vec<_>>(),
    }))
}

async fn list_upstreams(State(state): State<Arc<AdminState>>) -> Response {
    ok(json!({"upstreams": state.upstreams.snapshots()}))
}

async fn list_breakers(State(state): State<Arc<AdminState>>) -> Response {
    ok(json!({"circuit_breakers": state.gateway.breakers.stats()}))
}

async fn metrics_summary(State(state): State<Arc<AdminState>>) -> Response {
    ok(json!(state.gateway.metrics.summary()))
}

async fn admin_health_live(State(state): State<Arc<AdminState>>) -> Response {
    ok(state.gateway.health.liveness())
}

async fn admin_health_ready(State(state): State<Arc<AdminState>>) -> Response {
    ok(serde_json::to_value(state.gateway.health.readiness().await)
        .unwrap_or(json!({"ready": false})))
}

async fn admin_metrics(State(state): State<Arc<AdminState>>) -> Response {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.gateway.metrics.render(),
    )
        .into_response()
}

fn config_hash(config: &GatewayConfig) -> String {
    let bytes = serde_json::to_vec(config).unwrap_or_default();
    let digest = Sha256::digest(&bytes);
    hex::encode(digest)
}

// ---------------------------------------------------------------------------
// Redis Pub/Sub 配置同步
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct SyncMessage {
    origin: String,
    version: u64,
    routes: Vec<RouteConfig>,
}

/// 多实例配置同步。
pub struct ConfigSync {
    client: redis::Client,
    channel: String,
    node_id: String,
}

impl ConfigSync {
    pub fn new(redis_url: &str, channel: &str, node_id: &str) -> std::result::Result<Self, String> {
        if redis_url.trim().is_empty() {
            return Err("redis url is empty".to_string());
        }
        let client =
            redis::Client::open(redis_url).map_err(|e| format!("invalid redis url: {e}"))?;
        Ok(Self {
            client,
            channel: channel.to_string(),
            node_id: node_id.to_string(),
        })
    }

    pub async fn publish(
        &self,
        version: u64,
        routes: &[RouteConfig],
    ) -> std::result::Result<(), String> {
        use redis::AsyncCommands;
        let payload = serde_json::to_string(&SyncMessage {
            origin: self.node_id.clone(),
            version,
            routes: routes.to_vec(),
        })
        .map_err(|e| format!("failed to serialize config sync message: {e}"))?;
        let mut conn = tokio::time::timeout(
            Duration::from_secs(3),
            self.client.get_multiplexed_async_connection(),
        )
        .await
        .map_err(|_| "redis connect timeout".to_string())?
        .map_err(|e| format!("redis connect failed: {e}"))?;
        let _: i64 = tokio::time::timeout(
            Duration::from_secs(3),
            conn.publish(self.channel.clone(), payload),
        )
        .await
        .map_err(|_| "redis publish timeout".to_string())?
        .map_err(|e| format!("redis publish failed: {e}"))?;
        Ok(())
    }

    /// 启动订阅任务；收到其他节点的变更后原子替换本地路由快照。
    pub fn spawn_subscriber(self: Arc<Self>, table: Arc<RouteTable>, gateway: Arc<GatewayState>) {
        tokio::spawn(async move {
            loop {
                match self.subscribe_once(table.clone(), gateway.clone()).await {
                    Ok(()) => {}
                    Err(err) => tracing::warn!(error = %err, "config sync subscriber disconnected"),
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    async fn subscribe_once(
        &self,
        table: Arc<RouteTable>,
        gateway: Arc<GatewayState>,
    ) -> std::result::Result<(), String> {
        use futures::StreamExt;
        let mut pubsub = self
            .client
            .get_async_pubsub()
            .await
            .map_err(|e| format!("redis pubsub connect failed: {e}"))?;
        pubsub
            .subscribe(&self.channel)
            .await
            .map_err(|e| format!("redis subscribe failed: {e}"))?;
        tracing::info!(channel = %self.channel, "config sync subscriber ready");
        let mut stream = pubsub.on_message();
        while let Some(message) = stream.next().await {
            let payload: String = match message.get_payload() {
                Ok(payload) => payload,
                Err(err) => {
                    tracing::warn!(error = %err, "invalid config sync payload");
                    continue;
                }
            };
            let message: SyncMessage = match serde_json::from_str(&payload) {
                Ok(message) => message,
                Err(err) => {
                    tracing::warn!(error = %err, "invalid config sync json");
                    continue;
                }
            };
            if message.origin == self.node_id {
                continue;
            }
            let current = table.snapshot();
            if message.version <= current.version {
                continue;
            }
            let mut config = current.config.as_ref().clone();
            config.routes = message.routes;
            let hash = config_hash(&config);
            if let Err(err) = table.replace_with_version(config.clone(), hash, message.version) {
                tracing::warn!(error = %err, "failed to apply synced config");
                continue;
            }
            if let Err(err) = gateway.reload_derived(&config) {
                tracing::warn!(error = %err, "failed to rebuild derived components after sync");
            }
            tracing::info!(version = message.version, "applied config from peer node");
        }
        Ok(())
    }
}
