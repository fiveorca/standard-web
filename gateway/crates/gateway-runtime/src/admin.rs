//! Admin Server —— Axum 实现的管理接口。
//!
//! Phase 1 只暴露三个健康检查端点：
//!   - GET /health   —— 是否活着（进程是否在运行）
//!   - GET /ready    —— 是否可以接收流量（依赖是否就绪）
//!   - GET /version  —— 版本信息
//!
//! # 为什么用 Axum
//!
//! Admin API 是典型的"定义路由 → 写 handler"场景，Axum 的 ergonomic API
//! 非常适合。业务 HTTP 代理则用 Hyper + Tower，各司其职。
//!
//! # 安全
//!
//! Phase 1 中 Admin Server 默认只绑定 127.0.0.1，不能被公网直接访问。
//! Phase 3 控制面阶段加入 RBAC（admin 接口的认证/授权）。

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::get, Json, Router};
use gateway_common::GatewayError;
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::runtime::Runtime;

// ---------------------------------------------------------------------------
// 响应结构体
// ---------------------------------------------------------------------------
// 每个结构体都需要 #[derive(Serialize)]，因为 axum 的 Json<T> 要求 T: Serialize。
// axum 0.8 中 (StatusCode, Json<T>) 实现了 IntoResponse，
// 前提是 T: Serialize（Json 内部用 serde_json::to_string）。

/// /health 响应。
///
/// ```json
/// { "status": "ok" }
/// ```
#[derive(Serialize)]
struct HealthResponse {
    /// 固定为 `"ok"`（进程存活即返回 ok）
    status: &'static str,
}

/// /ready 响应。
///
/// ```json
/// {
///   "status": "ready",
///   "gateway_id": "gateway-dev",
///   "config_version": 1
/// }
/// ```
#[derive(Serialize)]
struct ReadyResponse {
    /// `"ready"` 或 `"not_ready"`（Phase 1 总是 ready）
    status: &'static str,
    /// Gateway 的唯一 ID（来自配置文件 gateway.id）
    gateway_id: String,
    /// 配置版本号（Phase 1 固定 1）
    config_version: u64,
}

/// /version 响应。
///
/// ```json
/// {
///   "version": "0.1.0",
///   "gateway_id": "gateway-dev",
///   "instance_name": "dev-node",
///   "environment": "development",
///   "config_version": 1
/// }
/// ```
#[derive(Serialize)]
struct VersionResponse {
    /// 编译时的 Cargo 包版本（env!("CARGO_PKG_VERSION")）
    version: &'static str,
    gateway_id: String,
    instance_name: String,
    environment: String,
    config_version: u64,
}

/// /upstreams 响应中的单个端点。
#[derive(Serialize)]
struct EndpointHealthView {
    /// 运行时端点 ID
    id: String,
    /// `host:port`
    address: String,
    /// 负载均衡权重
    weight: u32,
    /// 健康状态：HEALTHY / UNHEALTHY / UNKNOWN / DRAINING
    status: String,
}

/// /upstreams 响应中的单个上游。
#[derive(Serialize)]
struct UpstreamHealthView {
    id: String,
    /// 负载均衡算法
    algorithm: String,
    endpoints: Vec<EndpointHealthView>,
}

/// /upstreams 响应。
#[derive(Serialize)]
struct UpstreamsResponse {
    /// 当前生效配置版本
    config_version: u64,
    upstreams: Vec<UpstreamHealthView>,
}

// ---------------------------------------------------------------------------
// 启动 Admin Server
// ---------------------------------------------------------------------------

/// 启动 Axum Admin Server。
///
/// # 参数
/// - `addr`：监听地址（通常是 127.0.0.1:8081）
/// - `runtime`：共享的 Runtime 实例（Arc 包装），handler 通过 State extractor 访问
/// - `shutdown`：CancellationToken，收到信号后执行 graceful shutdown
/// - `extra`：额外挂载的路由（integrated 模式下为控制面 `/api/admin/v1`）
///
/// # axum 0.8 API
/// - `axum::Router::new()` —— 新建路由表
/// - `Router::route(path, method_handler)` —— 注册路由
/// - `Router::with_state(state)` —— 把共享状态注入 handler（通过 State extractor）
/// - `axum::serve(listener, app)` —— 启动 server，返回 Future<Result<(), Error>>
/// - `.with_graceful_shutdown(future)` —— 接受一个 Future，resolve 时触发 shutdown
pub async fn start_admin_server(
    addr: SocketAddr,
    runtime: Arc<Runtime>,
    shutdown: CancellationToken,
    extra: Option<Router>,
) -> Result<(), GatewayError> {
    // -----------------------------------------------------------------
    // 1. 组装路由
    // -----------------------------------------------------------------
    // Metrics 路径来自配置，注册前先取出来（避免与 with_state 的
    // runtime move 产生借用冲突）。
    let metrics_enabled = runtime.metrics_enabled();
    let metrics_path = runtime.metrics_path().to_string();

    let mut app = Router::new()
        // .route 接受 path + 一个或多个 HTTP method handler
        // routing::get(handler) 注册 GET 方法
        .route("/health", get(health_handler))
        .route("/ready", get(ready_handler))
        .route("/version", get(version_handler))
        .route("/upstreams", get(upstreams_handler));

    // observability.metrics.enabled 为 true 时才暴露 Prometheus 端点
    if metrics_enabled {
        app = app.route(&metrics_path, get(metrics_handler));
    }

    // with_state 把 runtime 注入 Router
    // handler 通过 State<Arc<Runtime>> extractor 拿到它
    let app = app.with_state(runtime);

    // integrated 模式：把控制面路由合并进来。`extra` 已经是 `Router<()>`，
    // 与上面 with_state 之后的 Router 状态类型一致，可以直接 merge。
    let app = match extra {
        Some(extra) => app.merge(extra),
        None => app,
    };

    // -----------------------------------------------------------------
    // 2. 绑定 TcpListener
    // -----------------------------------------------------------------
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| GatewayError::Internal(format!("admin bind error: {e}")))?;

    // local_addr() 可能失败（如 fd 已关闭的极端场景），显式 map_err 传播，
    // 生产代码禁止 unwrap/expect
    let actual = listener
        .local_addr()
        .map_err(|e| GatewayError::Internal(format!("admin local addr error: {e}")))?;
    tracing::info!("admin server listening on {}", actual);

    // -----------------------------------------------------------------
    // 3. 启动 Axum Server
    // -----------------------------------------------------------------
    // axum::serve 接受 TcpListener + Router，内部自动处理 HTTP/1.1 和 HTTP/2。
    // 我们用 .with_graceful_shutdown() 监听 CancellationToken。
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            // .cancelled() 返回 Future，cancel() 时 resolve
            shutdown.cancelled().await;
            tracing::info!("admin server graceful shutdown");
        })
        .await
        // axum::serve 的错误是 Box<dyn StdError>，包装成 GatewayError::Internal
        .map_err(|e| GatewayError::Internal(format!("admin serve error: {e}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Handler 函数
// ---------------------------------------------------------------------------
// axum handler 返回 impl IntoResponse。
// (StatusCode, Json<T>) 在 axum 0.8 中实现了 IntoResponse，
// 要求 T: Serialize（我们的响应结构体都满足）。

/// GET /health —— 进程存活检查。
///
/// 只要进程在运行就返回 200 OK + {"status": "ok"}。
/// 不检查任何下游依赖（那是 /ready 的职责）。
async fn health_handler() -> impl IntoResponse {
    // (StatusCode, Json<T>) → IntoResponse（axum 0.8 内置实现）
    (StatusCode::OK, Json(HealthResponse { status: "ok" }))
}

/// GET /ready —— 就绪检查。
///
/// Phase 1 总是返回 ready。
/// Phase 2+ 会检查上游健康、配置编译状态等。
async fn ready_handler(State(rt): State<Arc<Runtime>>) -> impl IntoResponse {
    if rt.is_ready() {
        (
            StatusCode::OK,
            Json(ReadyResponse {
                status: "ready",
                gateway_id: rt.gateway_id().to_string(),
                config_version: rt.config_version(),
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "not_ready",
                gateway_id: rt.gateway_id().to_string(),
                config_version: rt.config_version(),
            }),
        )
    }
}

/// GET /metrics —— Prometheus 文本格式指标导出。
///
/// 只有 `observability.metrics.enabled = true` 时才会注册该路由。
/// Content-Type 按 Prometheus 文本协议约定设置。
async fn metrics_handler() -> impl IntoResponse {
    // 全局注册表渲染为文本；渲染失败不会发生（内部只用 writeln!）
    let body = gateway_observability::Metrics::global().render();
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

/// GET /version —— 版本和实例信息。
///
/// 返回编译版本、Gateway ID、实例名、环境等。
async fn version_handler(State(rt): State<Arc<Runtime>>) -> impl IntoResponse {
    // 只有 Json<T>，没有 StatusCode——axum 默认 200 OK
    Json(VersionResponse {
        // env!("CARGO_PKG_VERSION") —— 编译时 Cargo 注入的包版本字符串
        version: env!("CARGO_PKG_VERSION"),
        gateway_id: rt.gateway_id().to_string(),
        instance_name: rt.instance_name().to_string(),
        environment: rt.environment().to_string(),
        config_version: rt.config_version(),
    })
}

/// GET /upstreams —— 上游端点健康状态。
///
/// 返回当前快照中所有上游及其端点的健康状态，用于排障与联调
/// （主动/被动健康检查的效果可以在这里直接观察）。
async fn upstreams_handler(State(rt): State<Arc<Runtime>>) -> impl IntoResponse {
    let state = rt.snapshot_store().current();
    let upstreams = state.upstream_registry.list_upstreams().await;
    let items = upstreams
        .into_iter()
        .map(|upstream| UpstreamHealthView {
            id: upstream.id.clone(),
            algorithm: upstream.algorithm.to_string(),
            endpoints: upstream
                .endpoints
                .into_iter()
                .map(|ep| EndpointHealthView {
                    id: ep.runtime_id.clone(),
                    address: ep.address(),
                    weight: ep.weight,
                    status: ep.status.to_string(),
                })
                .collect(),
        })
        .collect();

    (
        StatusCode::OK,
        Json(UpstreamsResponse {
            config_version: state.config_version,
            upstreams: items,
        }),
    )
}
