//! 认证授权中心服务入口。

use std::sync::Arc;
use std::time::Duration;

use axum::http::{header, HeaderValue, Method};
use axum::middleware;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::trace::TraceLayer;

use auth_center::api;
use auth_center::bootstrap::{seed, AppState};
use auth_center::config::Settings;
use auth_center::middleware::auth::{auth_middleware, request_context};
use auth_center::middleware::security::security_headers;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    init_tracing();

    let settings = Settings::load(None, None)?;
    let state = Arc::new(AppState::new(settings).await?);
    seed::seed(&state).await?;

    if std::env::args().any(|arg| arg == "seed-admin") {
        tracing::info!("种子数据已初始化，退出");
        return Ok(());
    }

    state.outbox.clone().spawn();

    let router = api::router(state.clone())
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .layer(middleware::from_fn(request_context))
        .layer(middleware::from_fn(security_headers))
        .layer(cors_layer(&state))
        .layer(TraceLayer::new_for_http())
        .layer(tower_http::limit::RequestBodyLimitLayer::new(
            state.config.server.max_body_bytes as usize,
        ))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::REQUEST_TIMEOUT,
            Duration::from_secs(state.config.server.request_timeout_secs.max(1)),
        ));

    let bind = state.config.server.bind.clone();
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(addr = %bind, "认证授权中心已启动");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn init_tracing() {
    let level = std::env::var("AUTH__LOGGING__LEVEL").unwrap_or_else(|_| "info".to_string());
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level));
    let format = std::env::var("AUTH__LOGGING__FORMAT").unwrap_or_default();
    if format.eq_ignore_ascii_case("json") {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
}

fn cors_layer(state: &AppState) -> CorsLayer {
    let origins = &state.config.server.cors_allowed_origins;
    let allow_origin = if origins.iter().any(|origin| origin == "*") {
        AllowOrigin::any()
    } else {
        AllowOrigin::list(
            origins
                .iter()
                .filter_map(|origin| HeaderValue::from_str(origin).ok()),
        )
    };
    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            header::ORIGIN,
            header::HeaderName::from_static("x-csrf-token"),
            header::HeaderName::from_static("x-request-id"),
            header::HeaderName::from_static("x-tenant"),
            header::HeaderName::from_static("x-internal-token"),
        ])
        .max_age(Duration::from_secs(600))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            signal.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!("收到退出信号，正在优雅关闭");
}
