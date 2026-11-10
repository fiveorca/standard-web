use crate::transport::http::handlers;
use crate::transport::http::handlers::AppState;
use axum::routing::{get, post};
use axum::Router;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        // health
        .route("/health", get(handlers::health))
        // logs query
        .route("/api/v1/logs/query", post(handlers::query_logs))
        .route("/api/v1/logs/:event_id", get(handlers::get_log))
        // analytics
        .route(
            "/api/v1/analytics/overview",
            get(handlers::analytics_overview),
        )
        .route("/api/v1/analytics/trends", get(handlers::analytics_trends))
        .route(
            "/api/v1/analytics/top-errors",
            get(handlers::analytics_top_errors),
        )
        .with_state(state)
}
