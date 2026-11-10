pub mod dto;

use crate::application::analytics::AnalyticsService;
use crate::application::query::QueryService;
use crate::transport::http::handlers::dto::*;
use crate::transport::http::middleware::auth::Authenticated;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use std::sync::Arc;
use uuid::Uuid;

/// AppState
#[derive(Clone)]
pub struct AppState {
    pub query: Arc<QueryService>,
    pub analytics: Arc<AnalyticsService>,
}

/// POST /api/v1/logs/query
pub async fn query_logs(
    State(state): State<AppState>,
    Authenticated(ctx): Authenticated,
    Json(req): Json<QueryLogsRequest>,
) -> Response {
    let tenant_id = ctx.tenant_id.clone();
    let app_req = crate::application::query::QueryLogsRequest {
        tenant_id,
        start_time: req.start_time,
        end_time: req.end_time,
        levels: req.levels,
        service_names: req.service_names,
        environments: req.environments,
        host_names: req.host_names,
        trace_id: req.trace_id,
        span_id: req.span_id,
        request_id: req.request_id,
        exception_type: req.exception_type,
        keyword: req.keyword,
        page_size: req.page_size,
        cursor: req.cursor,
    };

    match state.query.query_logs(app_req).await {
        Ok(result) => {
            let rows: Vec<LogSummary> = result
                .rows
                .into_iter()
                .map(|r| LogSummary {
                    event_id: r.event_id,
                    log_time: r.log_time,
                    level: r.level,
                    service_name: r.service_name,
                    environment: r.environment,
                    host_name: r.host_name,
                    message: r.message,
                    trace_id: r.trace_id,
                    tenant_id: r.tenant_id,
                })
                .collect();
            let next_cursor = result.next_cursor.map(|c| c.encode());
            let body = Json(QueryLogsResponse {
                rows,
                has_more: result.has_more,
                next_cursor,
            });
            (StatusCode::OK, body).into_response()
        }
        Err(crate::common::error::AppError::Validation(msg)) => {
            (StatusCode::BAD_REQUEST, Json(ApiErrorResponse {
                error: msg,
                details: None,
            }))
                .into_response()
        }
        Err(other) => {
            tracing::error!(?other, "query_logs failed");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiErrorResponse {
                error: other.to_string(),
                details: None,
            }))
                .into_response()
        }
    }
}

/// GET /api/v1/logs/{eventId}
pub async fn get_log(
    State(state): State<AppState>,
    Authenticated(ctx): Authenticated,
    Path(event_id): Path<String>,
) -> Response {
    let id: Uuid = match Uuid::parse_str(&event_id) {
        Ok(id) => id,
        Err(_) => {
            return (StatusCode::BAD_REQUEST, Json(ApiErrorResponse {
                error: "invalid event_id".into(),
                details: None,
            }))
                .into_response()
        }
    };

    match state.query.get_log_by_id(ctx.tenant_id, id).await {
        Ok(Some(ev)) => {
            let detail = LogDetailResponse {
                event_id: ev.event_id,
                schema_version: ev.schema_version,
                log_time: ev.timestamp,
                received_at: ev.received_at.unwrap_or(ev.timestamp),
                level: ev.level.as_str().to_string(),
                service_name: ev.service_name,
                service_version: ev.service_version,
                environment: ev.environment,
                host_name: ev.host_name,
                logger: ev.logger,
                thread_name: ev.thread_name,
                message: ev.message,
                trace_id: ev.trace_id,
                span_id: ev.span_id,
                request_id: ev.request_id,
                tenant_id: ev.tenant_id,
                exception: ev.exception.map(|ex| ExceptionInfoDto {
                    r#type: ex.r#type,
                    message: ex.message,
                    stack_trace: ex.stack_trace,
                }),
                attributes: ev.attributes,
            };
            (StatusCode::OK, Json(detail)).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(ApiErrorResponse {
            error: "log not found".into(),
            details: None,
        }))
            .into_response(),
        Err(other) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiErrorResponse {
            error: other.to_string(),
            details: None,
        }))
            .into_response(),
    }
}

/// GET /api/v1/analytics/overview
pub async fn analytics_overview(
    State(state): State<AppState>,
    Authenticated(ctx): Authenticated,
    axum::extract::Query(q): axum::extract::Query<TimeRangeQuery>,
) -> Response {
    match state
        .analytics
        .overview(ctx.tenant_id, q.start_time, q.end_time)
        .await
    {
        Ok(o) => {
            let body = OverviewResponse {
                total_count: o.total_count,
                error_count: o.error_count,
                fatal_count: o.fatal_count,
                error_rate: o.error_rate,
                fatal_rate: o.fatal_rate,
                levels: o
                    .levels
                    .into_iter()
                    .map(|l| LevelCountDto {
                        level: l.level,
                        count: l.count,
                    })
                    .collect(),
                services: o
                    .services
                    .into_iter()
                    .map(|s| ServiceCountDto {
                        service_name: s.service_name,
                        count: s.count,
                    })
                    .collect(),
            };
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(other) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiErrorResponse {
            error: other.to_string(),
            details: None,
        }))
            .into_response(),
    }
}

/// GET /api/v1/analytics/trends
pub async fn analytics_trends(
    State(state): State<AppState>,
    Authenticated(ctx): Authenticated,
    axum::extract::Query(q): axum::extract::Query<TrendQuery>,
) -> Response {
    match state
        .analytics
        .trends(ctx.tenant_id, q.start_time, q.end_time, q.granularity)
        .await
    {
        Ok(buckets) => {
            let body: Vec<TrendBucketDto> = buckets
                .into_iter()
                .map(|b| TrendBucketDto {
                    bucket: b.bucket,
                    count: b.count,
                })
                .collect();
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(other) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiErrorResponse {
            error: other.to_string(),
            details: None,
        }))
            .into_response(),
    }
}

/// GET /api/v1/analytics/top-errors
pub async fn analytics_top_errors(
    State(state): State<AppState>,
    Authenticated(ctx): Authenticated,
    axum::extract::Query(q): axum::extract::Query<TopErrorsQuery>,
) -> Response {
    match state
        .analytics
        .top_errors(ctx.tenant_id, q.start_time, q.end_time, q.limit)
        .await
    {
        Ok(errors) => {
            let body: Vec<TopErrorDto> = errors
                .into_iter()
                .map(|e| TopErrorDto {
                    error_key: e.error_key,
                    count: e.count,
                    last_seen: e.last_seen,
                })
                .collect();
            (StatusCode::OK, Json(body)).into_response()
        }
        Err(other) => (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiErrorResponse {
            error: other.to_string(),
            details: None,
        }))
            .into_response(),
    }
}

/// GET /health
pub async fn health() -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "ok", "service": "logserver"})),
    )
        .into_response()
}

