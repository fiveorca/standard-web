//! 授权决策与“我的权限”API。

use std::sync::Arc;

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::bootstrap::AppState;
use crate::domain::{AuthContext, AuthzRequest, ResourceRef};
use crate::shared::response::ok;
use crate::shared::AppResult;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/authz/check", post(check))
        .route("/api/v1/authz/batch-check", post(batch_check))
        .route("/api/v1/authz/me", get(me))
        .route("/api/v1/authz/me/permissions", get(my_permissions))
        .route("/api/v1/authz/me/menus", get(my_menus))
        .route("/api/v1/authz/me/buttons", get(my_buttons))
        .route("/api/v1/authz/me/apis", get(my_apis))
        .route("/api/v1/authz/me/data-scope", get(my_data_scope))
}

#[derive(Debug, Deserialize)]
pub struct CheckBody {
    #[serde(default)]
    pub identity_id: Option<Uuid>,
    pub permission: String,
    #[serde(default)]
    pub resource: Option<ResourceRef>,
    #[serde(default)]
    pub context: Value,
}

pub async fn check(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Json(body): Json<CheckBody>,
) -> AppResult<Response> {
    let decision = state
        .authz
        .check(&AuthzRequest {
            subject_id: body.identity_id.unwrap_or(ctx.identity_id),
            tenant_id: ctx.tenant_id,
            permission: body.permission,
            resource: body.resource,
            context: body.context,
        })
        .await?;
    Ok(ok(decision).into_response())
}

#[derive(Debug, Deserialize)]
pub struct BatchCheckBody {
    #[serde(default)]
    pub identity_id: Option<Uuid>,
    pub permissions: Vec<String>,
}

pub async fn batch_check(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Json(body): Json<BatchCheckBody>,
) -> AppResult<Response> {
    let results = crate::authorization::check_many(
        &state.authz,
        body.identity_id.unwrap_or(ctx.identity_id),
        ctx.tenant_id,
        &body.permissions,
    )
    .await?;
    Ok(ok(json!({ "results": results })).into_response())
}

pub async fn me(State(state): State<Arc<AppState>>, ctx: AuthContext) -> AppResult<Response> {
    let authorization = state
        .my_authorization(ctx.identity_id, ctx.tenant_id)
        .await?;
    Ok(ok(authorization).into_response())
}

pub async fn my_permissions(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    let authorization = state
        .my_authorization(ctx.identity_id, ctx.tenant_id)
        .await?;
    Ok(ok(json!({
        "roles": authorization.roles,
        "permissions": authorization.permissions,
    }))
    .into_response())
}

pub async fn my_menus(State(state): State<Arc<AppState>>, ctx: AuthContext) -> AppResult<Response> {
    let menus = state.my_menus(ctx.identity_id, ctx.tenant_id).await?;
    Ok(ok(json!({ "items": menus })).into_response())
}

pub async fn my_buttons(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    let buttons = state.my_buttons(ctx.identity_id, ctx.tenant_id).await?;
    Ok(ok(json!({ "items": buttons })).into_response())
}

pub async fn my_apis(State(state): State<Arc<AppState>>, ctx: AuthContext) -> AppResult<Response> {
    let items = state
        .my_api_permissions(ctx.identity_id, ctx.tenant_id)
        .await?;
    Ok(ok(json!({ "items": items })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct DataScopeQuery {
    pub permission: String,
}

pub async fn my_data_scope(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<DataScopeQuery>,
) -> AppResult<Response> {
    let scope = state
        .my_data_scope(ctx.identity_id, ctx.tenant_id, &query.permission)
        .await?;
    Ok(ok(scope).into_response())
}
