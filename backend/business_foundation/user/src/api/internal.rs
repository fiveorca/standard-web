//! 内部服务接口：供认证中心或其他可信服务同步用户投影。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::{parse_uuid, require_internal_token};
use crate::bootstrap::AppState;
use crate::domain::EventEnvelope;
use crate::shared::{ok, AppError, AppResult};

#[derive(Debug, Deserialize)]
pub struct EnsureInput {
    pub tenant_id: Uuid,
    pub identity_id: Uuid,
}

#[derive(Debug, Deserialize)]
pub struct StatusInput {
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ProfileInput {
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ContactInput {
    pub kind: String,
    pub value: String,
    #[serde(default)]
    pub verified: bool,
}

async fn ensure_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<EnsureInput>,
) -> AppResult<Json<Value>> {
    require_internal_token(&state, &headers)?;
    let identity = state.auth.get_identity(input.identity_id).await?;
    if identity.tenant_id != input.tenant_id {
        return Err(AppError::forbidden("身份与租户不匹配"));
    }
    let exists: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM users WHERE id = $1")
        .bind(identity.id)
        .fetch_optional(&state.pool)
        .await?;
    if exists.is_some() {
        let view = state.get_user_view(input.tenant_id, identity.id).await?;
        return Ok(ok(json!(view)));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "INSERT INTO users
            (id, tenant_id, username, email, email_verified, phone, phone_verified,
             display_name, avatar_url, status, source)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'auth_sync')
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(identity.id)
    .bind(identity.tenant_id)
    .bind(&identity.username)
    .bind(&identity.email)
    .bind(identity.email_verified)
    .bind(&identity.phone)
    .bind(identity.phone_verified)
    .bind(&identity.display_name)
    .bind(&identity.avatar_url)
    .bind(if identity.status.is_empty() {
        "active"
    } else {
        identity.status.as_str()
    })
    .execute(&mut *tx)
    .await?;
    sqlx::query("INSERT INTO user_profiles (user_id) VALUES ($1) ON CONFLICT (user_id) DO NOTHING")
        .bind(identity.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let view = state.get_user_view(input.tenant_id, identity.id).await?;
    Ok(ok(json!(view)))
}

async fn get_user(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    require_internal_token(&state, &headers)?;
    let user = sqlx::query_as::<_, (Uuid, Uuid)>("SELECT id, tenant_id FROM users WHERE id = $1")
        .bind(parse_uuid(&id, "user_id")?)
        .fetch_optional(&state.pool)
        .await?
        .ok_or_else(|| AppError::not_found("用户不存在"))?;
    let view = state.get_user_view(user.1, user.0).await?;
    Ok(ok(json!(view)))
}

async fn update_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<StatusInput>,
) -> AppResult<Json<Value>> {
    require_internal_token(&state, &headers)?;
    let user_id = parse_uuid(&id, "user_id")?;
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT tenant_id, status FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&state.pool)
            .await?;
    let Some((tenant_id, current)) = row else {
        return Err(AppError::not_found("用户不存在"));
    };
    if current == input.status {
        return Ok(ok(json!({ "updated": false })));
    }
    let mut tx = state.pool.begin().await?;
    sqlx::query(
        "UPDATE users SET status = $2, updated_at = now(), version = version + 1 WHERE id = $1",
    )
    .bind(user_id)
    .bind(&input.status)
    .execute(&mut *tx)
    .await?;
    crate::application::audit::status_history(
        &mut tx,
        tenant_id,
        user_id,
        Some(&current),
        &input.status,
        input.reason.as_deref().or(Some("auth_sync")),
        None,
    )
    .await?;
    crate::application::audit::record_in_tx(
        &mut tx,
        crate::application::audit::AuditEntry::new("user.status.synced")
            .tenant(tenant_id)
            .resource("user", user_id.to_string())
            .detail(json!({
                "from": current,
                "to": input.status,
                "reason": input.reason,
            })),
    )
    .await?;
    tx.commit().await?;
    Ok(ok(json!({ "updated": true })))
}

async fn update_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ProfileInput>,
) -> AppResult<Json<Value>> {
    require_internal_token(&state, &headers)?;
    let user_id = parse_uuid(&id, "user_id")?;
    sqlx::query(
        "UPDATE users SET
            display_name = COALESCE($2, display_name),
            avatar_url = COALESCE($3, avatar_url),
            updated_at = now()
          WHERE id = $1",
    )
    .bind(user_id)
    .bind(input.display_name.as_deref())
    .bind(input.avatar_url.as_deref())
    .execute(&state.pool)
    .await?;
    Ok(ok(json!({ "updated": true })))
}

async fn sync_contact(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ContactInput>,
) -> AppResult<Json<Value>> {
    require_internal_token(&state, &headers)?;
    let user_id = parse_uuid(&id, "user_id")?;
    let row: Option<(Uuid,)> = sqlx::query_as("SELECT tenant_id FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(&state.pool)
        .await?;
    let tenant_id = row.ok_or_else(|| AppError::not_found("用户不存在"))?.0;
    let kind = match input.kind.as_str() {
        "email" => "email",
        "phone" | "sms" => "phone",
        _ => return Err(AppError::bad_request("不支持的联系方式类型")),
    };
    state
        .sync_verified_contact(tenant_id, user_id, kind, &input.value, input.verified)
        .await?;
    Ok(ok(json!({ "synced": true })))
}

async fn receive_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(event): Json<EventEnvelope>,
) -> AppResult<Json<Value>> {
    require_internal_token(&state, &headers)?;
    let duplicate = crate::events::handle_incoming(&state, &event).await?;
    Ok(ok(json!({ "duplicate": duplicate })))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/internal/users/ensure", post(ensure_user))
        .route(
            "/api/v1/internal/users/{id}",
            get(get_user).patch(update_profile),
        )
        .route("/api/v1/internal/users/{id}/status", post(update_status))
        .route("/api/v1/internal/users/{id}/contacts", post(sync_contact))
        .route("/api/v1/internal/events", post(receive_event))
}
