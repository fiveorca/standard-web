//! 内部服务 API：供用户中心等受信服务同步身份与投递事件。
//!
//! 仅接受 `x-internal-token` 常量时间校验通过的请求。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;
use uuid::Uuid;

use crate::application::events::EventEnvelope;
use crate::application::identity::CreateIdentityInput;
use crate::bootstrap::AppState;
use crate::domain::{AuthzRequest, ResourceRef};
use crate::shared::response::ok;
use crate::shared::{AppError, AppResult};

use super::{parse_uuid, request_meta, require_internal_token};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/internal/identities", post(create_identity))
        .route(
            "/api/v1/internal/identities/{id}",
            get(get_identity).patch(sync_profile),
        )
        .route(
            "/api/v1/internal/identities/{id}/status",
            post(update_status),
        )
        .route(
            "/api/v1/internal/identities/{id}/contacts/request",
            post(request_contact_change),
        )
        .route(
            "/api/v1/internal/identities/{id}/contacts/confirm",
            post(confirm_contact_change),
        )
        .route(
            "/api/v1/internal/identities/{id}/contacts/{kind}",
            delete(clear_contact),
        )
        .route("/api/v1/internal/authz/check", post(authz_check))
        .route(
            "/api/v1/internal/identities/{id}/sessions/revoke",
            post(revoke_sessions),
        )
        .route("/api/v1/internal/events", post(receive_event))
}

#[derive(Debug, Deserialize)]
struct InternalCreateIdentity {
    tenant_id: Uuid,
    username: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    email_verified: Option<bool>,
    #[serde(default)]
    phone_verified: Option<bool>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    source: Option<String>,
}

async fn create_identity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<InternalCreateIdentity>,
) -> AppResult<Response> {
    require_internal_token(&state, &headers)?;
    let meta = request_meta(&state, &headers);
    let identity = state
        .create_identity(
            CreateIdentityInput {
                tenant_id: body.tenant_id,
                username: body.username,
                email: body.email,
                phone: body.phone,
                password: body.password,
                display_name: body.display_name,
                avatar_url: body.avatar_url,
                status: body.status,
                email_verified: body.email_verified.unwrap_or(false),
                phone_verified: body.phone_verified.unwrap_or(false),
                metadata: body.metadata.unwrap_or_else(|| json!({})),
                require_email_verification: false,
                source: body.source.unwrap_or_else(|| "internal".to_string()),
            },
            &meta,
        )
        .await?;
    Ok(ok(json!({ "identity": identity })).into_response())
}

async fn get_identity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    require_internal_token(&state, &headers)?;
    let identity = state.get_identity(parse_uuid(&id, "identity_id")?).await?;
    Ok(ok(json!({ "identity": identity })).into_response())
}

#[derive(Debug, Deserialize)]
struct SyncProfileRequest {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
}

async fn sync_profile(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SyncProfileRequest>,
) -> AppResult<Response> {
    require_internal_token(&state, &headers)?;
    state
        .sync_identity_profile(
            parse_uuid(&id, "identity_id")?,
            body.display_name,
            body.avatar_url,
            body.email,
            body.phone,
        )
        .await?;
    Ok(ok(json!({ "synced": true })).into_response())
}

#[derive(Debug, Deserialize)]
struct UpdateStatusRequest {
    status: String,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    actor_id: Option<Uuid>,
}

async fn update_status(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<UpdateStatusRequest>,
) -> AppResult<Response> {
    require_internal_token(&state, &headers)?;
    let meta = request_meta(&state, &headers);
    let identity = state
        .update_identity_status(
            parse_uuid(&id, "identity_id")?,
            &body.status,
            body.reason,
            body.actor_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "identity": identity })).into_response())
}

async fn revoke_sessions(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    require_internal_token(&state, &headers)?;
    let count = state
        .revoke_all_sessions(parse_uuid(&id, "identity_id")?, "internal_request")
        .await?;
    Ok(ok(json!({ "revoked": count })).into_response())
}

#[derive(Debug, Deserialize)]
struct ContactChangeRequest {
    /// `email` 或 `sms`/`phone`
    channel: String,
    value: String,
}

/// 内部发起联系方式变更验证码（由用户中心触发，验证码仍由认证中心发送与校验）。
async fn request_contact_change(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ContactChangeRequest>,
) -> AppResult<Response> {
    require_internal_token(&state, &headers)?;
    let identity = state.get_identity(parse_uuid(&id, "identity_id")?).await?;
    let (channel, purpose) = match body.channel.as_str() {
        "email" => ("email", "change_email"),
        "sms" | "phone" => ("sms", "change_phone"),
        _ => return Err(AppError::bad_request("不支持的联系方式类型")),
    };
    state
        .issue_verification_code(
            identity.tenant_id,
            Some(identity.id),
            purpose,
            channel,
            &body.value,
        )
        .await?;
    Ok(ok(json!({ "sent": true })).into_response())
}

#[derive(Debug, Deserialize)]
struct ContactConfirmRequest {
    channel: String,
    value: String,
    code: String,
}

/// 内部确认联系方式变更（校验验证码并更新身份标识）。
async fn confirm_contact_change(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ContactConfirmRequest>,
) -> AppResult<Response> {
    require_internal_token(&state, &headers)?;
    let meta = request_meta(&state, &headers);
    state
        .change_contact(
            parse_uuid(&id, "identity_id")?,
            &body.channel,
            &body.value,
            &body.code,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "changed": true })).into_response())
}

async fn receive_event(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(event): Json<EventEnvelope>,
) -> AppResult<Response> {
    require_internal_token(&state, &headers)?;
    let result = state.handle_incoming_event(event).await?;
    Ok(ok(result).into_response())
}

/// 解绑身份的联系方式（用户中心删除本地投影时调用）。
async fn clear_contact(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((id, kind)): Path<(String, String)>,
) -> AppResult<Response> {
    require_internal_token(&state, &headers)?;
    let meta = request_meta(&state, &headers);
    state
        .clear_contact(parse_uuid(&id, "identity_id")?, &kind, &meta)
        .await?;
    Ok(ok(json!({ "unbound": true })).into_response())
}

#[derive(Debug, Deserialize)]
struct InternalAuthzCheckRequest {
    tenant_id: Uuid,
    identity_id: Uuid,
    permission: String,
    #[serde(default)]
    resource: Option<ResourceRef>,
    #[serde(default)]
    context: serde_json::Value,
}

/// 内部授权决策：供用户中心等服务以内部令牌判定某个身份是否拥有权限。
async fn authz_check(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<InternalAuthzCheckRequest>,
) -> AppResult<Response> {
    require_internal_token(&state, &headers)?;
    let decision = state
        .authz
        .check(&AuthzRequest {
            subject_id: body.identity_id,
            tenant_id: body.tenant_id,
            permission: body.permission,
            resource: body.resource,
            context: body.context,
        })
        .await?;
    Ok(ok(decision).into_response())
}

#[allow(dead_code)]
fn _assert_error() -> AppError {
    AppError::bad_request("unreachable")
}
