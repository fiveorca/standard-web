//! 终端用户自助接口。

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::api::{request_meta, Auth};
use crate::application::attributes::AttributeValuesInput;
use crate::application::registrations::RegistrationInput;
use crate::application::ProfileInput;
use crate::bootstrap::AppState;
use crate::shared::{ok, AppResult, RequestMeta};

#[derive(Debug, Deserialize)]
pub struct ContactRequest {
    pub channel: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
pub struct ContactConfirm {
    pub channel: String,
    pub value: String,
    pub code: String,
}

#[derive(Debug, Deserialize)]
pub struct AvatarInput {
    pub avatar_url: String,
}

#[derive(Debug, Deserialize)]
pub struct NicknameInput {
    pub nickname: String,
}

fn meta(state: &AppState, headers: &HeaderMap) -> RequestMeta {
    request_meta(headers, state.config.server.trust_proxy_headers)
}

async fn me(State(state): State<Arc<AppState>>, Auth(ctx): Auth) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let detail = state.user_detail(ctx.tenant_id, ctx.identity_id).await?;
    Ok(ok(detail))
}

async fn update_me(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(patch): Json<crate::application::users::UpdateUserInput>,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let user = state
        .update_user(
            ctx.tenant_id,
            ctx.identity_id,
            &patch,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(user)))
}

async fn my_profile(State(state): State<Arc<AppState>>, Auth(ctx): Auth) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let profile = crate::application::load_profile(&state, ctx.identity_id).await?;
    Ok(ok(json!(profile)))
}

async fn update_my_profile(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<ProfileInput>,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let profile = state
        .update_profile(
            ctx.tenant_id,
            ctx.identity_id,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(profile)))
}

async fn update_avatar(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<AvatarInput>,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let patch = crate::application::users::UpdateUserInput {
        avatar_url: Some(input.avatar_url),
        ..Default::default()
    };
    let user = state
        .update_user(
            ctx.tenant_id,
            ctx.identity_id,
            &patch,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "avatar_url": user.avatar_url })))
}

async fn update_nickname(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<NicknameInput>,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let patch = crate::application::users::UpdateUserInput {
        display_name: Some(input.nickname),
        ..Default::default()
    };
    let user = state
        .update_user(
            ctx.tenant_id,
            ctx.identity_id,
            &patch,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "display_name": user.display_name })))
}

async fn my_contacts(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let contacts = state.list_contacts(ctx.tenant_id, ctx.identity_id).await?;
    Ok(ok(json!(contacts)))
}

async fn request_contact(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<ContactRequest>,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    state
        .request_contact_change(
            ctx.tenant_id,
            ctx.identity_id,
            &input.channel,
            &input.value,
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "sent": true })))
}

async fn confirm_contact(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<ContactConfirm>,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let contacts = state
        .confirm_contact_change(
            ctx.tenant_id,
            ctx.identity_id,
            &input.channel,
            &input.value,
            &input.code,
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(contacts)))
}

async fn unbind_contact(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(kind): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let contacts = state
        .unbind_contact(
            ctx.tenant_id,
            ctx.identity_id,
            &kind,
            &meta(&state, &headers),
            Some(ctx.identity_id),
        )
        .await?;
    Ok(ok(json!(contacts)))
}

async fn my_attributes(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let values = state
        .list_user_attribute_values(ctx.tenant_id, ctx.identity_id)
        .await?;
    Ok(ok(json!(values)))
}

async fn update_my_attributes(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<AttributeValuesInput>,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let values = state
        .set_user_attribute_values(
            ctx.tenant_id,
            ctx.identity_id,
            &input.values,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(values)))
}

async fn my_groups(State(state): State<Arc<AppState>>, Auth(ctx): Auth) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let groups = state
        .list_user_groups(ctx.tenant_id, ctx.identity_id)
        .await?;
    Ok(ok(json!(groups)))
}

async fn my_organizations(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let memberships = state
        .list_user_memberships(ctx.tenant_id, ctx.identity_id)
        .await?;
    Ok(ok(json!(memberships)))
}

async fn my_history(State(state): State<Arc<AppState>>, Auth(ctx): Auth) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let history = state
        .list_user_org_history(ctx.tenant_id, ctx.identity_id)
        .await?;
    Ok(ok(json!(history)))
}

async fn my_links(State(state): State<Arc<AppState>>, Auth(ctx): Auth) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let links = state
        .list_account_links(ctx.tenant_id, ctx.identity_id)
        .await?;
    Ok(ok(json!(links)))
}

async fn unlink(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(provider): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    state
        .remove_account_link(
            ctx.tenant_id,
            ctx.identity_id,
            &provider,
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "removed": true })))
}

async fn my_registration(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
) -> AppResult<Json<Value>> {
    state.ensure_user_from_context(&ctx).await?;
    let record = state
        .user_registration(ctx.tenant_id, ctx.identity_id)
        .await?;
    Ok(ok(json!(record)))
}

async fn register(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<RegistrationInput>,
) -> AppResult<Json<Value>> {
    let result = state.register_user(&input, &meta(&state, &headers)).await?;
    Ok(ok(json!(result)))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/users/me", get(me).patch(update_me))
        .route(
            "/api/v1/users/me/profile",
            get(my_profile).put(update_my_profile),
        )
        .route("/api/v1/users/me/avatar", put(update_avatar))
        .route("/api/v1/users/me/nickname", put(update_nickname))
        .route("/api/v1/users/me/contacts", get(my_contacts))
        .route("/api/v1/users/me/contacts/request", post(request_contact))
        .route("/api/v1/users/me/contacts/confirm", post(confirm_contact))
        .route("/api/v1/users/me/contacts/{kind}", delete(unbind_contact))
        .route(
            "/api/v1/users/me/attributes",
            get(my_attributes).put(update_my_attributes),
        )
        .route("/api/v1/users/me/groups", get(my_groups))
        .route("/api/v1/users/me/organizations", get(my_organizations))
        .route("/api/v1/users/me/history", get(my_history))
        .route("/api/v1/users/me/links", get(my_links))
        .route("/api/v1/users/me/links/{provider}", delete(unlink))
        .route("/api/v1/users/me/registration", get(my_registration))
        .route("/api/v1/registrations", post(register))
}
