//! 管理端接口：用户、属性、分组、组织、注册审核与审计。

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::api::{parse_uuid, request_meta, Auth};
use crate::application::attributes::{AttributeInput, AttributeValuesInput};
use crate::application::groups::{GroupInput, MembersInput};
use crate::application::orgs::{DepartmentInput, MemberInput, OrganizationInput, TransferInput};
use crate::application::registrations::{AccountLinkInput, RegistrationListQuery, ReviewInput};
use crate::application::users::{BatchUpdateItem, CreateUserInput, UpdateUserInput, UserListQuery};
use crate::application::ProfileInput;
use crate::bootstrap::AppState;
use crate::shared::{ok, AppResult, PageQuery, RequestMeta};

const ADMIN_PERMISSION: &str = "identity:manage";
const AUDIT_PERMISSION: &str = "audit:read";

#[derive(Debug, Deserialize)]
pub struct StatusInput {
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TagsInput {
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImportInput {
    pub content: String,
}

#[derive(Debug, Deserialize)]
pub struct LeaderInput {
    #[serde(default)]
    pub leader_id: Option<Uuid>,
}

fn meta(state: &AppState, headers: &HeaderMap) -> RequestMeta {
    request_meta(headers, state.config.server.trust_proxy_headers)
}

async fn guard(state: &AppState, ctx: &Auth, permission: &str) -> AppResult<()> {
    state.require_permission(&ctx.0, permission).await
}

// ───────────────────────── 用户 ─────────────────────────

async fn list_users(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Query(query): Query<UserListQuery>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let page = state.list_users(ctx.tenant_id, &query).await?;
    Ok(ok(json!(page)))
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<CreateUserInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    if input.tenant_id != ctx.tenant_id {
        return Err(crate::shared::AppError::forbidden("不能在其他租户创建用户"));
    }
    let user = state
        .create_user(input, Some(ctx.identity_id), &meta(&state, &headers))
        .await?;
    Ok(ok(json!(user)))
}

async fn user_detail(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let detail = state
        .user_detail(ctx.tenant_id, parse_uuid(&id, "user_id")?)
        .await?;
    Ok(ok(detail))
}

async fn update_user(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(patch): Json<UpdateUserInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let user = state
        .update_user(
            ctx.tenant_id,
            parse_uuid(&id, "user_id")?,
            &patch,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(user)))
}

async fn update_profile(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<ProfileInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let profile = state
        .update_profile(
            ctx.tenant_id,
            parse_uuid(&id, "user_id")?,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(profile)))
}

async fn delete_user(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    state
        .delete_user(
            ctx.tenant_id,
            parse_uuid(&id, "user_id")?,
            None,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "deleted": true })))
}

async fn restore_user(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let user = state
        .restore_user(
            ctx.tenant_id,
            parse_uuid(&id, "user_id")?,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(user)))
}

async fn change_status(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<StatusInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let user = state
        .change_status(
            ctx.tenant_id,
            parse_uuid(&id, "user_id")?,
            &input.status,
            input.reason.as_deref(),
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(user)))
}

async fn get_tags(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let view = state
        .get_user_view(ctx.tenant_id, parse_uuid(&id, "user_id")?)
        .await?;
    Ok(ok(json!(view.tags)))
}

async fn set_tags(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<TagsInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let tags = state
        .set_tags(
            ctx.tenant_id,
            parse_uuid(&id, "user_id")?,
            &input.tags,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(tags)))
}

async fn batch_create(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(inputs): Json<Vec<CreateUserInput>>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    if inputs.iter().any(|input| input.tenant_id != ctx.tenant_id) {
        return Err(crate::shared::AppError::forbidden("不能在其他租户创建用户"));
    }
    let result = state
        .batch_create(inputs, Some(ctx.identity_id), &meta(&state, &headers))
        .await?;
    Ok(ok(json!(result)))
}

async fn batch_update(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(items): Json<Vec<BatchUpdateItem>>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let result = state
        .batch_update(
            ctx.tenant_id,
            items,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(result)))
}

async fn import_users(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<ImportInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let result = state
        .import_users_csv(
            ctx.tenant_id,
            &input.content,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(result)))
}

async fn export_users(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Query(query): Query<UserListQuery>,
) -> AppResult<Response> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let csv = state.export_users_csv(ctx.tenant_id, &query).await?;
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/csv; charset=utf-8"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"users.csv\""),
            ),
        ],
        csv,
    )
        .into_response())
}

async fn user_contacts(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let contacts = state
        .list_contacts(ctx.tenant_id, parse_uuid(&id, "user_id")?)
        .await?;
    Ok(ok(json!(contacts)))
}

async fn unbind_contact(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path((id, kind)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let contacts = state
        .unbind_contact(
            ctx.tenant_id,
            parse_uuid(&id, "user_id")?,
            &kind,
            &meta(&state, &headers),
            Some(ctx.identity_id),
        )
        .await?;
    Ok(ok(json!(contacts)))
}

async fn user_attributes(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let values = state
        .list_user_attribute_values(ctx.tenant_id, parse_uuid(&id, "user_id")?)
        .await?;
    Ok(ok(json!(values)))
}

async fn set_user_attributes(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<AttributeValuesInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let values = state
        .set_user_attribute_values(
            ctx.tenant_id,
            parse_uuid(&id, "user_id")?,
            &input.values,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(values)))
}

async fn user_groups(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let groups = state
        .list_user_groups(ctx.tenant_id, parse_uuid(&id, "user_id")?)
        .await?;
    Ok(ok(json!(groups)))
}

async fn user_memberships(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let memberships = state
        .list_user_memberships(ctx.tenant_id, parse_uuid(&id, "user_id")?)
        .await?;
    Ok(ok(json!(memberships)))
}

async fn user_history(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let history = state
        .list_user_org_history(ctx.tenant_id, parse_uuid(&id, "user_id")?)
        .await?;
    Ok(ok(json!(history)))
}

async fn user_status_history(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let history = state
        .list_status_history(ctx.tenant_id, parse_uuid(&id, "user_id")?)
        .await?;
    Ok(ok(json!(history)))
}

async fn user_registration(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let record = state
        .user_registration(ctx.tenant_id, parse_uuid(&id, "user_id")?)
        .await?;
    Ok(ok(json!(record)))
}

async fn user_links(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let links = state
        .list_account_links(ctx.tenant_id, parse_uuid(&id, "user_id")?)
        .await?;
    Ok(ok(json!(links)))
}

async fn add_user_link(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<AccountLinkInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let link = state
        .add_account_link(
            ctx.tenant_id,
            parse_uuid(&id, "user_id")?,
            &input,
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(link)))
}

async fn remove_user_link(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path((id, provider)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    state
        .remove_account_link(
            ctx.tenant_id,
            parse_uuid(&id, "user_id")?,
            &provider,
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "removed": true })))
}

// ───────────────────────── 扩展属性 ─────────────────────────

async fn list_attributes(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Query(page): Query<PageQuery>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let result = state.list_attributes(ctx.tenant_id, &page).await?;
    Ok(ok(json!(result)))
}

async fn create_attribute(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<AttributeInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let row = state
        .create_attribute(
            ctx.tenant_id,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(row)))
}

async fn update_attribute(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<AttributeInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let row = state
        .update_attribute(
            ctx.tenant_id,
            parse_uuid(&id, "attribute_id")?,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(row)))
}

async fn delete_attribute(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    state
        .delete_attribute(
            ctx.tenant_id,
            parse_uuid(&id, "attribute_id")?,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "deleted": true })))
}

// ───────────────────────── 分组 ─────────────────────────

async fn list_groups(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Query(page): Query<PageQuery>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    Ok(ok(json!(state.list_groups(ctx.tenant_id, &page).await?)))
}

async fn group_tree(State(state): State<Arc<AppState>>, Auth(ctx): Auth) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    Ok(ok(json!(state.group_tree(ctx.tenant_id).await?)))
}

async fn create_group(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<GroupInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let row = state
        .create_group(
            ctx.tenant_id,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(row)))
}

async fn update_group(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<GroupInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let row = state
        .update_group(
            ctx.tenant_id,
            parse_uuid(&id, "group_id")?,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(row)))
}

async fn delete_group(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    state
        .delete_group(
            ctx.tenant_id,
            parse_uuid(&id, "group_id")?,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "deleted": true })))
}

async fn group_members(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    Query(page): Query<PageQuery>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let result = state
        .list_group_members(ctx.tenant_id, parse_uuid(&id, "group_id")?, &page)
        .await?;
    Ok(ok(json!(result)))
}

async fn add_group_members(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<MembersInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let added = state
        .add_group_members(
            ctx.tenant_id,
            parse_uuid(&id, "group_id")?,
            &input.user_ids,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "added": added })))
}

async fn remove_group_members(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<MembersInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let removed = state
        .remove_group_members(
            ctx.tenant_id,
            parse_uuid(&id, "group_id")?,
            &input.user_ids,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "removed": removed })))
}

// ───────────────────────── 组织 ─────────────────────────

async fn list_organizations(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Query(page): Query<PageQuery>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    Ok(ok(json!(
        state.list_organizations(ctx.tenant_id, &page).await?
    )))
}

async fn organization_tree(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    Ok(ok(json!(state.organization_tree(ctx.tenant_id).await?)))
}

async fn create_organization(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<OrganizationInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let row = state
        .create_organization(
            ctx.tenant_id,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(row)))
}

async fn update_organization(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<OrganizationInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let row = state
        .update_organization(
            ctx.tenant_id,
            parse_uuid(&id, "organization_id")?,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(row)))
}

async fn delete_organization(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    state
        .delete_organization(
            ctx.tenant_id,
            parse_uuid(&id, "organization_id")?,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "deleted": true })))
}

async fn set_organization_leader(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<LeaderInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let row = state
        .set_organization_leader(
            ctx.tenant_id,
            parse_uuid(&id, "organization_id")?,
            input.leader_id,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(row)))
}

async fn organization_members(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    Query(page): Query<PageQuery>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let result = state
        .list_organization_members(ctx.tenant_id, parse_uuid(&id, "organization_id")?, &page)
        .await?;
    Ok(ok(json!(result)))
}

async fn add_organization_member(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<MemberInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    state
        .add_organization_member(
            ctx.tenant_id,
            parse_uuid(&id, "organization_id")?,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "added": true })))
}

async fn remove_organization_member(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path((id, user_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    state
        .remove_organization_member(
            ctx.tenant_id,
            parse_uuid(&id, "organization_id")?,
            parse_uuid(&user_id, "user_id")?,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "removed": true })))
}

// ───────────────────────── 部门 ─────────────────────────

async fn list_departments(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Query(query): Query<DepartmentQuery>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let page = PageQuery {
        page: query.page,
        page_size: query.page_size,
    };
    let result = state
        .list_departments(ctx.tenant_id, query.organization_id, &page)
        .await?;
    Ok(ok(json!(result)))
}

#[derive(Debug, Deserialize)]
pub struct DepartmentQuery {
    #[serde(default)]
    pub organization_id: Option<Uuid>,
    #[serde(default)]
    pub page: Option<u32>,
    #[serde(default)]
    pub page_size: Option<u32>,
}

async fn department_tree(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Query(query): Query<DepartmentQuery>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let tree = state
        .department_tree(ctx.tenant_id, query.organization_id)
        .await?;
    Ok(ok(json!(tree)))
}

async fn create_department(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    headers: HeaderMap,
    Json(input): Json<DepartmentInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let row = state
        .create_department(
            ctx.tenant_id,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(row)))
}

async fn update_department(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<DepartmentInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let row = state
        .update_department(
            ctx.tenant_id,
            parse_uuid(&id, "department_id")?,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(row)))
}

async fn delete_department(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    state
        .delete_department(
            ctx.tenant_id,
            parse_uuid(&id, "department_id")?,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "deleted": true })))
}

async fn set_department_leader(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<LeaderInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let row = state
        .set_department_leader(
            ctx.tenant_id,
            parse_uuid(&id, "department_id")?,
            input.leader_id,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(row)))
}

async fn department_members(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    Query(page): Query<PageQuery>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let result = state
        .list_department_members(ctx.tenant_id, parse_uuid(&id, "department_id")?, &page)
        .await?;
    Ok(ok(json!(result)))
}

async fn add_department_member(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<MemberInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    state
        .add_department_member(
            ctx.tenant_id,
            parse_uuid(&id, "department_id")?,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "added": true })))
}

async fn remove_department_member(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path((id, user_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    state
        .remove_department_member(
            ctx.tenant_id,
            parse_uuid(&id, "department_id")?,
            parse_uuid(&user_id, "user_id")?,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "removed": true })))
}

async fn transfer_user(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(mut input): Json<TransferInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    input.user_id = parse_uuid(&id, "user_id")?;
    state
        .transfer_user(
            ctx.tenant_id,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!({ "transferred": true })))
}

// ───────────────────────── 注册审核 ─────────────────────────

async fn list_registrations(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Query(query): Query<RegistrationListQuery>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let result = state.list_registrations(ctx.tenant_id, &query).await?;
    Ok(ok(json!(result)))
}

async fn get_registration(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let record = state
        .get_registration(ctx.tenant_id, parse_uuid(&id, "registration_id")?)
        .await?;
    Ok(ok(json!(record)))
}

async fn review_registration(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(input): Json<ReviewInput>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), ADMIN_PERMISSION).await?;
    let record = state
        .review_registration(
            ctx.tenant_id,
            parse_uuid(&id, "registration_id")?,
            &input,
            Some(ctx.identity_id),
            &meta(&state, &headers),
        )
        .await?;
    Ok(ok(json!(record)))
}

// ───────────────────────── 审计 ─────────────────────────

async fn audit_logs(
    State(state): State<Arc<AppState>>,
    Auth(ctx): Auth,
    Query(page): Query<PageQuery>,
) -> AppResult<Json<Value>> {
    guard(&state, &Auth(ctx.clone()), AUDIT_PERMISSION).await?;
    let result = state.list_audit_logs(ctx.tenant_id, &page).await?;
    Ok(ok(json!(result)))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/admin/users", get(list_users).post(create_user))
        .route(
            "/api/v1/admin/users/batch",
            post(batch_create).patch(batch_update),
        )
        .route("/api/v1/admin/users/import", post(import_users))
        .route("/api/v1/admin/users/export", get(export_users))
        .route(
            "/api/v1/admin/users/{id}",
            get(user_detail).patch(update_user).delete(delete_user),
        )
        .route("/api/v1/admin/users/{id}/profile", put(update_profile))
        .route("/api/v1/admin/users/{id}/restore", post(restore_user))
        .route("/api/v1/admin/users/{id}/status", put(change_status))
        .route("/api/v1/admin/users/{id}/tags", get(get_tags).put(set_tags))
        .route("/api/v1/admin/users/{id}/contacts", get(user_contacts))
        .route(
            "/api/v1/admin/users/{id}/contacts/{kind}",
            delete(unbind_contact),
        )
        .route(
            "/api/v1/admin/users/{id}/attributes",
            get(user_attributes).put(set_user_attributes),
        )
        .route("/api/v1/admin/users/{id}/groups", get(user_groups))
        .route(
            "/api/v1/admin/users/{id}/memberships",
            get(user_memberships),
        )
        .route("/api/v1/admin/users/{id}/history", get(user_history))
        .route(
            "/api/v1/admin/users/{id}/status-history",
            get(user_status_history),
        )
        .route(
            "/api/v1/admin/users/{id}/registration",
            get(user_registration),
        )
        .route(
            "/api/v1/admin/users/{id}/links",
            get(user_links).post(add_user_link),
        )
        .route(
            "/api/v1/admin/users/{id}/links/{provider}",
            delete(remove_user_link),
        )
        .route("/api/v1/admin/users/{id}/transfer", post(transfer_user))
        .route(
            "/api/v1/admin/attributes",
            get(list_attributes).post(create_attribute),
        )
        .route(
            "/api/v1/admin/attributes/{id}",
            patch(update_attribute).delete(delete_attribute),
        )
        .route("/api/v1/admin/groups", get(list_groups).post(create_group))
        .route("/api/v1/admin/groups/tree", get(group_tree))
        .route(
            "/api/v1/admin/groups/{id}",
            patch(update_group).delete(delete_group),
        )
        .route(
            "/api/v1/admin/groups/{id}/members",
            get(group_members)
                .post(add_group_members)
                .delete(remove_group_members),
        )
        .route(
            "/api/v1/admin/organizations",
            get(list_organizations).post(create_organization),
        )
        .route("/api/v1/admin/organizations/tree", get(organization_tree))
        .route(
            "/api/v1/admin/organizations/{id}",
            patch(update_organization).delete(delete_organization),
        )
        .route(
            "/api/v1/admin/organizations/{id}/leader",
            put(set_organization_leader),
        )
        .route(
            "/api/v1/admin/organizations/{id}/members",
            get(organization_members).post(add_organization_member),
        )
        .route(
            "/api/v1/admin/organizations/{id}/members/{user_id}",
            delete(remove_organization_member),
        )
        .route(
            "/api/v1/admin/departments",
            get(list_departments).post(create_department),
        )
        .route("/api/v1/admin/departments/tree", get(department_tree))
        .route(
            "/api/v1/admin/departments/{id}",
            patch(update_department).delete(delete_department),
        )
        .route(
            "/api/v1/admin/departments/{id}/leader",
            put(set_department_leader),
        )
        .route(
            "/api/v1/admin/departments/{id}/members",
            get(department_members).post(add_department_member),
        )
        .route(
            "/api/v1/admin/departments/{id}/members/{user_id}",
            delete(remove_department_member),
        )
        .route("/api/v1/admin/registrations", get(list_registrations))
        .route("/api/v1/admin/registrations/{id}", get(get_registration))
        .route(
            "/api/v1/admin/registrations/{id}/review",
            post(review_registration),
        )
        .route("/api/v1/admin/audit-logs", get(audit_logs))
}
