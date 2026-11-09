//! 管理端 API：身份、RBAC/ABAC/ReBAC、租户、OAuth 客户端、审计、密钥、SAML 与身份提供商。

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post, put};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::application::identity::CreateIdentityInput;
use crate::application::rbac::{
    ApiResourceInput, ButtonInput, DataPermissionInput, MenuInput, PermissionInput, PolicyInput,
    RoleInput,
};
use crate::bootstrap::AppState;
use crate::domain::AuthContext;
use crate::protocol::federation::FederationProviderInput;
use crate::protocol::saml::{SamlIdpUpdate, SamlSpInput};
use crate::shared::response::{empty, ok, Page, PageQuery};
use crate::shared::{AppError, AppResult, DEFAULT_TENANT_ID};

use super::{parse_uuid, request_meta};

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/admin/identities",
            get(list_identities).post(create_identity),
        )
        .route(
            "/api/v1/admin/identities/{id}",
            get(get_identity).patch(update_identity),
        )
        .route(
            "/api/v1/admin/identities/{id}/status",
            put(set_identity_status),
        )
        .route(
            "/api/v1/admin/identities/{id}/roles",
            get(list_user_roles).post(assign_role),
        )
        .route(
            "/api/v1/admin/identities/{id}/roles/{role_id}",
            delete(revoke_role),
        )
        .route(
            "/api/v1/admin/identities/{id}/permissions",
            post(grant_user_permission),
        )
        .route(
            "/api/v1/admin/identities/{id}/permissions/{permission_id}",
            delete(revoke_user_permission),
        )
        .route("/api/v1/admin/identities/{id}/mfa/reset", post(reset_mfa))
        .route("/api/v1/admin/roles", get(list_roles).post(create_role))
        .route(
            "/api/v1/admin/roles/{id}",
            get(get_role).patch(update_role).delete(delete_role),
        )
        .route(
            "/api/v1/admin/roles/{id}/permissions",
            get(list_role_permissions).put(set_role_permissions),
        )
        .route("/api/v1/admin/roles/{id}/members", get(list_role_members))
        .route("/api/v1/admin/roles/{id}/assign", post(batch_assign_roles))
        .route(
            "/api/v1/admin/permissions",
            get(list_permissions).post(create_permission),
        )
        .route("/api/v1/admin/permissions/tree", get(permission_tree))
        .route(
            "/api/v1/admin/permissions/{id}",
            get(get_permission)
                .patch(update_permission)
                .delete(delete_permission),
        )
        .route(
            "/api/v1/admin/api-resources",
            get(list_api_resources).post(create_api_resource),
        )
        .route(
            "/api/v1/admin/api-resources/{id}",
            patch(update_api_resource).delete(delete_api_resource),
        )
        .route("/api/v1/admin/menus", get(list_menus).post(create_menu))
        .route(
            "/api/v1/admin/menus/{id}",
            patch(update_menu).delete(delete_menu),
        )
        .route(
            "/api/v1/admin/buttons",
            get(list_buttons).post(create_button),
        )
        .route("/api/v1/admin/buttons/{id}", delete(delete_button))
        .route(
            "/api/v1/admin/data-permissions",
            get(list_data_permissions).post(create_data_permission),
        )
        .route(
            "/api/v1/admin/data-permissions/{id}",
            delete(delete_data_permission),
        )
        .route(
            "/api/v1/admin/policies",
            get(list_policies).post(create_policy),
        )
        .route("/api/v1/admin/policies/{id}", delete(delete_policy))
        .route(
            "/api/v1/admin/resource-relations",
            get(list_resource_relations).post(add_resource_relation),
        )
        .route(
            "/api/v1/admin/resource-relations/{id}",
            delete(remove_resource_relation),
        )
        .route(
            "/api/v1/admin/tenants",
            get(list_tenants).post(create_tenant),
        )
        .route("/api/v1/admin/tenants/{id}/status", put(set_tenant_status))
        .route(
            "/api/v1/admin/oauth/clients",
            get(list_oauth_clients).post(create_oauth_client),
        )
        .route(
            "/api/v1/admin/oauth/clients/{client_id}/secret",
            post(rotate_client_secret),
        )
        .route(
            "/api/v1/admin/oauth/clients/{client_id}/status",
            put(set_client_status),
        )
        .route(
            "/api/v1/admin/oauth/scopes",
            get(list_oauth_scopes).post(create_oauth_scope),
        )
        .route("/api/v1/admin/audit-logs", get(list_audit_logs))
        .route(
            "/api/v1/admin/signing-keys",
            get(list_signing_keys).post(rotate_signing_key),
        )
        .route(
            "/api/v1/admin/saml/idp",
            get(get_saml_idp).put(update_saml_idp),
        )
        .route(
            "/api/v1/admin/saml/idp/rotate-certificate",
            post(rotate_saml_certificate),
        )
        .route(
            "/api/v1/admin/saml/sps",
            get(list_saml_sps).post(upsert_saml_sp),
        )
        .route(
            "/api/v1/admin/saml/sps/{code}",
            get(get_saml_sp).delete(delete_saml_sp),
        )
        .route(
            "/api/v1/admin/identity-providers",
            get(list_identity_providers).post(upsert_identity_provider),
        )
        .route(
            "/api/v1/admin/identity-providers/{code}",
            get(get_identity_provider).delete(delete_identity_provider),
        )
}

// ───────────────────────── 身份 ─────────────────────────

#[derive(Debug, Deserialize)]
pub struct IdentityQuery {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    keyword: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

impl IdentityQuery {
    fn page_query(&self) -> PageQuery {
        PageQuery {
            page: self.page,
            page_size: self.page_size,
        }
    }
}

pub async fn list_identities(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<IdentityQuery>,
) -> AppResult<Response> {
    let page = query.page_query();
    let keyword = query
        .keyword
        .as_deref()
        .map(|value| format!("%{}%", value.trim()))
        .unwrap_or_else(|| "%".to_string());
    let status = query.status.unwrap_or_default();
    let rows = sqlx::query_as::<_, crate::domain::Identity>(
        "SELECT * FROM identities
         WHERE tenant_id = $1 AND deleted_at IS NULL
           AND (lower(username) LIKE lower($2) OR lower(COALESCE(email, '')) LIKE lower($2)
                OR lower(COALESCE(display_name, '')) LIKE lower($2))
           AND ($3 = '' OR status = $3)
         ORDER BY created_at DESC LIMIT $4 OFFSET $5",
    )
    .bind(ctx.tenant_id)
    .bind(&keyword)
    .bind(&status)
    .bind(page.limit())
    .bind(page.offset())
    .fetch_all(&state.pool)
    .await?;
    let total: (i64,) = sqlx::query_as(
        "SELECT count(*) FROM identities
         WHERE tenant_id = $1 AND deleted_at IS NULL
           AND (lower(username) LIKE lower($2) OR lower(COALESCE(email, '')) LIKE lower($2)
                OR lower(COALESCE(display_name, '')) LIKE lower($2))
           AND ($3 = '' OR status = $3)",
    )
    .bind(ctx.tenant_id)
    .bind(&keyword)
    .bind(&status)
    .fetch_one(&state.pool)
    .await?;
    Ok(ok(Page::new(rows, total.0, &page)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct AdminCreateIdentity {
    #[serde(default)]
    tenant_id: Option<Uuid>,
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
    metadata: Option<Value>,
}

pub async fn create_identity(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(body): Json<AdminCreateIdentity>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let identity = state
        .create_identity(
            CreateIdentityInput {
                tenant_id: body.tenant_id.unwrap_or(ctx.tenant_id),
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
                source: "admin".to_string(),
            },
            &meta,
        )
        .await?;
    Ok(ok(json!({ "identity": identity })).into_response())
}

pub async fn get_identity(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let identity = state.get_identity(parse_uuid(&id, "identity_id")?).await?;
    if identity.tenant_id != ctx.tenant_id && ctx.tenant_id != DEFAULT_TENANT_ID {
        return Err(AppError::forbidden("无权访问其他租户身份"));
    }
    Ok(ok(json!({ "identity": identity })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct UpdateIdentityRequest {
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    avatar_url: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    phone: Option<String>,
    #[serde(default)]
    mfa_enforced: Option<bool>,
    #[serde(default)]
    metadata: Option<Value>,
}

pub async fn update_identity(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Path(id): Path<String>,
    Json(body): Json<UpdateIdentityRequest>,
) -> AppResult<Response> {
    let identity_id = parse_uuid(&id, "identity_id")?;
    let identity = state.get_identity(identity_id).await?;
    if identity.tenant_id != ctx.tenant_id {
        return Err(AppError::forbidden("无权操作其他租户身份"));
    }
    sqlx::query(
        "UPDATE identities SET
            display_name = COALESCE($2, display_name),
            avatar_url = COALESCE($3, avatar_url),
            email = COALESCE($4, email),
            phone = COALESCE($5, phone),
            mfa_enforced = COALESCE($6, mfa_enforced),
            metadata = COALESCE($7, metadata),
            version = version + 1,
            updated_at = now()
         WHERE id = $1",
    )
    .bind(identity_id)
    .bind(body.display_name)
    .bind(body.avatar_url)
    .bind(body.email)
    .bind(body.phone)
    .bind(body.mfa_enforced)
    .bind(body.metadata)
    .execute(&state.pool)
    .await?;
    let identity = state.get_identity(identity_id).await?;
    Ok(ok(json!({ "identity": identity })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct StatusRequest {
    status: String,
    #[serde(default)]
    reason: Option<String>,
}

pub async fn set_identity_status(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<StatusRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let identity = state
        .update_identity_status(
            parse_uuid(&id, "identity_id")?,
            &body.status,
            body.reason,
            Some(ctx.identity_id),
            &meta,
        )
        .await?;
    Ok(ok(json!({ "identity": identity })).into_response())
}

pub async fn list_user_roles(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let roles = state
        .list_user_roles(ctx.tenant_id, parse_uuid(&id, "identity_id")?)
        .await?;
    Ok(ok(json!({ "items": roles })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    role_id: Uuid,
    #[serde(default)]
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn assign_role(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<AssignRoleRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let id = state
        .assign_role(
            ctx.tenant_id,
            parse_uuid(&id, "identity_id")?,
            body.role_id,
            None,
            body.valid_until,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "id": id })).into_response())
}

pub async fn revoke_role(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path((id, role_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let count = state
        .revoke_role(
            ctx.tenant_id,
            parse_uuid(&id, "identity_id")?,
            parse_uuid(&role_id, "role_id")?,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "revoked": count })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct GrantPermissionRequest {
    permission_id: Uuid,
    #[serde(default = "default_effect")]
    effect: String,
    #[serde(default)]
    valid_until: Option<chrono::DateTime<chrono::Utc>>,
}

fn default_effect() -> String {
    "allow".to_string()
}

pub async fn grant_user_permission(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<GrantPermissionRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .grant_user_permission(
            ctx.tenant_id,
            parse_uuid(&id, "identity_id")?,
            body.permission_id,
            &body.effect,
            body.valid_until,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(empty().into_response())
}

pub async fn revoke_user_permission(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path((id, permission_id)): Path<(String, String)>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .revoke_user_permission(
            ctx.tenant_id,
            parse_uuid(&id, "identity_id")?,
            parse_uuid(&permission_id, "permission_id")?,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(empty().into_response())
}

#[derive(Debug, Deserialize, Default)]
pub struct ResetMfaRequest {
    #[serde(default)]
    reason: Option<String>,
}

pub async fn reset_mfa(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<ResetMfaRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .admin_reset_mfa(
            parse_uuid(&id, "identity_id")?,
            ctx.identity_id,
            &meta,
            body.reason,
        )
        .await?;
    Ok(empty().into_response())
}

// ───────────────────────── 角色 ─────────────────────────

#[derive(Debug, Deserialize)]
pub struct RoleQuery {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    keyword: Option<String>,
}

pub async fn list_roles(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<RoleQuery>,
) -> AppResult<Response> {
    let page = PageQuery {
        page: query.page,
        page_size: query.page_size,
    };
    let (roles, total) = state
        .list_roles(ctx.tenant_id, &page, query.keyword.as_deref())
        .await?;
    Ok(ok(Page::new(roles, total, &page)).into_response())
}

pub async fn get_role(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let role = state
        .get_role(ctx.tenant_id, parse_uuid(&id, "role_id")?)
        .await?;
    Ok(ok(json!({ "role": role })).into_response())
}

pub async fn create_role(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(input): Json<RoleInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let role = state
        .create_role(ctx.tenant_id, input, ctx.identity_id, &meta)
        .await?;
    Ok(ok(json!({ "role": role })).into_response())
}

pub async fn update_role(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<RoleInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let role = state
        .update_role(
            ctx.tenant_id,
            parse_uuid(&id, "role_id")?,
            input,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "role": role })).into_response())
}

pub async fn delete_role(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .delete_role(
            ctx.tenant_id,
            parse_uuid(&id, "role_id")?,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(empty().into_response())
}

pub async fn list_role_permissions(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let items = state
        .list_role_permissions(parse_uuid(&id, "role_id")?)
        .await?;
    Ok(ok(json!({ "items": items })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct SetPermissionsRequest {
    permission_ids: Vec<Uuid>,
}

pub async fn set_role_permissions(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<SetPermissionsRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let count = state
        .set_role_permissions(
            ctx.tenant_id,
            parse_uuid(&id, "role_id")?,
            &body.permission_ids,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "updated": count })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct MemberQuery {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    page_size: Option<u32>,
}

pub async fn list_role_members(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(query): Query<MemberQuery>,
) -> AppResult<Response> {
    let page = PageQuery {
        page: query.page,
        page_size: query.page_size,
    };
    let (members, total) = state
        .list_role_members(parse_uuid(&id, "role_id")?, &page)
        .await?;
    Ok(ok(Page::new(members, total, &page)).into_response())
}

#[derive(Debug, Deserialize)]
pub struct BatchAssignRequest {
    identity_ids: Vec<Uuid>,
}

pub async fn batch_assign_roles(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<BatchAssignRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let count = state
        .batch_assign_roles(
            ctx.tenant_id,
            parse_uuid(&id, "role_id")?,
            &body.identity_ids,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "assigned": count })).into_response())
}

// ───────────────────────── 权限 ─────────────────────────

#[derive(Debug, Deserialize)]
pub struct KeywordQuery {
    #[serde(default)]
    keyword: Option<String>,
}

pub async fn list_permissions(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<KeywordQuery>,
) -> AppResult<Response> {
    let items = state
        .list_permissions(ctx.tenant_id, query.keyword.as_deref())
        .await?;
    Ok(ok(json!({ "items": items })).into_response())
}

pub async fn permission_tree(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    let items = state.permission_tree(ctx.tenant_id).await?;
    Ok(ok(json!({ "items": items })).into_response())
}

pub async fn get_permission(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let permission = state
        .get_permission(ctx.tenant_id, parse_uuid(&id, "permission_id")?)
        .await?;
    Ok(ok(json!({ "permission": permission })).into_response())
}

pub async fn create_permission(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(input): Json<PermissionInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let permission = state
        .create_permission(ctx.tenant_id, input, ctx.identity_id, &meta)
        .await?;
    Ok(ok(json!({ "permission": permission })).into_response())
}

pub async fn update_permission(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<PermissionInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let permission = state
        .update_permission(
            ctx.tenant_id,
            parse_uuid(&id, "permission_id")?,
            input,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "permission": permission })).into_response())
}

pub async fn delete_permission(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .delete_permission(
            ctx.tenant_id,
            parse_uuid(&id, "permission_id")?,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(empty().into_response())
}

// ───────────────────────── API / 菜单 / 按钮 / 数据权限 ─────────────────────────

pub async fn list_api_resources(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    Ok(ok(json!({ "items": state.list_api_resources(ctx.tenant_id).await? })).into_response())
}

pub async fn create_api_resource(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(input): Json<ApiResourceInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let item = state
        .create_api_resource(ctx.tenant_id, input, ctx.identity_id, &meta)
        .await?;
    Ok(ok(json!({ "item": item })).into_response())
}

pub async fn update_api_resource(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ApiResourceInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let item = state
        .update_api_resource(
            ctx.tenant_id,
            parse_uuid(&id, "api_resource_id")?,
            input,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "item": item })).into_response())
}

pub async fn delete_api_resource(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .delete_api_resource(
            ctx.tenant_id,
            parse_uuid(&id, "api_resource_id")?,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(empty().into_response())
}

pub async fn list_menus(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    Ok(ok(json!({ "items": state.list_menus(ctx.tenant_id).await? })).into_response())
}

pub async fn create_menu(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(input): Json<MenuInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let item = state
        .create_menu(ctx.tenant_id, input, ctx.identity_id, &meta)
        .await?;
    Ok(ok(json!({ "item": item })).into_response())
}

pub async fn update_menu(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<MenuInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let item = state
        .update_menu(
            ctx.tenant_id,
            parse_uuid(&id, "menu_id")?,
            input,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "item": item })).into_response())
}

pub async fn delete_menu(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .delete_menu(
            ctx.tenant_id,
            parse_uuid(&id, "menu_id")?,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(empty().into_response())
}

pub async fn list_buttons(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    Ok(ok(json!({ "items": state.list_buttons(ctx.tenant_id).await? })).into_response())
}

pub async fn create_button(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(input): Json<ButtonInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let item = state
        .create_button(ctx.tenant_id, input, ctx.identity_id, &meta)
        .await?;
    Ok(ok(json!({ "item": item })).into_response())
}

pub async fn delete_button(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .delete_button(
            ctx.tenant_id,
            parse_uuid(&id, "button_id")?,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(empty().into_response())
}

pub async fn list_data_permissions(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    Ok(ok(json!({ "items": state.list_data_permissions(ctx.tenant_id).await? })).into_response())
}

pub async fn create_data_permission(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(input): Json<DataPermissionInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let item = state
        .create_data_permission(ctx.tenant_id, input, ctx.identity_id, &meta)
        .await?;
    Ok(ok(json!({ "item": item })).into_response())
}

pub async fn delete_data_permission(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .delete_data_permission(
            ctx.tenant_id,
            parse_uuid(&id, "data_permission_id")?,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(empty().into_response())
}

// ───────────────────────── 策略 / 资源关系 ─────────────────────────

pub async fn list_policies(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    Ok(ok(json!({ "items": state.list_policies(ctx.tenant_id).await? })).into_response())
}

pub async fn create_policy(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(input): Json<PolicyInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let item = state
        .create_policy(ctx.tenant_id, input, ctx.identity_id, &meta)
        .await?;
    Ok(ok(json!({ "item": item })).into_response())
}

pub async fn delete_policy(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .delete_policy(
            ctx.tenant_id,
            parse_uuid(&id, "policy_id")?,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(empty().into_response())
}

#[derive(Debug, Deserialize)]
pub struct RelationQuery {
    resource_type: String,
    resource_id: String,
}

pub async fn list_resource_relations(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<RelationQuery>,
) -> AppResult<Response> {
    let items = state
        .list_resource_relations(ctx.tenant_id, &query.resource_type, &query.resource_id)
        .await?;
    Ok(ok(json!({ "items": items })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct RelationInput {
    resource_type: String,
    resource_id: String,
    relation: String,
    subject_type: String,
    subject_id: String,
    #[serde(default)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

pub async fn add_resource_relation(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(body): Json<RelationInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let id = state
        .add_resource_relation(
            ctx.tenant_id,
            &body.resource_type,
            &body.resource_id,
            &body.relation,
            &body.subject_type,
            &body.subject_id,
            body.expires_at,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "id": id })).into_response())
}

pub async fn remove_resource_relation(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    state
        .remove_resource_relation(
            ctx.tenant_id,
            parse_uuid(&id, "relation_id")?,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(empty().into_response())
}

// ───────────────────────── 租户 ─────────────────────────

pub async fn list_tenants(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    Ok(ok(json!({ "items": state.list_tenants().await? })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct TenantInput {
    code: String,
    name: String,
}

pub async fn create_tenant(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(body): Json<TenantInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let tenant = state
        .create_tenant(&body.code, &body.name, ctx.identity_id, &meta)
        .await?;
    Ok(ok(json!({ "tenant": tenant })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct TenantStatusRequest {
    status: String,
}

pub async fn set_tenant_status(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(body): Json<TenantStatusRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let tenant = state
        .set_tenant_status(
            parse_uuid(&id, "tenant_id")?,
            &body.status,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "tenant": tenant })).into_response())
}

// ───────────────────────── OAuth 客户端 / scope ─────────────────────────

pub async fn list_oauth_clients(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    Ok(ok(json!({ "items": state.list_oauth_clients(ctx.tenant_id).await? })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct OAuthClientInput {
    #[serde(default)]
    client_id: Option<String>,
    name: String,
    #[serde(default = "default_kind")]
    kind: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    post_logout_redirect_uris: Vec<String>,
    #[serde(default)]
    grant_types: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
    #[serde(default = "default_true")]
    require_pkce: bool,
}

fn default_kind() -> String {
    "confidential".to_string()
}

fn default_true() -> bool {
    true
}

pub async fn create_oauth_client(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(body): Json<OAuthClientInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let grant_types = if body.grant_types.is_empty() {
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]
    } else {
        body.grant_types
    };
    let scopes = if body.scopes.is_empty() {
        state
            .config
            .oauth
            .default_scope
            .split_whitespace()
            .map(str::to_string)
            .collect()
    } else {
        body.scopes
    };
    let (client, secret) = state
        .create_oauth_client(
            ctx.tenant_id,
            body.client_id,
            &body.name,
            &body.kind,
            body.redirect_uris,
            body.post_logout_redirect_uris,
            grant_types,
            scopes,
            body.require_pkce,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "client": client, "client_secret": secret })).into_response())
}

pub async fn rotate_client_secret(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(client_id): Path<String>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let secret = state
        .rotate_client_secret(ctx.tenant_id, &client_id, ctx.identity_id, &meta)
        .await?;
    Ok(ok(json!({ "client_secret": secret })).into_response())
}

pub async fn set_client_status(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Path(client_id): Path<String>,
    Json(body): Json<TenantStatusRequest>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let client = state
        .set_client_status(
            ctx.tenant_id,
            &client_id,
            &body.status,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "client": client })).into_response())
}

pub async fn list_oauth_scopes(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
) -> AppResult<Response> {
    Ok(ok(json!({ "items": state.list_oauth_scopes(ctx.tenant_id).await? })).into_response())
}

#[derive(Debug, Deserialize)]
pub struct ScopeInput {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    is_default: bool,
}

pub async fn create_oauth_scope(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
    Json(body): Json<ScopeInput>,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let scope = state
        .create_oauth_scope(
            ctx.tenant_id,
            &body.name,
            body.description,
            body.is_default,
            ctx.identity_id,
            &meta,
        )
        .await?;
    Ok(ok(json!({ "scope": scope })).into_response())
}

// ───────────────────────── 审计 / 密钥 ─────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    page_size: Option<u32>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    actor_id: Option<Uuid>,
    #[serde(default)]
    result: Option<String>,
    #[serde(default)]
    all_tenants: Option<bool>,
}

pub async fn list_audit_logs(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<AuditQuery>,
) -> AppResult<Response> {
    let page = PageQuery {
        page: query.page,
        page_size: query.page_size,
    };
    let tenant = if query.all_tenants.unwrap_or(false) && ctx.tenant_id == DEFAULT_TENANT_ID {
        None
    } else {
        Some(ctx.tenant_id)
    };
    let (items, total) = state
        .list_audit_logs(
            tenant,
            query.action.as_deref(),
            query.actor_id,
            query.result.as_deref(),
            &page,
        )
        .await?;
    Ok(ok(Page::new(items, total, &page)).into_response())
}

pub async fn list_signing_keys(State(state): State<Arc<AppState>>) -> AppResult<Response> {
    Ok(ok(json!({ "items": state.list_signing_keys().await? })).into_response())
}

pub async fn rotate_signing_key(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    headers: HeaderMap,
) -> AppResult<Response> {
    let meta = request_meta(&state, &headers);
    let kid = state.rotate_signing_key(ctx.identity_id, &meta).await?;
    Ok(ok(json!({ "kid": kid })).into_response())
}

// ───────────────────────── SAML ─────────────────────────

#[derive(Debug, Deserialize)]
pub struct TenantQuery {
    #[serde(default)]
    tenant: Option<Uuid>,
}

pub async fn get_saml_idp(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<TenantQuery>,
) -> AppResult<Response> {
    let config = state
        .saml_idp_config(query.tenant.unwrap_or(ctx.tenant_id))
        .await?;
    Ok(ok(json!({ "config": config })).into_response())
}

pub async fn update_saml_idp(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<TenantQuery>,
    Json(input): Json<SamlIdpUpdate>,
) -> AppResult<Response> {
    let config = state
        .saml_update_idp_config(query.tenant.unwrap_or(ctx.tenant_id), input)
        .await?;
    Ok(ok(json!({ "config": config })).into_response())
}

pub async fn rotate_saml_certificate(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<TenantQuery>,
) -> AppResult<Response> {
    let config = state
        .saml_rotate_idp_certificate(query.tenant.unwrap_or(ctx.tenant_id))
        .await?;
    Ok(ok(json!({ "config": config })).into_response())
}

pub async fn list_saml_sps(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<TenantQuery>,
) -> AppResult<Response> {
    let items = state
        .saml_list_sp(query.tenant.unwrap_or(ctx.tenant_id))
        .await?;
    Ok(ok(json!({ "items": items })).into_response())
}

pub async fn upsert_saml_sp(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<TenantQuery>,
    Json(input): Json<SamlSpInput>,
) -> AppResult<Response> {
    let item = state
        .saml_upsert_sp(query.tenant.unwrap_or(ctx.tenant_id), input)
        .await?;
    Ok(ok(json!({ "item": item })).into_response())
}

pub async fn get_saml_sp(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<TenantQuery>,
    Path(code): Path<String>,
) -> AppResult<Response> {
    let item = state
        .saml_get_sp(query.tenant.unwrap_or(ctx.tenant_id), &code)
        .await?;
    Ok(ok(json!({ "item": item })).into_response())
}

pub async fn delete_saml_sp(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<TenantQuery>,
    Path(code): Path<String>,
) -> AppResult<Response> {
    state
        .saml_delete_sp(query.tenant.unwrap_or(ctx.tenant_id), &code)
        .await?;
    Ok(empty().into_response())
}

// ───────────────────────── 身份提供商 ─────────────────────────

pub async fn list_identity_providers(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<TenantQuery>,
) -> AppResult<Response> {
    let items = state
        .federation_list_providers(query.tenant.unwrap_or(ctx.tenant_id))
        .await?;
    Ok(ok(json!({ "items": items })).into_response())
}

pub async fn upsert_identity_provider(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<TenantQuery>,
    Json(input): Json<FederationProviderInput>,
) -> AppResult<Response> {
    let provider = state
        .federation_upsert_provider(query.tenant.unwrap_or(ctx.tenant_id), input)
        .await?;
    Ok(ok(json!({ "provider": provider })).into_response())
}

pub async fn get_identity_provider(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<TenantQuery>,
    Path(code): Path<String>,
) -> AppResult<Response> {
    let provider = state
        .federation_provider(query.tenant.unwrap_or(ctx.tenant_id), &code)
        .await?;
    Ok(ok(json!({ "provider": provider })).into_response())
}

pub async fn delete_identity_provider(
    State(state): State<Arc<AppState>>,
    ctx: AuthContext,
    Query(query): Query<TenantQuery>,
    Path(code): Path<String>,
) -> AppResult<Response> {
    state
        .federation_delete_provider(query.tenant.unwrap_or(ctx.tenant_id), &code)
        .await?;
    Ok(empty().into_response())
}
