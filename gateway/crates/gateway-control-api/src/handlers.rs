//! Admin API handlers。
//!
//! 每个 handler 只做三件事：解析参数 → 调用 [`ConfigService`] → 转换 DTO。
//! 认证通过 [`crate::auth::Principal`] 提取器完成；写操作显式调用
//! `require_admin()` 实现 RBAC。

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use gateway_control_service::Page;
use gateway_storage::ResourceKind;

use crate::auth::Principal;
use crate::dto::{
    AuditLogView, CreateResourceRequest, CurrentConfigView, DeleteQuery, HealthView, PageQuery,
    PageView, PublishRecordView, PublishRequest, PublishView, ResourceView, StatusView,
    UpdateResourceRequest, VersionView,
};
use crate::error::ApiError;
use crate::state::AdminState;

// ---------------------------------------------------------------------------
// 健康检查 / 状态
// ---------------------------------------------------------------------------

/// 控制面健康检查（无需认证，便于探活）。
pub async fn health() -> Json<HealthView> {
    Json(HealthView { status: "ok" })
}

/// 控制面状态：最新已发布版本。
pub async fn status(
    State(state): State<AdminState>,
    _principal: Principal,
) -> Result<Json<StatusView>, ApiError> {
    let latest = state.service.latest_version().await?;
    Ok(Json(StatusView {
        service: "gateway-control",
        published_version: latest.as_ref().map(|v| v.version),
        published_checksum: latest.as_ref().map(|v| v.checksum.clone()),
        has_configuration: latest.is_some(),
    }))
}

// ---------------------------------------------------------------------------
// 资源 CRUD
// ---------------------------------------------------------------------------

/// 列出某类资源。
pub async fn list_resources(
    State(state): State<AdminState>,
    _principal: Principal,
    Path(kind): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Json<PageView<ResourceView>>, ApiError> {
    let kind = parse_kind(&kind)?;
    let page: Page<gateway_storage::StoredResource> = state
        .service
        .list_resources(kind, query.limit(), query.offset())
        .await?;
    Ok(Json(map_page(page, ResourceView::from)))
}

/// 查询单个资源。
pub async fn get_resource(
    State(state): State<AdminState>,
    _principal: Principal,
    Path((kind, id)): Path<(String, String)>,
) -> Result<Json<ResourceView>, ApiError> {
    let kind = parse_kind(&kind)?;
    let resource = state.service.get_resource(kind, &id).await?;
    Ok(Json(ResourceView::from(resource)))
}

/// 创建资源（需要 admin）。
pub async fn create_resource(
    State(state): State<AdminState>,
    principal: Principal,
    Path(kind): Path<String>,
    Json(body): Json<CreateResourceRequest>,
) -> Result<(StatusCode, Json<ResourceView>), ApiError> {
    principal.require_admin()?;
    let kind = parse_kind(&kind)?;
    let created = state
        .service
        .create_resource(
            kind,
            gateway_storage::ResourceDraft {
                id: body.id,
                name: body.name,
                enabled: body.enabled,
                payload: body.payload,
            },
            &principal.actor,
        )
        .await?;
    Ok((StatusCode::CREATED, Json(ResourceView::from(created))))
}

/// 更新资源（需要 admin）。
pub async fn update_resource(
    State(state): State<AdminState>,
    principal: Principal,
    Path((kind, id)): Path<(String, String)>,
    Json(body): Json<UpdateResourceRequest>,
) -> Result<Json<ResourceView>, ApiError> {
    principal.require_admin()?;
    let kind = parse_kind(&kind)?;
    let updated = state
        .service
        .update_resource(
            kind,
            &id,
            gateway_storage::ResourceUpdate {
                name: body.name,
                enabled: body.enabled,
                payload: body.payload,
                expected_version: body.expected_version,
            },
            &principal.actor,
        )
        .await?;
    Ok(Json(ResourceView::from(updated)))
}

/// 删除资源（需要 admin）。
pub async fn delete_resource(
    State(state): State<AdminState>,
    principal: Principal,
    Path((kind, id)): Path<(String, String)>,
    Query(query): Query<DeleteQuery>,
) -> Result<StatusCode, ApiError> {
    principal.require_admin()?;
    let kind = parse_kind(&kind)?;
    state
        .service
        .delete_resource(kind, &id, query.expected_version, &principal.actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// 配置查询 / 校验 / 编译 / 发布 / 回滚
// ---------------------------------------------------------------------------

/// 当前已发布配置（GET /config）。
///
/// 尚未发布过任何版本时返回 404。
pub async fn current_config(
    State(state): State<AdminState>,
    _principal: Principal,
) -> Result<Json<CurrentConfigView>, ApiError> {
    let latest = state
        .service
        .latest_version()
        .await?
        .ok_or_else(|| ApiError::not_found("no configuration has been published yet"))?;
    Ok(Json(CurrentConfigView::from(latest)))
}

/// 发布前 dry-run 校验。
pub async fn validate_config(
    State(state): State<AdminState>,
    _principal: Principal,
) -> Result<Json<gateway_control_service::ValidationReport>, ApiError> {
    Ok(Json(state.service.validate().await?))
}

/// 编译预览：返回将要下发的快照，但不写版本、不应用数据面。
pub async fn compile_config(
    State(state): State<AdminState>,
    _principal: Principal,
) -> Result<Json<gateway_control_service::CompilePreview>, ApiError> {
    Ok(Json(state.service.compile().await?))
}

/// 发布当前资源集合（需要 admin）。
pub async fn publish(
    State(state): State<AdminState>,
    principal: Principal,
    Json(body): Json<PublishRequest>,
) -> Result<Json<PublishView>, ApiError> {
    principal.require_admin()?;
    let outcome = state.service.publish(&principal.actor, body.note).await?;
    Ok(Json(PublishView::from(outcome)))
}

/// 回滚到历史版本（需要 admin）。目标版本号来自路径。
pub async fn rollback(
    State(state): State<AdminState>,
    principal: Principal,
    Path(version): Path<u64>,
    body: Option<Json<PublishRequest>>,
) -> Result<Json<PublishView>, ApiError> {
    principal.require_admin()?;
    // 请求体可省略：没有 body 时使用自动生成的备注
    let note = body.and_then(|Json(request)| request.note);
    let outcome = state
        .service
        .rollback(version, &principal.actor, note)
        .await?;
    Ok(Json(PublishView::from(outcome)))
}

// ---------------------------------------------------------------------------
// 版本 / 审计 / 应用记录
// ---------------------------------------------------------------------------

/// 历史版本列表。
pub async fn list_versions(
    State(state): State<AdminState>,
    _principal: Principal,
    Query(query): Query<PageQuery>,
) -> Result<Json<PageView<VersionView>>, ApiError> {
    let page = state
        .service
        .list_versions(query.limit(), query.offset())
        .await?;
    Ok(Json(map_page(page, VersionView::from)))
}

/// 最新版本。
pub async fn latest_version(
    State(state): State<AdminState>,
    _principal: Principal,
) -> Result<Json<Option<VersionView>>, ApiError> {
    let latest = state.service.latest_version().await?;
    Ok(Json(latest.map(VersionView::from)))
}

/// 指定版本。
pub async fn get_version(
    State(state): State<AdminState>,
    _principal: Principal,
    Path(version): Path<u64>,
) -> Result<Json<VersionView>, ApiError> {
    let record = state.service.get_version(version).await?;
    Ok(Json(VersionView::from(record)))
}

/// 审计日志。
pub async fn list_audit_logs(
    State(state): State<AdminState>,
    _principal: Principal,
    Query(query): Query<PageQuery>,
) -> Result<Json<PageView<AuditLogView>>, ApiError> {
    let page = state
        .service
        .list_audit_logs(query.version, query.limit(), query.offset())
        .await?;
    Ok(Json(map_page(page, AuditLogView::from)))
}

/// 实例应用记录。
pub async fn list_publish_records(
    State(state): State<AdminState>,
    _principal: Principal,
    Query(query): Query<PageQuery>,
) -> Result<Json<PageView<PublishRecordView>>, ApiError> {
    let page = state
        .service
        .list_publish_records(query.version, query.limit(), query.offset())
        .await?;
    Ok(Json(map_page(page, PublishRecordView::from)))
}

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

/// 解析路径中的资源类型。
fn parse_kind(kind: &str) -> Result<ResourceKind, ApiError> {
    ResourceKind::from_api_name(kind)
        .ok_or_else(|| ApiError::not_found(format!("unknown resource kind '{kind}'")))
}

/// 服务层分页结果 → API 分页响应。
fn map_page<T, U>(page: Page<T>, f: impl Fn(T) -> U) -> PageView<U> {
    PageView::new(
        page.items.into_iter().map(f).collect(),
        page.total,
        page.limit,
        page.offset,
    )
}
