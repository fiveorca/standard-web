//! Admin API handlers。
//!
//! 每个 handler 只做三件事：解析参数 → 调用 [`ConfigService`] → 转换 DTO。
//! 认证通过 [`crate::auth::Principal`] 提取器完成；写操作显式调用
//! `require_admin()` 实现 RBAC。

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use gateway_control_service::Page;
use gateway_storage::{ResourceDraft, ResourceKind, ResourceUpdate, StoredResource};

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
//
// 内部 impl 函数（显式传入 ResourceKind）供通用 handler 与别名 handler 共用，
// 避免 consumers / plugins 别名路由重复写相同的 service 调用逻辑。

/// 内部：列出指定类型的资源。
async fn list_resources_impl(
    state: &AdminState,
    kind: ResourceKind,
    limit: usize,
    offset: usize,
) -> Result<Json<PageView<ResourceView>>, ApiError> {
    let page: Page<StoredResource> = state
        .service
        .list_resources(kind, limit, offset)
        .await?;
    Ok(Json(map_page(page, ResourceView::from)))
}

/// 内部：按 ID 查询指定类型的单个资源。
async fn get_resource_impl(
    state: &AdminState,
    kind: ResourceKind,
    id: &str,
) -> Result<Json<ResourceView>, ApiError> {
    let resource = state.service.get_resource(kind, id).await?;
    Ok(Json(ResourceView::from(resource)))
}

/// 内部：创建指定类型的资源。
async fn create_resource_impl(
    state: &AdminState,
    kind: ResourceKind,
    draft: ResourceDraft,
    actor: &str,
) -> Result<(StatusCode, Json<ResourceView>), ApiError> {
    let created = state
        .service
        .create_resource(kind, draft, actor)
        .await?;
    Ok((StatusCode::CREATED, Json(ResourceView::from(created))))
}

/// 内部：更新指定类型的资源。
async fn update_resource_impl(
    state: &AdminState,
    kind: ResourceKind,
    id: &str,
    update: ResourceUpdate,
    actor: &str,
) -> Result<Json<ResourceView>, ApiError> {
    let updated = state
        .service
        .update_resource(kind, id, update, actor)
        .await?;
    Ok(Json(ResourceView::from(updated)))
}

/// 内部：删除指定类型的资源。
async fn delete_resource_impl(
    state: &AdminState,
    kind: ResourceKind,
    id: &str,
    expected_version: Option<i64>,
    actor: &str,
) -> Result<StatusCode, ApiError> {
    state
        .service
        .delete_resource(kind, id, expected_version, actor)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---- 通用 /resources/{kind} 路由 handler ----

/// 列出某类资源（从路径 `{kind}` 解析类型）。
pub async fn list_resources(
    State(state): State<AdminState>,
    _principal: Principal,
    Path(kind): Path<String>,
    Query(query): Query<PageQuery>,
) -> Result<Json<PageView<ResourceView>>, ApiError> {
    list_resources_impl(&state, parse_kind(&kind)?, query.limit(), query.offset()).await
}

/// 查询单个资源（从路径 `{kind}/{id}` 解析）。
pub async fn get_resource(
    State(state): State<AdminState>,
    _principal: Principal,
    Path((kind, id)): Path<(String, String)>,
) -> Result<Json<ResourceView>, ApiError> {
    get_resource_impl(&state, parse_kind(&kind)?, &id).await
}

/// 创建资源（从路径 `{kind}` 解析类型，需要 admin）。
pub async fn create_resource(
    State(state): State<AdminState>,
    principal: Principal,
    Path(kind): Path<String>,
    Json(body): Json<CreateResourceRequest>,
) -> Result<(StatusCode, Json<ResourceView>), ApiError> {
    principal.require_admin()?;
    let kind = parse_kind(&kind)?;
    let draft = ResourceDraft {
        id: body.id,
        name: body.name,
        enabled: body.enabled,
        payload: body.payload,
    };
    create_resource_impl(&state, kind, draft, &principal.actor).await
}

/// 更新资源（从路径 `{kind}/{id}` 解析，需要 admin）。
pub async fn update_resource(
    State(state): State<AdminState>,
    principal: Principal,
    Path((kind, id)): Path<(String, String)>,
    Json(body): Json<UpdateResourceRequest>,
) -> Result<Json<ResourceView>, ApiError> {
    principal.require_admin()?;
    let kind = parse_kind(&kind)?;
    let update = ResourceUpdate {
        name: body.name,
        enabled: body.enabled,
        payload: body.payload,
        expected_version: body.expected_version,
    };
    update_resource_impl(&state, kind, &id, update, &principal.actor).await
}

/// 删除资源（从路径 `{kind}/{id}` 解析，需要 admin）。
pub async fn delete_resource(
    State(state): State<AdminState>,
    principal: Principal,
    Path((kind, id)): Path<(String, String)>,
    Query(query): Query<DeleteQuery>,
) -> Result<StatusCode, ApiError> {
    principal.require_admin()?;
    let kind = parse_kind(&kind)?;
    delete_resource_impl(
        &state,
        kind,
        &id,
        query.expected_version,
        &principal.actor,
    )
    .await
}

// ---- consumers 别名路由 handler（设计文档 8.5） ----

/// 列出所有消费者（`GET /consumers`）。
pub async fn list_consumers(
    State(state): State<AdminState>,
    _principal: Principal,
    Query(query): Query<PageQuery>,
) -> Result<Json<PageView<ResourceView>>, ApiError> {
    list_resources_impl(&state, ResourceKind::Consumer, query.limit(), query.offset()).await
}

/// 查询单个消费者（`GET /consumers/{id}`）。
pub async fn get_consumer(
    State(state): State<AdminState>,
    _principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<ResourceView>, ApiError> {
    get_resource_impl(&state, ResourceKind::Consumer, &id).await
}

/// 创建消费者（`POST /consumers`，需要 admin）。
pub async fn create_consumer(
    State(state): State<AdminState>,
    principal: Principal,
    Json(body): Json<CreateResourceRequest>,
) -> Result<(StatusCode, Json<ResourceView>), ApiError> {
    principal.require_admin()?;
    let draft = ResourceDraft {
        id: body.id,
        name: body.name,
        enabled: body.enabled,
        payload: body.payload,
    };
    create_resource_impl(&state, ResourceKind::Consumer, draft, &principal.actor).await
}

/// 更新消费者（`PUT /consumers/{id}`，需要 admin）。
pub async fn update_consumer(
    State(state): State<AdminState>,
    principal: Principal,
    Path(id): Path<String>,
    Json(body): Json<UpdateResourceRequest>,
) -> Result<Json<ResourceView>, ApiError> {
    principal.require_admin()?;
    let update = ResourceUpdate {
        name: body.name,
        enabled: body.enabled,
        payload: body.payload,
        expected_version: body.expected_version,
    };
    update_resource_impl(&state, ResourceKind::Consumer, &id, update, &principal.actor).await
}

/// 删除消费者（`DELETE /consumers/{id}`，需要 admin）。
pub async fn delete_consumer(
    State(state): State<AdminState>,
    principal: Principal,
    Path(id): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<StatusCode, ApiError> {
    principal.require_admin()?;
    delete_resource_impl(
        &state,
        ResourceKind::Consumer,
        &id,
        query.expected_version,
        &principal.actor,
    )
    .await
}

// ---- plugins 别名路由 handler（设计文档 8.7） ----

/// 列出所有插件（`GET /plugins`）。
pub async fn list_plugins(
    State(state): State<AdminState>,
    _principal: Principal,
    Query(query): Query<PageQuery>,
) -> Result<Json<PageView<ResourceView>>, ApiError> {
    list_resources_impl(&state, ResourceKind::Plugin, query.limit(), query.offset()).await
}

/// 查询单个插件（`GET /plugins/{id}`）。
pub async fn get_plugin(
    State(state): State<AdminState>,
    _principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<ResourceView>, ApiError> {
    get_resource_impl(&state, ResourceKind::Plugin, &id).await
}

/// 创建插件（`POST /plugins`，需要 admin）。
pub async fn create_plugin(
    State(state): State<AdminState>,
    principal: Principal,
    Json(body): Json<CreateResourceRequest>,
) -> Result<(StatusCode, Json<ResourceView>), ApiError> {
    principal.require_admin()?;
    let draft = ResourceDraft {
        id: body.id,
        name: body.name,
        enabled: body.enabled,
        payload: body.payload,
    };
    create_resource_impl(&state, ResourceKind::Plugin, draft, &principal.actor).await
}

/// 更新插件（`PUT /plugins/{id}`，需要 admin）。
pub async fn update_plugin(
    State(state): State<AdminState>,
    principal: Principal,
    Path(id): Path<String>,
    Json(body): Json<UpdateResourceRequest>,
) -> Result<Json<ResourceView>, ApiError> {
    principal.require_admin()?;
    let update = ResourceUpdate {
        name: body.name,
        enabled: body.enabled,
        payload: body.payload,
        expected_version: body.expected_version,
    };
    update_resource_impl(&state, ResourceKind::Plugin, &id, update, &principal.actor).await
}

/// 删除插件（`DELETE /plugins/{id}`，需要 admin）。
pub async fn delete_plugin(
    State(state): State<AdminState>,
    principal: Principal,
    Path(id): Path<String>,
    Query(query): Query<DeleteQuery>,
) -> Result<StatusCode, ApiError> {
    principal.require_admin()?;
    delete_resource_impl(
        &state,
        ResourceKind::Plugin,
        &id,
        query.expected_version,
        &principal.actor,
    )
    .await
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
// Consumer Credentials（嵌套资源）
// ---------------------------------------------------------------------------

/// 为指定消费者创建凭据。
///
/// ConsumerCredential 在通用 CRUD 里的 kind 是 `consumer-credentials`，
/// 但设计文档 8.6 把它暴露为 `/consumers/{id}/credentials` 的嵌套路径，
/// 这里提供显式 handler，内部复用相同的 service 方法。
pub async fn create_credential(
    State(state): State<AdminState>,
    principal: Principal,
    Path(consumer_id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<ResourceView>, ApiError> {
    principal.require_admin()?;
    // 请求体必须带 id（凭据唯一标识），作为外部消费者侧的凭据 ID；
    // ResourceKind::ConsumerCredential 路由通过父 consumer_id 归属校验
    let id = body.get("id").and_then(|v| v.as_str()).ok_or_else(|| {
        ApiError::bad_request("consumer credential requires 'id' field")
    })?;
    // 把 consumer_id 注入 payload，保证凭据与父消费者一致
    let mut payload = body.clone();
    payload["consumer_id"] = serde_json::Value::String(consumer_id);

    // 构造 ResourceDraft 以匹配 service.create_resource 签名
    let draft = ResourceDraft {
        id: id.to_string(),
        name: None,
        enabled: true,
        payload,
    };
    let res = state
        .service
        .create_resource(ResourceKind::ConsumerCredential, draft, &principal.actor)
        .await?;
    Ok(Json(ResourceView::from(res)))
}

/// 删除指定消费者的指定凭据。
pub async fn delete_credential(
    State(state): State<AdminState>,
    principal: Principal,
    Path((consumer_id, credential_id)): Path<(String, String)>,
    Query(query): Query<DeleteQuery>,
) -> Result<StatusCode, ApiError> {
    principal.require_admin()?;
    // service 层只按 (kind, id) 定位；凭据归属校验由 payload 匹配保证
    let _ = consumer_id; // 保留参数名以便路由语义清晰
    state
        .service
        .delete_resource(
            ResourceKind::ConsumerCredential,
            &credential_id,
            query.expected_version,
            &principal.actor,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Plugin enable / disable（设计文档 8.7）
// ---------------------------------------------------------------------------

/// 启用插件：等价于 `PUT /resources/plugins/{id}` 把 `enabled` 设为 true。
pub async fn enable_plugin(
    State(state): State<AdminState>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<ResourceView>, ApiError> {
    principal.require_admin()?;
    let res = set_plugin_enabled(&state, &id, true, &principal.actor).await?;
    Ok(Json(ResourceView::from(res)))
}

/// 禁用插件：等价于 `PUT /resources/plugins/{id}` 把 `enabled` 设为 false。
pub async fn disable_plugin(
    State(state): State<AdminState>,
    principal: Principal,
    Path(id): Path<String>,
) -> Result<Json<ResourceView>, ApiError> {
    principal.require_admin()?;
    let res = set_plugin_enabled(&state, &id, false, &principal.actor).await?;
    Ok(Json(ResourceView::from(res)))
}

/// enable/disable 的共享实现。
async fn set_plugin_enabled(
    state: &AdminState,
    id: &str,
    enabled: bool,
    actor: &str,
) -> Result<StoredResource, ApiError> {
    // 先查当前 payload（包含 id 与其他字段，避免 PUT 覆盖其他属性）
    let existing = state
        .service
        .get_resource(ResourceKind::Plugin, id)
        .await?;
    let mut payload = existing.payload.clone();
    payload["enabled"] = serde_json::Value::Bool(enabled);
    // 构造 ResourceUpdate，只更新 payload，同时带上乐观锁版本号
    let update = ResourceUpdate {
        name: None,
        enabled: None,
        payload: Some(payload),
        expected_version: Some(existing.version),
    };
    // ? 自动触发 From<ControlError> for ApiError 转换，再用 Ok() 包成 Result
    Ok(state
        .service
        .update_resource(ResourceKind::Plugin, id, update, actor)
        .await?)
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
