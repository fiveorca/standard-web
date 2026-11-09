//! RBAC / ABAC / ReBAC 管理服务与授权视图。

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::application::RequestMeta;
use crate::bootstrap::AppState;
use crate::domain::{
    ApiResource, AuditLog, AuthorizationPolicy, ButtonResource, DataPermission, DomainEvent,
    Identity, MenuResource, OAuthClient, OAuthScope, Permission, ResourceRelation, Role, Tenant,
    UserRole,
};
use crate::infrastructure::outbox;
use crate::shared::{normalize_permission_code, AppError, AppResult, PageQuery, DEFAULT_TENANT_ID};

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RoleInput {
    pub code: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub kind: Option<String>,
    pub scope: Option<String>,
    pub parent_id: Option<Uuid>,
    pub status: Option<String>,
    pub metadata: Option<Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PermissionInput {
    pub code: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
    pub kind: Option<String>,
    pub parent_id: Option<Uuid>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ApiResourceInput {
    pub method: Option<String>,
    pub path_pattern: Option<String>,
    pub permission_id: Option<Uuid>,
    pub description: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MenuInput {
    pub parent_id: Option<Uuid>,
    pub code: Option<String>,
    pub name: Option<String>,
    pub route: Option<String>,
    pub icon: Option<String>,
    pub menu_type: Option<String>,
    pub sort_order: Option<i32>,
    pub visible: Option<bool>,
    pub permission_id: Option<Uuid>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ButtonInput {
    pub menu_id: Option<Uuid>,
    pub api_resource_id: Option<Uuid>,
    pub code: Option<String>,
    pub name: Option<String>,
    pub permission_id: Option<Uuid>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DataPermissionInput {
    pub role_id: Option<Uuid>,
    pub permission_id: Option<Uuid>,
    pub scope_type: String,
    pub scope_config: Option<Value>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PolicyInput {
    pub name: Option<String>,
    pub description: Option<String>,
    pub effect: Option<String>,
    pub subject_type: Option<String>,
    pub subject_id: Option<String>,
    pub action: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub condition: Option<Value>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PermissionTreeNode {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub kind: String,
    pub category: String,
    pub children: Vec<PermissionTreeNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MenuTreeNode {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub route: Option<String>,
    pub icon: Option<String>,
    pub menu_type: String,
    pub sort_order: i32,
    pub visible: bool,
    pub children: Vec<MenuTreeNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MyAuthorization {
    pub identity_id: Uuid,
    pub tenant_id: Uuid,
    pub roles: Vec<crate::domain::RoleRef>,
    pub permissions: Vec<String>,
    pub data_permissions: Vec<DataPermission>,
}

impl AppState {
    // ───────────────────────── 角色 ─────────────────────────

    pub async fn list_roles(
        &self,
        tenant_id: Uuid,
        query: &PageQuery,
        keyword: Option<&str>,
    ) -> AppResult<(Vec<Role>, i64)> {
        let keyword = keyword.map(|value| format!("%{}%", value.trim()));
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM roles
             WHERE deleted_at IS NULL AND (tenant_id = $1 OR tenant_id IS NULL)
               AND ($2::text IS NULL OR code ILIKE $2 OR name ILIKE $2)",
        )
        .bind(tenant_id)
        .bind(&keyword)
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query_as::<_, Role>(
            "SELECT * FROM roles
             WHERE deleted_at IS NULL AND (tenant_id = $1 OR tenant_id IS NULL)
               AND ($2::text IS NULL OR code ILIKE $2 OR name ILIKE $2)
             ORDER BY tenant_id NULLS FIRST, code
             LIMIT $3 OFFSET $4",
        )
        .bind(tenant_id)
        .bind(&keyword)
        .bind(query.limit())
        .bind(query.offset())
        .fetch_all(&self.pool)
        .await?;
        Ok((rows, total))
    }

    pub async fn get_role(&self, tenant_id: Uuid, role_id: Uuid) -> AppResult<Role> {
        sqlx::query_as::<_, Role>(
            "SELECT * FROM roles
             WHERE id = $1 AND deleted_at IS NULL AND (tenant_id = $2 OR tenant_id IS NULL)",
        )
        .bind(role_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("角色不存在"))
    }

    pub async fn create_role(
        &self,
        tenant_id: Uuid,
        input: RoleInput,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<Role> {
        self.ensure_tenant(tenant_id).await?;
        let code = input
            .code
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::validation("code", "角色编码不能为空"))?;
        let code = normalize_permission_code(code);
        let name = input
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::validation("name", "角色名称不能为空"))?;
        let kind = input.kind.as_deref().unwrap_or("tenant");
        if !matches!(kind, "system" | "tenant" | "organization" | "resource") {
            return Err(AppError::validation("kind", "角色类型非法"));
        }
        let scope = input.scope.as_deref().unwrap_or("tenant");
        if !matches!(scope, "global" | "tenant" | "organization" | "resource") {
            return Err(AppError::validation("scope", "角色作用域非法"));
        }
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO roles (id, tenant_id, code, name, description, kind, scope, parent_id, metadata)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
        )
        .bind(id)
        .bind(if scope == "global" { None } else { Some(tenant_id) })
        .bind(&code)
        .bind(name)
        .bind(&input.description)
        .bind(kind)
        .bind(scope)
        .bind(input.parent_id)
        .bind(input.metadata.unwrap_or_else(|| json!({})))
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "角色编码已存在"))?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.role.created",
            "role",
            id,
            meta,
            json!({ "code": code }),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        self.get_role(tenant_id, id).await
    }

    pub async fn update_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        input: RoleInput,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<Role> {
        let existing = self.get_role(tenant_id, role_id).await?;
        if existing.is_builtin && input.code.is_some() {
            return Err(AppError::conflict("内置角色不允许修改编码"));
        }
        let code = input
            .code
            .as_deref()
            .map(normalize_permission_code)
            .unwrap_or(existing.code);
        let status = input.status.clone().unwrap_or(existing.status);
        if !matches!(status.as_str(), "active" | "disabled") {
            return Err(AppError::validation("status", "角色状态非法"));
        }
        sqlx::query(
            "UPDATE roles SET code = $2, name = $3, description = $4, status = $5,
                    parent_id = $6, metadata = $7, updated_at = now()
             WHERE id = $1",
        )
        .bind(role_id)
        .bind(&code)
        .bind(input.name.clone().unwrap_or(existing.name))
        .bind(input.description.clone().or(existing.description))
        .bind(&status)
        .bind(input.parent_id.or(existing.parent_id))
        .bind(input.metadata.unwrap_or(existing.metadata))
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "角色编码已存在"))?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.role.updated",
            "role",
            role_id,
            meta,
            json!({}),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        self.get_role(tenant_id, role_id).await
    }

    pub async fn delete_role(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let role = self.get_role(tenant_id, role_id).await?;
        if role.is_builtin {
            return Err(AppError::conflict("内置角色不允许删除"));
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE roles SET deleted_at = now(), updated_at = now() WHERE id = $1")
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM user_roles WHERE role_id = $1")
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM data_permissions WHERE role_id = $1")
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("auth.role.deleted")
                .tenant(tenant_id)
                .actor(actor)
                .resource("role", role_id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                )
                .detail(json!({ "code": role.code })),
        )
        .await?;
        tx.commit().await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(())
    }

    pub async fn set_role_permissions(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        permission_ids: &[Uuid],
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<usize> {
        let role = self.get_role(tenant_id, role_id).await?;
        for permission_id in permission_ids {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM permissions
                 WHERE id = $1 AND deleted_at IS NULL AND (tenant_id = $2 OR tenant_id IS NULL))",
            )
            .bind(permission_id)
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await?;
            if !exists {
                return Err(AppError::validation(
                    "permission_ids",
                    format!("权限 {permission_id} 不存在或不属于当前租户"),
                ));
            }
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM role_permissions WHERE role_id = $1")
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
        for permission_id in permission_ids {
            sqlx::query(
                "INSERT INTO role_permissions (role_id, permission_id, tenant_id, granted_by)
                 VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING",
            )
            .bind(role_id)
            .bind(permission_id)
            .bind(role.tenant_id)
            .bind(actor)
            .execute(&mut *tx)
            .await?;
        }
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("auth.role.permissions_changed")
                .tenant(tenant_id)
                .actor(actor)
                .resource("role", role_id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                )
                .detail(json!({ "count": permission_ids.len(), "code": role.code })),
        )
        .await?;
        outbox::enqueue(
            &mut tx,
            &DomainEvent::new(
                crate::domain::EVENT_PERMISSIONS_CHANGED,
                "role",
                role_id.to_string(),
                json!({ "role_id": role_id, "tenant_id": tenant_id }),
            ),
        )
        .await?;
        tx.commit().await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(permission_ids.len())
    }

    pub async fn list_role_permissions(&self, role_id: Uuid) -> AppResult<Vec<Permission>> {
        Ok(sqlx::query_as::<_, Permission>(
            "SELECT p.* FROM permissions p
             JOIN role_permissions rp ON rp.permission_id = p.id
             WHERE rp.role_id = $1 AND p.deleted_at IS NULL
             ORDER BY p.code",
        )
        .bind(role_id)
        .fetch_all(&self.pool)
        .await?)
    }

    // ───────────────────────── 权限 ─────────────────────────

    pub async fn list_permissions(
        &self,
        tenant_id: Uuid,
        keyword: Option<&str>,
    ) -> AppResult<Vec<Permission>> {
        let keyword = keyword.map(|value| format!("%{}%", value.trim()));
        Ok(sqlx::query_as::<_, Permission>(
            "SELECT * FROM permissions
             WHERE deleted_at IS NULL AND (tenant_id = $1 OR tenant_id IS NULL)
               AND ($2::text IS NULL OR code ILIKE $2 OR name ILIKE $2)
             ORDER BY category, code",
        )
        .bind(tenant_id)
        .bind(&keyword)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn permission_tree(&self, tenant_id: Uuid) -> AppResult<Vec<PermissionTreeNode>> {
        let all = self.list_permissions(tenant_id, None).await?;
        fn build(parent: Option<Uuid>, all: &[Permission]) -> Vec<PermissionTreeNode> {
            all.iter()
                .filter(|item| item.parent_id == parent)
                .map(|item| PermissionTreeNode {
                    id: item.id,
                    code: item.code.clone(),
                    name: item.name.clone(),
                    kind: item.kind.clone(),
                    category: item.category.clone(),
                    children: build(Some(item.id), all),
                })
                .collect()
        }
        Ok(build(None, &all))
    }

    pub async fn create_permission(
        &self,
        tenant_id: Uuid,
        input: PermissionInput,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<Permission> {
        let code = input
            .code
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::validation("code", "权限编码不能为空"))?;
        if !code.contains(':') {
            return Err(AppError::validation(
                "code",
                "权限编码必须使用 domain:action 形式",
            ));
        }
        let code = normalize_permission_code(code);
        let name = input
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::validation("name", "权限名称不能为空"))?;
        let kind = input.kind.as_deref().unwrap_or("action");
        if !matches!(
            kind,
            "api" | "menu" | "button" | "data" | "resource" | "action"
        ) {
            return Err(AppError::validation("kind", "权限类型非法"));
        }
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO permissions (id, tenant_id, code, name, description, category, kind, parent_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(id)
        .bind(Some(tenant_id))
        .bind(&code)
        .bind(name)
        .bind(&input.description)
        .bind(input.category.as_deref().unwrap_or("general"))
        .bind(kind)
        .bind(input.parent_id)
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "权限编码已存在"))?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.permission.created",
            "permission",
            id,
            meta,
            json!({ "code": code }),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        sqlx::query_as::<_, Permission>("SELECT * FROM permissions WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    pub async fn update_permission(
        &self,
        tenant_id: Uuid,
        permission_id: Uuid,
        input: PermissionInput,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<Permission> {
        let existing = self.get_permission(tenant_id, permission_id).await?;
        let code = input
            .code
            .as_deref()
            .map(normalize_permission_code)
            .unwrap_or(existing.code);
        let status = input.status.clone().unwrap_or(existing.status);
        sqlx::query(
            "UPDATE permissions SET code = $2, name = $3, description = $4, category = $5,
                    kind = $6, parent_id = $7, status = $8, updated_at = now()
             WHERE id = $1",
        )
        .bind(permission_id)
        .bind(&code)
        .bind(input.name.unwrap_or(existing.name))
        .bind(input.description.or(existing.description))
        .bind(input.category.unwrap_or(existing.category))
        .bind(input.kind.unwrap_or(existing.kind))
        .bind(input.parent_id.or(existing.parent_id))
        .bind(&status)
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "权限编码已存在"))?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.permission.updated",
            "permission",
            permission_id,
            meta,
            json!({}),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        self.get_permission(tenant_id, permission_id).await
    }

    pub async fn get_permission(
        &self,
        tenant_id: Uuid,
        permission_id: Uuid,
    ) -> AppResult<Permission> {
        sqlx::query_as::<_, Permission>(
            "SELECT * FROM permissions
             WHERE id = $1 AND deleted_at IS NULL AND (tenant_id = $2 OR tenant_id IS NULL)",
        )
        .bind(permission_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("权限不存在"))
    }

    pub async fn delete_permission(
        &self,
        tenant_id: Uuid,
        permission_id: Uuid,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let permission = self.get_permission(tenant_id, permission_id).await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("UPDATE permissions SET deleted_at = now(), updated_at = now() WHERE id = $1")
            .bind(permission_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM role_permissions WHERE permission_id = $1")
            .bind(permission_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM user_permissions WHERE permission_id = $1")
            .bind(permission_id)
            .execute(&mut *tx)
            .await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("auth.permission.deleted")
                .tenant(tenant_id)
                .actor(actor)
                .resource("permission", permission_id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                )
                .detail(json!({ "code": permission.code })),
        )
        .await?;
        tx.commit().await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(())
    }

    // ───────────────────────── 用户角色 ─────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub async fn assign_role(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        role_id: Uuid,
        organization_id: Option<Uuid>,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<Uuid> {
        let identity = self.get_identity(identity_id).await?;
        if identity.tenant_id != tenant_id {
            return Err(AppError::forbidden("身份不属于当前租户"));
        }
        let role = self.get_role(tenant_id, role_id).await?;
        if role.status != "active" {
            return Err(AppError::conflict("角色已被禁用"));
        }
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO user_roles
                (id, identity_id, role_id, tenant_id, organization_id, scope, valid_until, granted_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        )
        .bind(id)
        .bind(identity_id)
        .bind(role_id)
        .bind(tenant_id)
        .bind(organization_id)
        .bind(&role.scope)
        .bind(valid_until)
        .bind(actor)
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "用户已拥有该角色"))?;
        let mut tx = self.pool.begin().await?;
        audit::record_in_tx(
            &mut tx,
            AuditEntry::new("auth.user_role.granted")
                .tenant(tenant_id)
                .actor(actor)
                .resource("identity", identity_id.to_string())
                .request_context(meta.ip.clone(), meta.user_agent.clone(), meta.trace_id.clone())
                .detail(json!({ "role_id": role_id, "role_code": role.code, "organization_id": organization_id })),
        )
        .await?;
        outbox::enqueue(
            &mut tx,
            &DomainEvent::new(
                crate::domain::EVENT_USER_ROLES_CHANGED,
                "identity",
                identity_id.to_string(),
                json!({ "identity_id": identity_id, "tenant_id": tenant_id, "role_id": role_id, "action": "grant" }),
            ),
        )
        .await?;
        tx.commit().await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(id)
    }

    pub async fn revoke_role(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        role_id: Uuid,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<u64> {
        let result = sqlx::query(
            "UPDATE user_roles SET revoked_at = now(), revoked_by = $4, version = version + 1
             WHERE identity_id = $1 AND role_id = $2 AND tenant_id = $3 AND revoked_at IS NULL",
        )
        .bind(identity_id)
        .bind(role_id)
        .bind(tenant_id)
        .bind(actor)
        .execute(&self.pool)
        .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.user_role.revoked",
            "identity",
            identity_id,
            meta,
            json!({ "role_id": role_id, "count": result.rows_affected() }),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(result.rows_affected())
    }

    pub async fn batch_assign_roles(
        &self,
        tenant_id: Uuid,
        role_id: Uuid,
        identity_ids: &[Uuid],
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<usize> {
        let mut granted = 0;
        for identity_id in identity_ids {
            match self
                .assign_role(tenant_id, *identity_id, role_id, None, None, actor, meta)
                .await
            {
                Ok(_) => granted += 1,
                Err(error) if error.code == "conflict" => {}
                Err(error) => return Err(error),
            }
        }
        Ok(granted)
    }

    pub async fn list_user_roles(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
    ) -> AppResult<Vec<UserRole>> {
        Ok(sqlx::query_as::<_, UserRole>(
            "SELECT * FROM user_roles
             WHERE identity_id = $1 AND tenant_id = $2 AND revoked_at IS NULL
               AND valid_from <= now() AND (valid_until IS NULL OR valid_until > now())
             ORDER BY created_at DESC",
        )
        .bind(identity_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn list_role_members(
        &self,
        role_id: Uuid,
        query: &PageQuery,
    ) -> AppResult<(Vec<Identity>, i64)> {
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM user_roles WHERE role_id = $1 AND revoked_at IS NULL",
        )
        .bind(role_id)
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query_as::<_, Identity>(
            "SELECT i.* FROM identities i
             JOIN user_roles ur ON ur.identity_id = i.id
             WHERE ur.role_id = $1 AND ur.revoked_at IS NULL
             ORDER BY ur.created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(role_id)
        .bind(query.limit())
        .bind(query.offset())
        .fetch_all(&self.pool)
        .await?;
        Ok((rows, total))
    }

    pub async fn grant_user_permission(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        permission_id: Uuid,
        effect: &str,
        valid_until: Option<chrono::DateTime<chrono::Utc>>,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        if !matches!(effect, "allow" | "deny") {
            return Err(AppError::validation(
                "effect",
                "授权效果必须是 allow 或 deny",
            ));
        }
        let identity = self.get_identity(identity_id).await?;
        if identity.tenant_id != tenant_id {
            return Err(AppError::forbidden("身份不属于当前租户"));
        }
        let permission = self.get_permission(tenant_id, permission_id).await?;
        sqlx::query(
            "INSERT INTO user_permissions
                (identity_id, permission_id, tenant_id, effect, valid_until, granted_by)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (identity_id, permission_id, tenant_id) WHERE revoked_at IS NULL
             DO UPDATE SET effect = EXCLUDED.effect, valid_until = EXCLUDED.valid_until",
        )
        .bind(identity_id)
        .bind(permission_id)
        .bind(tenant_id)
        .bind(effect)
        .bind(valid_until)
        .bind(actor)
        .execute(&self.pool)
        .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.user_permission.granted",
            "identity",
            identity_id,
            meta,
            json!({ "permission": permission.code, "effect": effect }),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(())
    }

    pub async fn revoke_user_permission(
        &self,
        tenant_id: Uuid,
        identity_id: Uuid,
        permission_id: Uuid,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE user_permissions SET revoked_at = now()
             WHERE identity_id = $1 AND permission_id = $2 AND tenant_id = $3 AND revoked_at IS NULL",
        )
        .bind(identity_id)
        .bind(permission_id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.user_permission.revoked",
            "identity",
            identity_id,
            meta,
            json!({ "permission_id": permission_id }),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(())
    }

    // ───────────────────────── 资源 ─────────────────────────

    pub async fn list_api_resources(&self, tenant_id: Uuid) -> AppResult<Vec<ApiResource>> {
        Ok(sqlx::query_as::<_, ApiResource>(
            "SELECT * FROM api_resources
             WHERE deleted_at IS NULL AND (tenant_id = $1 OR tenant_id IS NULL)
             ORDER BY path_pattern, method",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn create_api_resource(
        &self,
        tenant_id: Uuid,
        input: ApiResourceInput,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<ApiResource> {
        let method = input
            .method
            .as_deref()
            .map(str::trim)
            .map(str::to_uppercase)
            .ok_or_else(|| AppError::validation("method", "HTTP 方法不能为空"))?;
        if !matches!(
            method.as_str(),
            "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD"
        ) {
            return Err(AppError::validation("method", "HTTP 方法非法"));
        }
        let path = input
            .path_pattern
            .as_deref()
            .map(str::trim)
            .filter(|value| value.starts_with('/'))
            .ok_or_else(|| AppError::validation("path_pattern", "API 路径必须以 / 开头"))?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO api_resources (id, tenant_id, method, path_pattern, permission_id, description)
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(id)
        .bind(Some(tenant_id))
        .bind(&method)
        .bind(path)
        .bind(input.permission_id)
        .bind(&input.description)
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "API 资源已存在"))?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.api_resource.created",
            "api_resource",
            id,
            meta,
            json!({}),
        )
        .await?;
        Ok(
            sqlx::query_as::<_, ApiResource>("SELECT * FROM api_resources WHERE id = $1")
                .bind(id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn update_api_resource(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: ApiResourceInput,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<ApiResource> {
        let existing = sqlx::query_as::<_, ApiResource>(
            "SELECT * FROM api_resources WHERE id = $1 AND deleted_at IS NULL
             AND (tenant_id = $2 OR tenant_id IS NULL)",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("API 资源不存在"))?;
        sqlx::query(
            "UPDATE api_resources SET method = $2, path_pattern = $3, permission_id = $4,
                    description = $5, status = $6, updated_at = now() WHERE id = $1",
        )
        .bind(id)
        .bind(input.method.unwrap_or(existing.method).to_uppercase())
        .bind(input.path_pattern.unwrap_or(existing.path_pattern))
        .bind(input.permission_id.or(existing.permission_id))
        .bind(input.description.or(existing.description))
        .bind(input.status.unwrap_or(existing.status))
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "API 资源重复"))?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.api_resource.updated",
            "api_resource",
            id,
            meta,
            json!({}),
        )
        .await?;
        Ok(
            sqlx::query_as::<_, ApiResource>("SELECT * FROM api_resources WHERE id = $1")
                .bind(id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn delete_api_resource(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE api_resources SET deleted_at = now(), updated_at = now()
             WHERE id = $1 AND (tenant_id = $2 OR tenant_id IS NULL)",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.api_resource.deleted",
            "api_resource",
            id,
            meta,
            json!({}),
        )
        .await?;
        Ok(())
    }

    pub async fn list_menus(&self, tenant_id: Uuid) -> AppResult<Vec<MenuResource>> {
        Ok(sqlx::query_as::<_, MenuResource>(
            "SELECT * FROM menu_resources
             WHERE deleted_at IS NULL AND (tenant_id = $1 OR tenant_id IS NULL)
             ORDER BY sort_order, code",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn create_menu(
        &self,
        tenant_id: Uuid,
        input: MenuInput,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<MenuResource> {
        let code = input
            .code
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::validation("code", "菜单编码不能为空"))?;
        let name = input
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::validation("name", "菜单名称不能为空"))?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO menu_resources
                (id, tenant_id, parent_id, code, name, route, icon, menu_type, sort_order, visible, permission_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(id)
        .bind(Some(tenant_id))
        .bind(input.parent_id)
        .bind(code)
        .bind(name)
        .bind(&input.route)
        .bind(&input.icon)
        .bind(input.menu_type.as_deref().unwrap_or("menu"))
        .bind(input.sort_order.unwrap_or(0))
        .bind(input.visible.unwrap_or(true))
        .bind(input.permission_id)
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "菜单编码已存在"))?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.menu.created",
            "menu",
            id,
            meta,
            json!({}),
        )
        .await?;
        Ok(
            sqlx::query_as::<_, MenuResource>("SELECT * FROM menu_resources WHERE id = $1")
                .bind(id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn update_menu(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: MenuInput,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<MenuResource> {
        let existing = sqlx::query_as::<_, MenuResource>(
            "SELECT * FROM menu_resources WHERE id = $1 AND deleted_at IS NULL
             AND (tenant_id = $2 OR tenant_id IS NULL)",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("菜单不存在"))?;
        sqlx::query(
            "UPDATE menu_resources SET parent_id = $2, code = $3, name = $4, route = $5,
                    icon = $6, menu_type = $7, sort_order = $8, visible = $9,
                    permission_id = $10, status = $11, updated_at = now()
             WHERE id = $1",
        )
        .bind(id)
        .bind(input.parent_id.or(existing.parent_id))
        .bind(input.code.unwrap_or(existing.code))
        .bind(input.name.unwrap_or(existing.name))
        .bind(input.route.or(existing.route))
        .bind(input.icon.or(existing.icon))
        .bind(input.menu_type.unwrap_or(existing.menu_type))
        .bind(input.sort_order.unwrap_or(existing.sort_order))
        .bind(input.visible.unwrap_or(existing.visible))
        .bind(input.permission_id.or(existing.permission_id))
        .bind(input.status.unwrap_or(existing.status))
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "菜单编码已存在"))?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.menu.updated",
            "menu",
            id,
            meta,
            json!({}),
        )
        .await?;
        Ok(
            sqlx::query_as::<_, MenuResource>("SELECT * FROM menu_resources WHERE id = $1")
                .bind(id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn delete_menu(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE menu_resources SET deleted_at = now(), updated_at = now()
             WHERE id = $1 AND (tenant_id = $2 OR tenant_id IS NULL)",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.menu.deleted",
            "menu",
            id,
            meta,
            json!({}),
        )
        .await?;
        Ok(())
    }

    pub async fn list_buttons(&self, tenant_id: Uuid) -> AppResult<Vec<ButtonResource>> {
        Ok(sqlx::query_as::<_, ButtonResource>(
            "SELECT * FROM button_resources
             WHERE deleted_at IS NULL AND (tenant_id = $1 OR tenant_id IS NULL)
             ORDER BY code",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn create_button(
        &self,
        tenant_id: Uuid,
        input: ButtonInput,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<ButtonResource> {
        let code = input
            .code
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::validation("code", "按钮编码不能为空"))?;
        let name = input
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::validation("name", "按钮名称不能为空"))?;
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO button_resources
                (id, tenant_id, menu_id, api_resource_id, code, name, permission_id)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(Some(tenant_id))
        .bind(input.menu_id)
        .bind(input.api_resource_id)
        .bind(code)
        .bind(name)
        .bind(input.permission_id)
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "按钮编码已存在"))?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.button.created",
            "button",
            id,
            meta,
            json!({}),
        )
        .await?;
        Ok(
            sqlx::query_as::<_, ButtonResource>("SELECT * FROM button_resources WHERE id = $1")
                .bind(id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn delete_button(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        sqlx::query(
            "UPDATE button_resources SET deleted_at = now(), updated_at = now()
             WHERE id = $1 AND (tenant_id = $2 OR tenant_id IS NULL)",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.button.deleted",
            "button",
            id,
            meta,
            json!({}),
        )
        .await?;
        Ok(())
    }

    pub async fn list_data_permissions(&self, tenant_id: Uuid) -> AppResult<Vec<DataPermission>> {
        Ok(sqlx::query_as::<_, DataPermission>(
            "SELECT * FROM data_permissions WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn create_data_permission(
        &self,
        tenant_id: Uuid,
        input: DataPermissionInput,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<DataPermission> {
        if !matches!(
            input.scope_type.as_str(),
            "all"
                | "self"
                | "department"
                | "department_and_children"
                | "departments"
                | "users"
                | "custom"
        ) {
            return Err(AppError::validation("scope_type", "数据范围类型非法"));
        }
        if input.role_id.is_none() && input.permission_id.is_none() {
            return Err(AppError::validation(
                "role_id",
                "数据权限必须绑定角色或权限",
            ));
        }
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO data_permissions
                (id, tenant_id, role_id, permission_id, scope_type, scope_config, description)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(input.role_id)
        .bind(input.permission_id)
        .bind(&input.scope_type)
        .bind(input.scope_config.unwrap_or_else(|| json!({})))
        .bind(&input.description)
        .execute(&self.pool)
        .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.data_permission.created",
            "data_permission",
            id,
            meta,
            json!({ "scope_type": input.scope_type }),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(
            sqlx::query_as::<_, DataPermission>("SELECT * FROM data_permissions WHERE id = $1")
                .bind(id)
                .fetch_one(&self.pool)
                .await?,
        )
    }

    pub async fn delete_data_permission(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        sqlx::query("DELETE FROM data_permissions WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.data_permission.deleted",
            "data_permission",
            id,
            meta,
            json!({}),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(())
    }

    pub async fn list_policies(&self, tenant_id: Uuid) -> AppResult<Vec<AuthorizationPolicy>> {
        Ok(sqlx::query_as::<_, AuthorizationPolicy>(
            "SELECT * FROM authorization_policies
             WHERE tenant_id = $1 OR tenant_id IS NULL ORDER BY priority, created_at",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn create_policy(
        &self,
        tenant_id: Uuid,
        input: PolicyInput,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<AuthorizationPolicy> {
        let name = input
            .name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| AppError::validation("name", "策略名称不能为空"))?;
        let effect = input.effect.as_deref().unwrap_or("allow");
        if !matches!(effect, "allow" | "deny") {
            return Err(AppError::validation("effect", "策略效果非法"));
        }
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO authorization_policies
                (id, tenant_id, name, description, effect, subject_type, subject_id, action,
                 resource_type, resource_id, condition, priority, enabled)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(name)
        .bind(&input.description)
        .bind(effect)
        .bind(&input.subject_type)
        .bind(&input.subject_id)
        .bind(&input.action)
        .bind(&input.resource_type)
        .bind(&input.resource_id)
        .bind(input.condition.unwrap_or_else(|| json!({})))
        .bind(input.priority.unwrap_or(100))
        .bind(input.enabled.unwrap_or(true))
        .execute(&self.pool)
        .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.policy.created",
            "policy",
            id,
            meta,
            json!({}),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(sqlx::query_as::<_, AuthorizationPolicy>(
            "SELECT * FROM authorization_policies WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&self.pool)
        .await?)
    }

    pub async fn delete_policy(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        sqlx::query(
            "DELETE FROM authorization_policies WHERE id = $1 AND (tenant_id = $2 OR tenant_id IS NULL)",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&self.pool)
        .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.policy.deleted",
            "policy",
            id,
            meta,
            json!({}),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(())
    }

    pub async fn add_resource_relation(
        &self,
        tenant_id: Uuid,
        resource_type: &str,
        resource_id: &str,
        relation: &str,
        subject_type: &str,
        subject_id: &str,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<Uuid> {
        if !matches!(
            relation,
            "owner" | "editor" | "viewer" | "member" | "admin" | "reader"
        ) {
            return Err(AppError::validation("relation", "资源关系类型非法"));
        }
        if !matches!(
            subject_type,
            "identity" | "role" | "organization" | "group" | "tenant"
        ) {
            return Err(AppError::validation("subject_type", "授权主体类型非法"));
        }
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO resource_relations
                (id, tenant_id, resource_type, resource_id, relation, subject_type, subject_id, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             ON CONFLICT (resource_type, resource_id, relation, subject_type, subject_id)
             DO UPDATE SET expires_at = EXCLUDED.expires_at",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(resource_type)
        .bind(resource_id)
        .bind(relation)
        .bind(subject_type)
        .bind(subject_id)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.resource_relation.created",
            "resource_relation",
            id,
            meta,
            json!({ "resource_type": resource_type, "relation": relation, "subject_type": subject_type }),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(id)
    }

    pub async fn remove_resource_relation(
        &self,
        tenant_id: Uuid,
        relation_id: Uuid,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        sqlx::query("DELETE FROM resource_relations WHERE id = $1 AND tenant_id = $2")
            .bind(relation_id)
            .bind(tenant_id)
            .execute(&self.pool)
            .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.resource_relation.deleted",
            "resource_relation",
            relation_id,
            meta,
            json!({}),
        )
        .await?;
        self.authz.invalidate_tenant(tenant_id).await?;
        Ok(())
    }

    pub async fn list_resource_relations(
        &self,
        tenant_id: Uuid,
        resource_type: &str,
        resource_id: &str,
    ) -> AppResult<Vec<ResourceRelation>> {
        Ok(sqlx::query_as::<_, ResourceRelation>(
            "SELECT * FROM resource_relations
             WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3
               AND (expires_at IS NULL OR expires_at > now())
             ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .bind(resource_type)
        .bind(resource_id)
        .fetch_all(&self.pool)
        .await?)
    }

    // ───────────────────────── 租户 ─────────────────────────

    pub async fn list_tenants(&self) -> AppResult<Vec<Tenant>> {
        Ok(sqlx::query_as::<_, Tenant>(
            "SELECT * FROM tenants WHERE deleted_at IS NULL ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn create_tenant(
        &self,
        code: &str,
        name: &str,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<Tenant> {
        let code = code.trim().to_lowercase();
        if code.len() < 2
            || !code
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
        {
            return Err(AppError::validation(
                "code",
                "租户编码只能包含小写字母、数字、- 和 _",
            ));
        }
        let id = Uuid::now_v7();
        sqlx::query("INSERT INTO tenants (id, code, name) VALUES ($1, $2, $3)")
            .bind(id)
            .bind(&code)
            .bind(name.trim())
            .execute(&self.pool)
            .await
            .map_err(|error| map_conflict(error, "租户编码已存在"))?;
        self.audit_admin(
            DEFAULT_TENANT_ID,
            actor,
            "auth.tenant.created",
            "tenant",
            id,
            meta,
            json!({ "code": code }),
        )
        .await?;
        sqlx::query_as::<_, Tenant>("SELECT * FROM tenants WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    pub async fn set_tenant_status(
        &self,
        tenant_id: Uuid,
        status: &str,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<Tenant> {
        if !matches!(status, "active" | "suspended" | "closed") {
            return Err(AppError::validation("status", "租户状态非法"));
        }
        sqlx::query("UPDATE tenants SET status = $2, updated_at = now() WHERE id = $1")
            .bind(tenant_id)
            .bind(status)
            .execute(&self.pool)
            .await?;
        if status != "active" {
            let identities: Vec<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM identities WHERE tenant_id = $1 AND deleted_at IS NULL",
            )
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
            for (identity_id,) in identities {
                self.revoke_all_sessions(identity_id, "tenant_suspended")
                    .await?;
            }
        }
        self.authz.invalidate_tenant(tenant_id).await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.tenant.status_changed",
            "tenant",
            tenant_id,
            meta,
            json!({ "status": status }),
        )
        .await?;
        sqlx::query_as::<_, Tenant>("SELECT * FROM tenants WHERE id = $1")
            .bind(tenant_id)
            .fetch_one(&self.pool)
            .await
            .map_err(Into::into)
    }

    // ───────────────────────── OAuth 客户端与 Scope ─────────────────────────

    pub async fn list_oauth_clients(&self, tenant_id: Uuid) -> AppResult<Vec<OAuthClient>> {
        Ok(sqlx::query_as::<_, OAuthClient>(
            "SELECT * FROM oauth_clients WHERE tenant_id = $1 ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create_oauth_client(
        &self,
        tenant_id: Uuid,
        client_id: Option<String>,
        name: &str,
        kind: &str,
        redirect_uris: Vec<String>,
        post_logout_redirect_uris: Vec<String>,
        grant_types: Vec<String>,
        scopes: Vec<String>,
        require_pkce: bool,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<(OAuthClient, Option<String>)> {
        if !matches!(kind, "confidential" | "public") {
            return Err(AppError::validation("kind", "客户端类型非法"));
        }
        if redirect_uris.is_empty() {
            return Err(AppError::validation(
                "redirect_uris",
                "至少配置一个回调地址",
            ));
        }
        for uri in &redirect_uris {
            self.validate_redirect_uri(uri).await?;
        }
        for uri in &post_logout_redirect_uris {
            self.validate_redirect_uri(uri).await?;
        }
        let allowed_grants = [
            "authorization_code",
            "refresh_token",
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code",
        ];
        for grant in &grant_types {
            if !allowed_grants.contains(&grant.as_str()) {
                return Err(AppError::validation(
                    "grant_types",
                    format!("不支持授权类型: {grant}"),
                ));
            }
        }
        if kind == "public" && grant_types.iter().any(|item| item == "client_credentials") {
            return Err(AppError::validation(
                "grant_types",
                "公共客户端不能使用 client_credentials",
            ));
        }
        let available: Vec<(String,)> =
            sqlx::query_as("SELECT name FROM oauth_scopes WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await?;
        let available: Vec<String> = available.into_iter().map(|row| row.0).collect();
        for scope in &scopes {
            if !available.contains(scope) {
                return Err(AppError::validation(
                    "scopes",
                    format!("未注册的 scope: {scope}"),
                ));
            }
        }
        let client_id =
            client_id.unwrap_or_else(|| format!("client_{}", &Uuid::now_v7().to_string()[..8]));
        if client_id.len() < 6 || client_id.len() > 100 {
            return Err(AppError::validation(
                "client_id",
                "client_id 长度必须为 6-100",
            ));
        }
        let plaintext_secret = if kind == "confidential" {
            Some(format!("cs_{}", crate::shared::random_token(36)))
        } else {
            None
        };
        let secret_hash = match &plaintext_secret {
            Some(secret) => Some(self.password.hash(secret.clone()).await?),
            None => None,
        };
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO oauth_clients
                (id, tenant_id, client_id, client_secret_hash, name, kind, redirect_uris,
                 post_logout_redirect_uris, grant_types, scopes, require_pkce)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&client_id)
        .bind(&secret_hash)
        .bind(name.trim())
        .bind(kind)
        .bind(serde_json::to_value(&redirect_uris)?)
        .bind(serde_json::to_value(&post_logout_redirect_uris)?)
        .bind(serde_json::to_value(&grant_types)?)
        .bind(serde_json::to_value(&scopes)?)
        .bind(require_pkce)
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "client_id 已存在"))?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.oauth_client.created",
            "oauth_client",
            id,
            meta,
            json!({ "client_id": client_id, "kind": kind }),
        )
        .await?;
        let client = sqlx::query_as::<_, OAuthClient>("SELECT * FROM oauth_clients WHERE id = $1")
            .bind(id)
            .fetch_one(&self.pool)
            .await?;
        Ok((client, plaintext_secret))
    }

    pub async fn rotate_client_secret(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<String> {
        let client = sqlx::query_as::<_, OAuthClient>(
            "SELECT * FROM oauth_clients WHERE client_id = $1 AND tenant_id = $2",
        )
        .bind(client_id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("客户端不存在"))?;
        if client.is_public() {
            return Err(AppError::conflict("公共客户端没有密钥"));
        }
        let secret = format!("cs_{}", crate::shared::random_token(36));
        let hash = self.password.hash(secret.clone()).await?;
        sqlx::query(
            "UPDATE oauth_clients SET client_secret_hash = $2, updated_at = now() WHERE id = $1",
        )
        .bind(client.id)
        .bind(hash)
        .execute(&self.pool)
        .await?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.oauth_client.secret_rotated",
            "oauth_client",
            client.id,
            meta,
            json!({ "client_id": client.client_id }),
        )
        .await?;
        Ok(secret)
    }

    pub async fn set_client_status(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        status: &str,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<OAuthClient> {
        if !matches!(status, "active" | "disabled") {
            return Err(AppError::validation("status", "客户端状态非法"));
        }
        let updated = sqlx::query(
            "UPDATE oauth_clients SET status = $3, updated_at = now()
             WHERE client_id = $1 AND tenant_id = $2",
        )
        .bind(client_id)
        .bind(tenant_id)
        .bind(status)
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() == 0 {
            return Err(AppError::not_found("客户端不存在"));
        }
        self.audit_admin(
            tenant_id,
            actor,
            "auth.oauth_client.status_changed",
            "oauth_client",
            Uuid::nil(),
            meta,
            json!({ "client_id": client_id, "status": status }),
        )
        .await?;
        sqlx::query_as::<_, OAuthClient>(
            "SELECT * FROM oauth_clients WHERE client_id = $1 AND tenant_id = $2",
        )
        .bind(client_id)
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    pub async fn list_oauth_scopes(&self, tenant_id: Uuid) -> AppResult<Vec<OAuthScope>> {
        Ok(sqlx::query_as::<_, OAuthScope>(
            "SELECT * FROM oauth_scopes WHERE tenant_id = $1 ORDER BY name",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?)
    }

    pub async fn create_oauth_scope(
        &self,
        tenant_id: Uuid,
        name: &str,
        description: Option<String>,
        is_default: bool,
        actor: Uuid,
        meta: &RequestMeta,
    ) -> AppResult<OAuthScope> {
        let name = name.trim();
        if name.len() < 2 || name.len() > 80 {
            return Err(AppError::validation("name", "scope 长度必须为 2-80"));
        }
        sqlx::query(
            "INSERT INTO oauth_scopes (tenant_id, name, description, is_default)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(&description)
        .bind(is_default)
        .execute(&self.pool)
        .await
        .map_err(|error| map_conflict(error, "scope 已存在"))?;
        self.audit_admin(
            tenant_id,
            actor,
            "auth.oauth_scope.created",
            "oauth_scope",
            Uuid::nil(),
            meta,
            json!({ "name": name }),
        )
        .await?;
        sqlx::query_as::<_, OAuthScope>(
            "SELECT * FROM oauth_scopes WHERE tenant_id = $1 AND name = $2",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_one(&self.pool)
        .await
        .map_err(Into::into)
    }

    // ───────────────────────── 审计与密钥 ─────────────────────────

    pub async fn list_audit_logs(
        &self,
        tenant_id: Option<Uuid>,
        action: Option<&str>,
        actor_id: Option<Uuid>,
        result: Option<&str>,
        query: &PageQuery,
    ) -> AppResult<(Vec<AuditLog>, i64)> {
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM security_audit_logs
             WHERE ($1::uuid IS NULL OR tenant_id = $1)
               AND ($2::text IS NULL OR action ILIKE $2)
               AND ($3::uuid IS NULL OR actor_id = $3)
               AND ($4::text IS NULL OR result = $4)",
        )
        .bind(tenant_id)
        .bind(action)
        .bind(actor_id)
        .bind(result)
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query_as::<_, AuditLog>(
            "SELECT * FROM security_audit_logs
             WHERE ($1::uuid IS NULL OR tenant_id = $1)
               AND ($2::text IS NULL OR action ILIKE $2)
               AND ($3::uuid IS NULL OR actor_id = $3)
               AND ($4::text IS NULL OR result = $4)
             ORDER BY id DESC LIMIT $5 OFFSET $6",
        )
        .bind(tenant_id)
        .bind(action)
        .bind(actor_id)
        .bind(result)
        .bind(query.limit())
        .bind(query.offset())
        .fetch_all(&self.pool)
        .await?;
        Ok((rows, total))
    }

    pub async fn list_signing_keys(&self) -> AppResult<Vec<Value>> {
        let rows: Vec<(
            Uuid,
            String,
            String,
            Value,
            String,
            chrono::DateTime<chrono::Utc>,
            Option<chrono::DateTime<chrono::Utc>>,
        )> = sqlx::query_as(
            "SELECT id, kid, algorithm, public_jwk, status, created_at, not_after
                 FROM signing_keys ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| {
                json!({
                    "id": row.0, "kid": row.1, "algorithm": row.2, "public_jwk": row.3,
                    "status": row.4, "created_at": row.5, "not_after": row.6,
                })
            })
            .collect())
    }

    pub async fn rotate_signing_key(&self, actor: Uuid, meta: &RequestMeta) -> AppResult<String> {
        let kid = self.keys.rotate().await?;
        self.audit_admin(
            DEFAULT_TENANT_ID,
            actor,
            "auth.signing_key.rotated",
            "signing_key",
            Uuid::nil(),
            meta,
            json!({ "kid": kid }),
        )
        .await?;
        Ok(kid)
    }

    // ───────────────────────── 授权视图 ─────────────────────────

    pub async fn my_authorization(
        &self,
        identity_id: Uuid,
        tenant_id: Uuid,
    ) -> AppResult<MyAuthorization> {
        let grants = self.authz.effective_grants(identity_id, tenant_id).await?;
        let mut permissions: Vec<String> = grants.permissions.iter().cloned().collect();
        permissions.sort();
        Ok(MyAuthorization {
            identity_id,
            tenant_id,
            roles: grants.roles,
            permissions,
            data_permissions: grants.data_permissions,
        })
    }

    pub async fn my_menus(
        &self,
        identity_id: Uuid,
        tenant_id: Uuid,
    ) -> AppResult<Vec<MenuTreeNode>> {
        let grants = self.authz.effective_grants(identity_id, tenant_id).await?;
        let menus = self.list_menus(tenant_id).await?;
        let permission_ids: Vec<Uuid> = {
            let rows: Vec<(Uuid, String)> =
                sqlx::query_as("SELECT id, code FROM permissions WHERE deleted_at IS NULL")
                    .fetch_all(&self.pool)
                    .await?;
            rows.into_iter()
                .filter(|(_, code)| grants.permissions.contains(code))
                .map(|(id, _)| id)
                .collect()
        };
        let visible: Vec<MenuResource> = menus
            .into_iter()
            .filter(|menu| {
                menu.visible
                    && menu.status == "active"
                    && menu
                        .permission_id
                        .map(|id| permission_ids.contains(&id))
                        .unwrap_or(true)
            })
            .collect();
        fn build(parent: Option<Uuid>, all: &[MenuResource]) -> Vec<MenuTreeNode> {
            all.iter()
                .filter(|item| item.parent_id == parent)
                .map(|item| MenuTreeNode {
                    id: item.id,
                    code: item.code.clone(),
                    name: item.name.clone(),
                    route: item.route.clone(),
                    icon: item.icon.clone(),
                    menu_type: item.menu_type.clone(),
                    sort_order: item.sort_order,
                    visible: item.visible,
                    children: build(Some(item.id), all),
                })
                .collect()
        }
        Ok(build(None, &visible))
    }

    pub async fn my_buttons(&self, identity_id: Uuid, tenant_id: Uuid) -> AppResult<Vec<String>> {
        let grants = self.authz.effective_grants(identity_id, tenant_id).await?;
        let rows: Vec<(String, Option<String>)> = sqlx::query_as(
            "SELECT b.code, p.code FROM button_resources b
             LEFT JOIN permissions p ON p.id = b.permission_id
             WHERE b.deleted_at IS NULL AND b.status = 'active'
               AND (b.tenant_id = $1 OR b.tenant_id IS NULL)",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter(|(_, permission)| {
                permission
                    .as_ref()
                    .map(|code| grants.permissions.contains(code))
                    .unwrap_or(false)
            })
            .map(|(code, _)| code)
            .collect())
    }

    pub async fn my_api_permissions(
        &self,
        identity_id: Uuid,
        tenant_id: Uuid,
    ) -> AppResult<Vec<Value>> {
        let grants = self.authz.effective_grants(identity_id, tenant_id).await?;
        let rows: Vec<(String, String, Option<String>)> = sqlx::query_as(
            "SELECT a.method, a.path_pattern, p.code FROM api_resources a
             LEFT JOIN permissions p ON p.id = a.permission_id
             WHERE a.deleted_at IS NULL AND a.status = 'active'
               AND (a.tenant_id = $1 OR a.tenant_id IS NULL)",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .filter(|(_, _, permission)| {
                permission
                    .as_ref()
                    .map(|code| grants.permissions.contains(code))
                    .unwrap_or(false)
            })
            .map(|(method, path, permission)| {
                json!({ "method": method, "path": path, "permission": permission })
            })
            .collect())
    }

    pub async fn my_data_scope(
        &self,
        identity_id: Uuid,
        tenant_id: Uuid,
        permission: &str,
    ) -> AppResult<crate::domain::DataScope> {
        if permission.trim().is_empty() {
            return Ok(crate::domain::DataScope::self_only(tenant_id, identity_id));
        }
        let decision = self
            .authz
            .check(&crate::domain::AuthzRequest {
                subject_id: identity_id,
                tenant_id,
                permission: permission.to_string(),
                resource: None,
                context: json!({}),
            })
            .await?;
        if !decision.allowed {
            return Err(AppError::forbidden("没有该权限"));
        }
        Ok(decision
            .data_scope
            .unwrap_or_else(|| crate::domain::DataScope::self_only(tenant_id, identity_id)))
    }

    // ───────────────────────── 辅助 ─────────────────────────

    pub async fn validate_redirect_uri(&self, uri: &str) -> AppResult<()> {
        let parsed = url::Url::parse(uri)
            .map_err(|_| AppError::validation("redirect_uris", "回调地址不是合法 URL"))?;
        if parsed.fragment().is_some() {
            return Err(AppError::validation(
                "redirect_uris",
                "回调地址不允许包含片段",
            ));
        }
        match parsed.scheme() {
            "https" => Ok(()),
            "http" if self.config.oauth.allow_http_redirect_uri => Ok(()),
            "http" => Err(AppError::validation(
                "redirect_uris",
                "生产环境回调地址必须使用 HTTPS",
            )),
            "urn" => Ok(()),
            _ => Err(AppError::validation("redirect_uris", "不支持的回调协议")),
        }
    }

    async fn audit_admin(
        &self,
        tenant_id: Uuid,
        actor: Uuid,
        action: &str,
        resource_type: &str,
        resource_id: Uuid,
        meta: &RequestMeta,
        detail: Value,
    ) -> AppResult<()> {
        audit::record(
            &self.pool,
            AuditEntry::new(action)
                .tenant(tenant_id)
                .actor(actor)
                .resource(resource_type, resource_id.to_string())
                .request_context(
                    meta.ip.clone(),
                    meta.user_agent.clone(),
                    meta.trace_id.clone(),
                )
                .detail(detail),
        )
        .await
    }
}

fn map_conflict(error: sqlx::Error, message: &str) -> AppError {
    if let sqlx::Error::Database(db_error) = &error {
        if db_error.code().as_deref() == Some("23505") {
            return AppError::conflict(message);
        }
    }
    error.into()
}
