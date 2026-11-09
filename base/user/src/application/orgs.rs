//! 组织与部门：树形结构、成员、负责人、调动与历史。

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::application::users::EVENT_ORG_CHANGED;
use crate::bootstrap::AppState;
use crate::domain::{Department, Organization, User};
use crate::infrastructure::outbox::{self, OutboxEvent};
use crate::shared::{AppError, AppResult, Page, PageQuery, RequestMeta};

#[derive(Debug, Clone, Deserialize)]
pub struct OrganizationInput {
    #[serde(default)]
    pub parent_id: Option<Uuid>,
    #[serde(default = "default_kind")]
    pub kind: String,
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub leader_id: Option<Uuid>,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub extra: Value,
    #[serde(default)]
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DepartmentInput {
    pub organization_id: Uuid,
    #[serde(default)]
    pub parent_id: Option<Uuid>,
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub leader_id: Option<Uuid>,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub extra: Value,
    #[serde(default)]
    pub sort_order: i32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemberInput {
    pub user_id: Uuid,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub is_primary: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TransferInput {
    pub user_id: Uuid,
    pub organization_id: Uuid,
    #[serde(default)]
    pub department_id: Option<Uuid>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default = "default_true")]
    pub is_primary: bool,
    #[serde(default)]
    pub reason: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_kind() -> String {
    "company".to_string()
}

fn default_status() -> String {
    "active".to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct OrganizationNode {
    #[serde(flatten)]
    pub organization: Organization,
    pub children: Vec<OrganizationNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DepartmentNode {
    #[serde(flatten)]
    pub department: Department,
    pub children: Vec<DepartmentNode>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MembershipView {
    pub organization_id: Uuid,
    pub organization_name: Option<String>,
    pub department_id: Option<Uuid>,
    pub department_name: Option<String>,
    pub department_path: Option<String>,
    pub title: Option<String>,
    pub is_primary: bool,
    pub joined_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryView {
    pub id: Uuid,
    pub action: String,
    pub organization_id: Option<Uuid>,
    pub department_id: Option<Uuid>,
    pub detail: Value,
    pub operator_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

const ORG_COLUMNS: &str = "id, tenant_id, parent_id, kind, code, name, description, path, level,
     leader_id, status, extra, sort_order, created_at, updated_at, deleted_at";
const DEPT_COLUMNS: &str = "id, tenant_id, organization_id, parent_id, code, name, description,
     path, level, leader_id, status, extra, sort_order, created_at, updated_at, deleted_at";

fn validate_code(code: &str, field: &str) -> AppResult<()> {
    let code = code.trim();
    if code.len() < 2 || code.len() > 64 {
        return Err(AppError::validation(field, "编码长度需在 2-64 之间"));
    }
    if !code
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
    {
        return Err(AppError::validation(
            field,
            "编码仅允许字母、数字、下划线、点和短横线",
        ));
    }
    Ok(())
}

fn map_unique(error: sqlx::Error, message: &str) -> AppError {
    if let sqlx::Error::Database(db_error) = &error {
        if db_error.code().as_deref() == Some("23505") {
            return AppError::conflict(message);
        }
    }
    error.into()
}

impl AppState {
    pub async fn get_organization(&self, tenant_id: Uuid, id: Uuid) -> AppResult<Organization> {
        sqlx::query_as::<_, Organization>(&format!(
            "SELECT {ORG_COLUMNS} FROM organizations
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL"
        ))
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("组织不存在"))
    }

    pub async fn get_department(&self, tenant_id: Uuid, id: Uuid) -> AppResult<Department> {
        sqlx::query_as::<_, Department>(&format!(
            "SELECT {DEPT_COLUMNS} FROM departments
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL"
        ))
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("部门不存在"))
    }

    pub async fn list_organizations(
        &self,
        tenant_id: Uuid,
        page: &PageQuery,
    ) -> AppResult<Page<Organization>> {
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organizations WHERE tenant_id = $1 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query_as::<_, Organization>(&format!(
            "SELECT {ORG_COLUMNS} FROM organizations
              WHERE tenant_id = $1 AND deleted_at IS NULL
              ORDER BY path, sort_order LIMIT $2 OFFSET $3"
        ))
        .bind(tenant_id)
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(&self.pool)
        .await?;
        Ok(Page::new(rows, total, page))
    }

    pub async fn organization_tree(&self, tenant_id: Uuid) -> AppResult<Vec<OrganizationNode>> {
        let rows = sqlx::query_as::<_, Organization>(&format!(
            "SELECT {ORG_COLUMNS} FROM organizations
              WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY path"
        ))
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(build_org_tree(rows))
    }

    pub async fn create_organization(
        &self,
        tenant_id: Uuid,
        input: &OrganizationInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<Organization> {
        validate_code(&input.code, "code")?;
        if input.name.trim().is_empty() {
            return Err(AppError::validation("name", "组织名称不能为空"));
        }
        if !matches!(
            input.kind.as_str(),
            "company" | "department" | "team" | "other"
        ) {
            return Err(AppError::validation("kind", "组织类型不合法"));
        }
        let (parent_path, level) = match input.parent_id {
            Some(parent_id) => {
                let parent = self.get_organization(tenant_id, parent_id).await?;
                (parent.path, parent.level + 1)
            }
            None => (String::new(), 0),
        };
        if let Some(leader_id) = input.leader_id {
            self.get_user(tenant_id, leader_id).await?;
        }
        let id = Uuid::now_v7();
        let path = if parent_path.is_empty() {
            format!("/{id}")
        } else {
            format!("{}/{id}", parent_path.trim_end_matches('/'))
        };
        let row = sqlx::query_as::<_, Organization>(&format!(
            "INSERT INTO organizations
                (id, tenant_id, parent_id, kind, code, name, description, path, level, leader_id,
                 status, extra, sort_order)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING {ORG_COLUMNS}"
        ))
        .bind(id)
        .bind(tenant_id)
        .bind(input.parent_id)
        .bind(&input.kind)
        .bind(input.code.trim())
        .bind(input.name.trim())
        .bind(input.description.as_deref())
        .bind(&path)
        .bind(level)
        .bind(input.leader_id)
        .bind(&input.status)
        .bind(if input.extra.is_null() {
            json!({})
        } else {
            input.extra.clone()
        })
        .bind(input.sort_order)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| map_unique(error, "组织编码已存在"))?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.organization.created")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("organization", id.to_string())
                .detail(json!({ "code": row.code }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(row)
    }

    pub async fn update_organization(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: &OrganizationInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<Organization> {
        validate_code(&input.code, "code")?;
        let current = self.get_organization(tenant_id, id).await?;
        let (parent_path, new_level) = match input.parent_id {
            Some(parent_id) => {
                if parent_id == id {
                    return Err(AppError::validation(
                        "parent_id",
                        "组织不能作为自己的父节点",
                    ));
                }
                let parent = self.get_organization(tenant_id, parent_id).await?;
                if parent.path == current.path
                    || parent.path.starts_with(&format!("{}/", current.path))
                {
                    return Err(AppError::validation(
                        "parent_id",
                        "不能移动到自己的子组织下",
                    ));
                }
                (parent.path, parent.level + 1)
            }
            None => (String::new(), 0),
        };
        if let Some(leader_id) = input.leader_id {
            self.get_user(tenant_id, leader_id).await?;
        }
        let new_path = if parent_path.is_empty() {
            format!("/{id}")
        } else {
            format!("{}/{id}", parent_path.trim_end_matches('/'))
        };
        let old_path = current.path.clone();
        let delta = new_level - current.level;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE organizations SET parent_id = $2, kind = $3, code = $4, name = $5,
                    description = $6, path = $7, level = $8, leader_id = $9, status = $10,
                    extra = $11, sort_order = $12, updated_at = now()
              WHERE id = $1 AND tenant_id = $13 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(input.parent_id)
        .bind(&input.kind)
        .bind(input.code.trim())
        .bind(input.name.trim())
        .bind(input.description.as_deref())
        .bind(&new_path)
        .bind(new_level)
        .bind(input.leader_id)
        .bind(&input.status)
        .bind(if input.extra.is_null() {
            json!({})
        } else {
            input.extra.clone()
        })
        .bind(input.sort_order)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        if old_path != new_path {
            sqlx::query(
                "UPDATE organizations
                    SET path = $1 || substring(path from $2), level = level + $3, updated_at = now()
                  WHERE tenant_id = $4 AND path LIKE $5 AND deleted_at IS NULL",
            )
            .bind(&new_path)
            .bind((old_path.len() + 1) as i32)
            .bind(delta)
            .bind(tenant_id)
            .bind(format!("{old_path}/%"))
            .execute(&mut *tx)
            .await?;
        }
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.organization.updated")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("organization", id.to_string());
            entry.request_context(meta);
            entry
        })
        .await?;
        tx.commit().await?;
        self.get_organization(tenant_id, id).await
    }

    pub async fn delete_organization(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        self.get_organization(tenant_id, id).await?;
        let children: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organizations
              WHERE tenant_id = $1 AND parent_id = $2 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        if children > 0 {
            return Err(AppError::conflict("请先删除子组织"));
        }
        let affected: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT user_id FROM organization_members
              WHERE organization_id = $1 AND left_at IS NULL
             UNION
             SELECT DISTINCT dm.user_id FROM department_members dm
              JOIN departments d ON d.id = dm.department_id
             WHERE d.organization_id = $1 AND dm.left_at IS NULL",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE departments SET deleted_at = now(), status = 'disabled', updated_at = now()
              WHERE organization_id = $1 AND deleted_at IS NULL",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE organizations SET deleted_at = now(), status = 'disabled', updated_at = now()
              WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM organization_members WHERE organization_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM department_members WHERE department_id IN
                (SELECT id FROM departments WHERE organization_id = $1)",
        )
        .bind(id)
        .execute(&mut *tx)
        .await?;
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.organization.deleted")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("organization", id.to_string());
            entry.request_context(meta);
            entry
        })
        .await?;
        for user_id in affected {
            emit_membership_event(&mut tx, tenant_id, user_id, meta.trace_id.clone()).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_organization_leader(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        leader_id: Option<Uuid>,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<Organization> {
        self.get_organization(tenant_id, id).await?;
        if let Some(leader_id) = leader_id {
            self.get_user(tenant_id, leader_id).await?;
        }
        let row = sqlx::query_as::<_, Organization>(&format!(
            "UPDATE organizations SET leader_id = $3, updated_at = now()
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL RETURNING {ORG_COLUMNS}"
        ))
        .bind(id)
        .bind(tenant_id)
        .bind(leader_id)
        .fetch_one(&self.pool)
        .await?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.organization.leader_changed")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("organization", id.to_string())
                .detail(json!({ "leader_id": leader_id }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(row)
    }

    pub async fn add_organization_member(
        &self,
        tenant_id: Uuid,
        organization_id: Uuid,
        input: &MemberInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        self.get_organization(tenant_id, organization_id).await?;
        self.get_user(tenant_id, input.user_id).await?;
        let mut tx = self.pool.begin().await?;
        if input.is_primary {
            sqlx::query(
                "UPDATE organization_members SET is_primary = FALSE
                  WHERE user_id = $1 AND tenant_id = $2 AND left_at IS NULL",
            )
            .bind(input.user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "INSERT INTO organization_members
                (organization_id, user_id, tenant_id, title, is_primary, joined_at, left_at)
             VALUES ($1, $2, $3, $4, $5, now(), NULL)
             ON CONFLICT (organization_id, user_id) DO UPDATE SET
                title = EXCLUDED.title, is_primary = EXCLUDED.is_primary,
                joined_at = now(), left_at = NULL",
        )
        .bind(organization_id)
        .bind(input.user_id)
        .bind(tenant_id)
        .bind(input.title.as_deref())
        .bind(input.is_primary)
        .execute(&mut *tx)
        .await?;
        record_history(
            &mut tx,
            tenant_id,
            input.user_id,
            Some(organization_id),
            None,
            "join",
            actor_id,
            json!({ "title": input.title, "is_primary": input.is_primary }),
        )
        .await?;
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.organization.member_added")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("organization", organization_id.to_string())
                .detail(json!({ "user_id": input.user_id }));
            entry.request_context(meta);
            entry
        })
        .await?;
        emit_membership_event(&mut tx, tenant_id, input.user_id, meta.trace_id.clone()).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn remove_organization_member(
        &self,
        tenant_id: Uuid,
        organization_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        self.get_organization(tenant_id, organization_id).await?;
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE organization_members SET left_at = now(), is_primary = FALSE
              WHERE organization_id = $1 AND user_id = $2 AND left_at IS NULL",
        )
        .bind(organization_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::not_found("成员关系不存在"));
        }
        record_history(
            &mut tx,
            tenant_id,
            user_id,
            Some(organization_id),
            None,
            "leave",
            actor_id,
            json!({}),
        )
        .await?;
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.organization.member_removed")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("organization", organization_id.to_string())
                .detail(json!({ "user_id": user_id }));
            entry.request_context(meta);
            entry
        })
        .await?;
        emit_membership_event(&mut tx, tenant_id, user_id, meta.trace_id.clone()).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_organization_members(
        &self,
        tenant_id: Uuid,
        organization_id: Uuid,
        page: &PageQuery,
    ) -> AppResult<Page<User>> {
        self.get_organization(tenant_id, organization_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM organization_members m
               JOIN users u ON u.id = m.user_id AND u.deleted_at IS NULL
              WHERE m.organization_id = $1 AND m.left_at IS NULL",
        )
        .bind(organization_id)
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query_as::<_, User>(
            "SELECT u.id, u.tenant_id, u.username, u.email, u.email_verified, u.phone,
                    u.phone_verified, u.display_name, u.avatar_url, u.status, u.source, u.remark,
                    u.last_active_at, u.last_login_at, u.registered_at, u.version, u.created_at,
                    u.updated_at, u.deleted_at
               FROM organization_members m
               JOIN users u ON u.id = m.user_id AND u.deleted_at IS NULL
              WHERE m.organization_id = $1 AND m.left_at IS NULL
              ORDER BY m.is_primary DESC, m.joined_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(organization_id)
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(&self.pool)
        .await?;
        Ok(Page::new(rows, total, page))
    }

    // ───────────────────────── 部门 ─────────────────────────

    pub async fn list_departments(
        &self,
        tenant_id: Uuid,
        organization_id: Option<Uuid>,
        page: &PageQuery,
    ) -> AppResult<Page<Department>> {
        let total: i64 =
            match organization_id {
                Some(organization_id) => {
                    sqlx::query_scalar(
                        "SELECT count(*) FROM departments
                  WHERE tenant_id = $1 AND organization_id = $2 AND deleted_at IS NULL",
                    )
                    .bind(tenant_id)
                    .bind(organization_id)
                    .fetch_one(&self.pool)
                    .await?
                }
                None => sqlx::query_scalar(
                    "SELECT count(*) FROM departments WHERE tenant_id = $1 AND deleted_at IS NULL",
                )
                .bind(tenant_id)
                .fetch_one(&self.pool)
                .await?,
            };
        let rows = match organization_id {
            Some(organization_id) => {
                sqlx::query_as::<_, Department>(&format!(
                    "SELECT {DEPT_COLUMNS} FROM departments
                      WHERE tenant_id = $1 AND organization_id = $2 AND deleted_at IS NULL
                      ORDER BY path, sort_order LIMIT $3 OFFSET $4"
                ))
                .bind(tenant_id)
                .bind(organization_id)
                .bind(page.limit())
                .bind(page.offset())
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, Department>(&format!(
                    "SELECT {DEPT_COLUMNS} FROM departments
                      WHERE tenant_id = $1 AND deleted_at IS NULL
                      ORDER BY organization_id, path, sort_order LIMIT $2 OFFSET $3"
                ))
                .bind(tenant_id)
                .bind(page.limit())
                .bind(page.offset())
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(Page::new(rows, total, page))
    }

    pub async fn department_tree(
        &self,
        tenant_id: Uuid,
        organization_id: Option<Uuid>,
    ) -> AppResult<Vec<DepartmentNode>> {
        let rows = match organization_id {
            Some(organization_id) => {
                sqlx::query_as::<_, Department>(&format!(
                    "SELECT {DEPT_COLUMNS} FROM departments
                      WHERE tenant_id = $1 AND organization_id = $2 AND deleted_at IS NULL
                      ORDER BY path"
                ))
                .bind(tenant_id)
                .bind(organization_id)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as::<_, Department>(&format!(
                    "SELECT {DEPT_COLUMNS} FROM departments
                      WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY organization_id, path"
                ))
                .bind(tenant_id)
                .fetch_all(&self.pool)
                .await?
            }
        };
        Ok(build_department_tree(rows))
    }

    pub async fn create_department(
        &self,
        tenant_id: Uuid,
        input: &DepartmentInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<Department> {
        validate_code(&input.code, "code")?;
        if input.name.trim().is_empty() {
            return Err(AppError::validation("name", "部门名称不能为空"));
        }
        let organization = self
            .get_organization(tenant_id, input.organization_id)
            .await?;
        let (parent_path, level) = match input.parent_id {
            Some(parent_id) => {
                let parent = self.get_department(tenant_id, parent_id).await?;
                if parent.organization_id != organization.id {
                    return Err(AppError::validation("parent_id", "父部门必须属于同一组织"));
                }
                (parent.path, parent.level + 1)
            }
            None => (String::new(), 0),
        };
        if let Some(leader_id) = input.leader_id {
            self.get_user(tenant_id, leader_id).await?;
        }
        let id = Uuid::now_v7();
        let path = if parent_path.is_empty() {
            format!("/{id}")
        } else {
            format!("{}/{id}", parent_path.trim_end_matches('/'))
        };
        let row = sqlx::query_as::<_, Department>(&format!(
            "INSERT INTO departments
                (id, tenant_id, organization_id, parent_id, code, name, description, path, level,
                 leader_id, status, extra, sort_order)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
             RETURNING {DEPT_COLUMNS}"
        ))
        .bind(id)
        .bind(tenant_id)
        .bind(input.organization_id)
        .bind(input.parent_id)
        .bind(input.code.trim())
        .bind(input.name.trim())
        .bind(input.description.as_deref())
        .bind(&path)
        .bind(level)
        .bind(input.leader_id)
        .bind(&input.status)
        .bind(if input.extra.is_null() {
            json!({})
        } else {
            input.extra.clone()
        })
        .bind(input.sort_order)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| map_unique(error, "部门编码已存在"))?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.department.created")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("department", id.to_string())
                .detail(json!({ "code": row.code }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(row)
    }

    pub async fn update_department(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: &DepartmentInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<Department> {
        validate_code(&input.code, "code")?;
        let current = self.get_department(tenant_id, id).await?;
        let organization = self
            .get_organization(tenant_id, input.organization_id)
            .await?;
        let (parent_path, new_level) = match input.parent_id {
            Some(parent_id) => {
                if parent_id == id {
                    return Err(AppError::validation(
                        "parent_id",
                        "部门不能作为自己的父节点",
                    ));
                }
                let parent = self.get_department(tenant_id, parent_id).await?;
                if parent.organization_id != organization.id {
                    return Err(AppError::validation("parent_id", "父部门必须属于同一组织"));
                }
                if parent.path == current.path
                    || parent.path.starts_with(&format!("{}/", current.path))
                {
                    return Err(AppError::validation(
                        "parent_id",
                        "不能移动到自己的子部门下",
                    ));
                }
                (parent.path, parent.level + 1)
            }
            None => (String::new(), 0),
        };
        if let Some(leader_id) = input.leader_id {
            self.get_user(tenant_id, leader_id).await?;
        }
        let new_path = if parent_path.is_empty() {
            format!("/{id}")
        } else {
            format!("{}/{id}", parent_path.trim_end_matches('/'))
        };
        let old_path = current.path.clone();
        let delta = new_level - current.level;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE departments SET organization_id = $2, parent_id = $3, code = $4, name = $5,
                    description = $6, path = $7, level = $8, leader_id = $9, status = $10,
                    extra = $11, sort_order = $12, updated_at = now()
              WHERE id = $1 AND tenant_id = $13 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(input.organization_id)
        .bind(input.parent_id)
        .bind(input.code.trim())
        .bind(input.name.trim())
        .bind(input.description.as_deref())
        .bind(&new_path)
        .bind(new_level)
        .bind(input.leader_id)
        .bind(&input.status)
        .bind(if input.extra.is_null() {
            json!({})
        } else {
            input.extra.clone()
        })
        .bind(input.sort_order)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        if old_path != new_path {
            sqlx::query(
                "UPDATE departments
                    SET path = $1 || substring(path from $2), level = level + $3, updated_at = now()
                  WHERE tenant_id = $4 AND path LIKE $5 AND deleted_at IS NULL",
            )
            .bind(&new_path)
            .bind((old_path.len() + 1) as i32)
            .bind(delta)
            .bind(tenant_id)
            .bind(format!("{old_path}/%"))
            .execute(&mut *tx)
            .await?;
        }
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.department.updated")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("department", id.to_string());
            entry.request_context(meta);
            entry
        })
        .await?;
        tx.commit().await?;
        self.get_department(tenant_id, id).await
    }

    pub async fn delete_department(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        self.get_department(tenant_id, id).await?;
        let children: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM departments
              WHERE tenant_id = $1 AND parent_id = $2 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        if children > 0 {
            return Err(AppError::conflict("请先删除子部门"));
        }
        let affected: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT user_id FROM department_members
              WHERE department_id = $1 AND left_at IS NULL",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE departments SET deleted_at = now(), status = 'disabled', updated_at = now()
              WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM department_members WHERE department_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.department.deleted")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("department", id.to_string());
            entry.request_context(meta);
            entry
        })
        .await?;
        for user_id in affected {
            emit_membership_event(&mut tx, tenant_id, user_id, meta.trace_id.clone()).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    pub async fn set_department_leader(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        leader_id: Option<Uuid>,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<Department> {
        self.get_department(tenant_id, id).await?;
        if let Some(leader_id) = leader_id {
            self.get_user(tenant_id, leader_id).await?;
        }
        let row = sqlx::query_as::<_, Department>(&format!(
            "UPDATE departments SET leader_id = $3, updated_at = now()
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL RETURNING {DEPT_COLUMNS}"
        ))
        .bind(id)
        .bind(tenant_id)
        .bind(leader_id)
        .fetch_one(&self.pool)
        .await?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.department.leader_changed")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("department", id.to_string())
                .detail(json!({ "leader_id": leader_id }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(row)
    }

    pub async fn add_department_member(
        &self,
        tenant_id: Uuid,
        department_id: Uuid,
        input: &MemberInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let department = self.get_department(tenant_id, department_id).await?;
        self.get_user(tenant_id, input.user_id).await?;
        let mut tx = self.pool.begin().await?;
        if input.is_primary {
            sqlx::query(
                "UPDATE department_members SET is_primary = FALSE
                  WHERE user_id = $1 AND tenant_id = $2 AND left_at IS NULL",
            )
            .bind(input.user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "INSERT INTO department_members
                (department_id, user_id, tenant_id, title, is_primary, joined_at, left_at)
             VALUES ($1, $2, $3, $4, $5, now(), NULL)
             ON CONFLICT (department_id, user_id) DO UPDATE SET
                title = EXCLUDED.title, is_primary = EXCLUDED.is_primary,
                joined_at = now(), left_at = NULL",
        )
        .bind(department_id)
        .bind(input.user_id)
        .bind(tenant_id)
        .bind(input.title.as_deref())
        .bind(input.is_primary)
        .execute(&mut *tx)
        .await?;
        record_history(
            &mut tx,
            tenant_id,
            input.user_id,
            Some(department.organization_id),
            Some(department_id),
            "join",
            actor_id,
            json!({ "title": input.title, "is_primary": input.is_primary }),
        )
        .await?;
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.department.member_added")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("department", department_id.to_string())
                .detail(json!({ "user_id": input.user_id }));
            entry.request_context(meta);
            entry
        })
        .await?;
        emit_membership_event(&mut tx, tenant_id, input.user_id, meta.trace_id.clone()).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn remove_department_member(
        &self,
        tenant_id: Uuid,
        department_id: Uuid,
        user_id: Uuid,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        let department = self.get_department(tenant_id, department_id).await?;
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query(
            "UPDATE department_members SET left_at = now(), is_primary = FALSE
              WHERE department_id = $1 AND user_id = $2 AND left_at IS NULL",
        )
        .bind(department_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AppError::not_found("成员关系不存在"));
        }
        record_history(
            &mut tx,
            tenant_id,
            user_id,
            Some(department.organization_id),
            Some(department_id),
            "leave",
            actor_id,
            json!({}),
        )
        .await?;
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.department.member_removed")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("department", department_id.to_string())
                .detail(json!({ "user_id": user_id }));
            entry.request_context(meta);
            entry
        })
        .await?;
        emit_membership_event(&mut tx, tenant_id, user_id, meta.trace_id.clone()).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_department_members(
        &self,
        tenant_id: Uuid,
        department_id: Uuid,
        page: &PageQuery,
    ) -> AppResult<Page<User>> {
        self.get_department(tenant_id, department_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM department_members m
               JOIN users u ON u.id = m.user_id AND u.deleted_at IS NULL
              WHERE m.department_id = $1 AND m.left_at IS NULL",
        )
        .bind(department_id)
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query_as::<_, User>(
            "SELECT u.id, u.tenant_id, u.username, u.email, u.email_verified, u.phone,
                    u.phone_verified, u.display_name, u.avatar_url, u.status, u.source, u.remark,
                    u.last_active_at, u.last_login_at, u.registered_at, u.version, u.created_at,
                    u.updated_at, u.deleted_at
               FROM department_members m
               JOIN users u ON u.id = m.user_id AND u.deleted_at IS NULL
              WHERE m.department_id = $1 AND m.left_at IS NULL
              ORDER BY m.is_primary DESC, m.joined_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(department_id)
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(&self.pool)
        .await?;
        Ok(Page::new(rows, total, page))
    }

    /// 用户调动：设置主组织/主部门，保留其他兼职关系。
    pub async fn transfer_user(
        &self,
        tenant_id: Uuid,
        input: &TransferInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        self.get_user(tenant_id, input.user_id).await?;
        let organization = self
            .get_organization(tenant_id, input.organization_id)
            .await?;
        let department = match input.department_id {
            Some(department_id) => {
                let department = self.get_department(tenant_id, department_id).await?;
                if department.organization_id != organization.id {
                    return Err(AppError::validation("department_id", "部门不属于指定组织"));
                }
                Some(department)
            }
            None => None,
        };
        let mut tx = self.pool.begin().await?;
        if input.is_primary {
            sqlx::query(
                "UPDATE organization_members SET is_primary = FALSE
                  WHERE user_id = $1 AND tenant_id = $2 AND left_at IS NULL",
            )
            .bind(input.user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE department_members SET is_primary = FALSE
                  WHERE user_id = $1 AND tenant_id = $2 AND left_at IS NULL",
            )
            .bind(input.user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        }
        sqlx::query(
            "INSERT INTO organization_members
                (organization_id, user_id, tenant_id, title, is_primary, joined_at, left_at)
             VALUES ($1, $2, $3, $4, $5, now(), NULL)
             ON CONFLICT (organization_id, user_id) DO UPDATE SET
                title = EXCLUDED.title, is_primary = EXCLUDED.is_primary,
                joined_at = now(), left_at = NULL",
        )
        .bind(organization.id)
        .bind(input.user_id)
        .bind(tenant_id)
        .bind(input.title.as_deref())
        .bind(input.is_primary)
        .execute(&mut *tx)
        .await?;
        if let Some(department) = &department {
            sqlx::query(
                "INSERT INTO department_members
                    (department_id, user_id, tenant_id, title, is_primary, joined_at, left_at)
                 VALUES ($1, $2, $3, $4, $5, now(), NULL)
                 ON CONFLICT (department_id, user_id) DO UPDATE SET
                    title = EXCLUDED.title, is_primary = EXCLUDED.is_primary,
                    joined_at = now(), left_at = NULL",
            )
            .bind(department.id)
            .bind(input.user_id)
            .bind(tenant_id)
            .bind(input.title.as_deref())
            .bind(input.is_primary)
            .execute(&mut *tx)
            .await?;
        }
        record_history(
            &mut tx,
            tenant_id,
            input.user_id,
            Some(organization.id),
            department.as_ref().map(|item| item.id),
            "transfer",
            actor_id,
            json!({
                "title": input.title,
                "is_primary": input.is_primary,
                "reason": input.reason,
            }),
        )
        .await?;
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.organization.transferred")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user", input.user_id.to_string())
                .detail(json!({
                    "organization_id": organization.id,
                    "department_id": department.as_ref().map(|item| item.id),
                    "reason": input.reason,
                }));
            entry.request_context(meta);
            entry
        })
        .await?;
        emit_membership_event(&mut tx, tenant_id, input.user_id, meta.trace_id.clone()).await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn list_user_memberships(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Vec<MembershipView>> {
        let rows: Vec<(
            Uuid,
            Option<String>,
            Option<Uuid>,
            Option<String>,
            Option<String>,
            Option<String>,
            bool,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT om.organization_id, o.name, NULL::uuid, NULL::text, NULL::text, om.title,
                    om.is_primary, om.joined_at
               FROM organization_members om
               JOIN organizations o ON o.id = om.organization_id
              WHERE om.user_id = $1 AND om.tenant_id = $2 AND om.left_at IS NULL
             UNION ALL
             SELECT d.organization_id, o.name, dm.department_id, d.name, d.path, dm.title,
                    dm.is_primary, dm.joined_at
               FROM department_members dm
               JOIN departments d ON d.id = dm.department_id
               JOIN organizations o ON o.id = d.organization_id
              WHERE dm.user_id = $1 AND dm.tenant_id = $2 AND dm.left_at IS NULL
              ORDER BY 8 DESC",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| MembershipView {
                organization_id: row.0,
                organization_name: row.1,
                department_id: row.2,
                department_name: row.3,
                department_path: row.4,
                title: row.5,
                is_primary: row.6,
                joined_at: row.7,
            })
            .collect())
    }

    pub async fn list_user_org_history(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Vec<HistoryView>> {
        let rows: Vec<(
            Uuid,
            String,
            Option<Uuid>,
            Option<Uuid>,
            Value,
            Option<Uuid>,
            DateTime<Utc>,
        )> = sqlx::query_as(
            "SELECT id, action, organization_id, department_id, detail, operator_id, created_at
               FROM user_organization_history
              WHERE user_id = $1 AND tenant_id = $2
              ORDER BY created_at DESC LIMIT 200",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|row| HistoryView {
                id: row.0,
                action: row.1,
                organization_id: row.2,
                department_id: row.3,
                detail: row.4,
                operator_id: row.5,
                created_at: row.6,
            })
            .collect())
    }
}

fn build_org_tree(rows: Vec<Organization>) -> Vec<OrganizationNode> {
    let mut children: HashMap<Option<Uuid>, Vec<Organization>> = HashMap::new();
    for organization in rows {
        children
            .entry(organization.parent_id)
            .or_default()
            .push(organization);
    }
    fn build(
        parent: Option<Uuid>,
        children: &mut HashMap<Option<Uuid>, Vec<Organization>>,
    ) -> Vec<OrganizationNode> {
        let mut nodes = Vec::new();
        if let Some(items) = children.remove(&parent) {
            for organization in items {
                let nested = build(Some(organization.id), children);
                nodes.push(OrganizationNode {
                    organization,
                    children: nested,
                });
            }
        }
        nodes.sort_by_key(|node| (node.organization.sort_order, node.organization.name.clone()));
        nodes
    }
    build(None, &mut children)
}

fn build_department_tree(rows: Vec<Department>) -> Vec<DepartmentNode> {
    let mut children: HashMap<Option<Uuid>, Vec<Department>> = HashMap::new();
    for department in rows {
        children
            .entry(department.parent_id)
            .or_default()
            .push(department);
    }
    fn build(
        parent: Option<Uuid>,
        children: &mut HashMap<Option<Uuid>, Vec<Department>>,
    ) -> Vec<DepartmentNode> {
        let mut nodes = Vec::new();
        if let Some(items) = children.remove(&parent) {
            for department in items {
                let nested = build(Some(department.id), children);
                nodes.push(DepartmentNode {
                    department,
                    children: nested,
                });
            }
        }
        nodes.sort_by_key(|node| (node.department.sort_order, node.department.name.clone()));
        nodes
    }
    build(None, &mut children)
}

async fn record_history(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    user_id: Uuid,
    organization_id: Option<Uuid>,
    department_id: Option<Uuid>,
    action: &str,
    operator_id: Option<Uuid>,
    detail: Value,
) -> AppResult<()> {
    sqlx::query(
        "INSERT INTO user_organization_history
            (tenant_id, user_id, organization_id, department_id, action, operator_id, detail)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(organization_id)
    .bind(department_id)
    .bind(action)
    .bind(operator_id)
    .bind(detail)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

/// 组织/部门关系变化后，向认证中心投递当前全部成员关系投影。
async fn emit_membership_event(
    tx: &mut Transaction<'_, Postgres>,
    tenant_id: Uuid,
    user_id: Uuid,
    trace_id: Option<String>,
) -> AppResult<()> {
    let rows: Vec<(Option<Uuid>, Option<Uuid>, Option<String>, bool)> = sqlx::query_as(
        "SELECT om.organization_id, NULL::uuid, NULL::text, om.is_primary
           FROM organization_members om
          WHERE om.user_id = $1 AND om.tenant_id = $2 AND om.left_at IS NULL
         UNION ALL
         SELECT d.organization_id, dm.department_id, d.path, dm.is_primary
           FROM department_members dm
           JOIN departments d ON d.id = dm.department_id
          WHERE dm.user_id = $1 AND dm.tenant_id = $2 AND dm.left_at IS NULL",
    )
    .bind(user_id)
    .bind(tenant_id)
    .fetch_all(&mut **tx)
    .await?;
    let memberships = rows
        .into_iter()
        .map(
            |(organization_id, department_id, department_path, is_primary)| {
                json!({
                    "organization_id": organization_id,
                    "department_id": department_id,
                    "department_path": department_path,
                    "is_primary": is_primary,
                })
            },
        )
        .collect::<Vec<_>>();
    outbox::enqueue(
        tx,
        &OutboxEvent::new(
            EVENT_ORG_CHANGED,
            "user",
            user_id.to_string(),
            json!({
                "identity_id": user_id,
                "tenant_id": tenant_id,
                "memberships": memberships,
            }),
        )
        .with_trace(trace_id),
    )
    .await?;
    Ok(())
}
