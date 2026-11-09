//! 用户分组：树形结构、成员管理与批量操作。

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::application::audit::{self, AuditEntry};
use crate::application::users::{UserListQuery, EVENT_GROUP_CHANGED};
use crate::bootstrap::AppState;
use crate::domain::{User, UserGroup};
use crate::infrastructure::outbox::{self, OutboxEvent};
use crate::shared::{AppError, AppResult, Page, PageQuery, RequestMeta};

#[derive(Debug, Clone, Deserialize)]
pub struct GroupInput {
    #[serde(default)]
    pub parent_id: Option<Uuid>,
    pub code: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default = "default_status")]
    pub status: String,
    #[serde(default)]
    pub tags: Vec<Value>,
    #[serde(default)]
    pub extra: Value,
    #[serde(default)]
    pub sort_order: i32,
}

fn default_status() -> String {
    "active".to_string()
}

#[derive(Debug, Clone, Serialize)]
pub struct GroupNode {
    #[serde(flatten)]
    pub group: UserGroup,
    pub children: Vec<GroupNode>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MembersInput {
    pub user_ids: Vec<Uuid>,
}

const GROUP_COLUMNS: &str = "id, tenant_id, parent_id, code, name, description, path, level,
     status, tags, extra, sort_order, created_at, updated_at, deleted_at";

fn validate(input: &GroupInput) -> AppResult<()> {
    let code = input.code.trim();
    if code.len() < 2 || code.len() > 64 {
        return Err(AppError::validation("code", "分组编码长度需在 2-64 之间"));
    }
    if input.name.trim().is_empty() {
        return Err(AppError::validation("name", "分组名称不能为空"));
    }
    if !matches!(input.status.as_str(), "active" | "disabled") {
        return Err(AppError::validation("status", "分组状态不合法"));
    }
    Ok(())
}

fn build_group_tree(groups: Vec<UserGroup>) -> Vec<GroupNode> {
    let mut children: HashMap<Option<Uuid>, Vec<UserGroup>> = HashMap::new();
    for group in groups {
        children.entry(group.parent_id).or_default().push(group);
    }
    fn build(
        parent: Option<Uuid>,
        children: &mut HashMap<Option<Uuid>, Vec<UserGroup>>,
    ) -> Vec<GroupNode> {
        let mut nodes = Vec::new();
        if let Some(items) = children.remove(&parent) {
            for mut group in items {
                let nested = build(Some(group.id), children);
                group.parent_id = parent;
                nodes.push(GroupNode {
                    group,
                    children: nested,
                });
            }
        }
        nodes.sort_by_key(|node| (node.group.sort_order, node.group.name.clone()));
        nodes
    }
    build(None, &mut children)
}

impl AppState {
    pub async fn get_group(&self, tenant_id: Uuid, id: Uuid) -> AppResult<UserGroup> {
        sqlx::query_as::<_, UserGroup>(&format!(
            "SELECT {GROUP_COLUMNS} FROM user_groups
              WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL"
        ))
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::not_found("分组不存在"))
    }

    pub async fn list_groups(
        &self,
        tenant_id: Uuid,
        page: &PageQuery,
    ) -> AppResult<Page<UserGroup>> {
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM user_groups WHERE tenant_id = $1 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query_as::<_, UserGroup>(&format!(
            "SELECT {GROUP_COLUMNS} FROM user_groups
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

    pub async fn group_tree(&self, tenant_id: Uuid) -> AppResult<Vec<GroupNode>> {
        let rows = sqlx::query_as::<_, UserGroup>(&format!(
            "SELECT {GROUP_COLUMNS} FROM user_groups
              WHERE tenant_id = $1 AND deleted_at IS NULL ORDER BY path"
        ))
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(build_group_tree(rows))
    }

    pub async fn create_group(
        &self,
        tenant_id: Uuid,
        input: &GroupInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<UserGroup> {
        validate(input)?;
        let (parent_path, level) = match input.parent_id {
            Some(parent_id) => {
                let parent = self.get_group(tenant_id, parent_id).await?;
                (parent.path, parent.level + 1)
            }
            None => (String::new(), 0),
        };
        let id = Uuid::now_v7();
        let path = if parent_path.is_empty() {
            format!("/{id}")
        } else {
            format!("{}/{id}", parent_path.trim_end_matches('/'))
        };
        let row = sqlx::query_as::<_, UserGroup>(&format!(
            "INSERT INTO user_groups
                (id, tenant_id, parent_id, code, name, description, path, level, status, tags,
                 extra, sort_order)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
             RETURNING {GROUP_COLUMNS}"
        ))
        .bind(id)
        .bind(tenant_id)
        .bind(input.parent_id)
        .bind(input.code.trim())
        .bind(input.name.trim())
        .bind(input.description.as_deref())
        .bind(&path)
        .bind(level)
        .bind(&input.status)
        .bind(json!(input.tags))
        .bind(if input.extra.is_null() {
            json!({})
        } else {
            input.extra.clone()
        })
        .bind(input.sort_order)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| {
            if let sqlx::Error::Database(db_error) = &error {
                if db_error.code().as_deref() == Some("23505") {
                    return AppError::conflict("分组编码已存在");
                }
            }
            error.into()
        })?;
        audit::record(&self.pool, {
            let mut entry = AuditEntry::new("user.group.created")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user_group", id.to_string())
                .detail(json!({ "code": row.code }));
            entry.request_context(meta);
            entry
        })
        .await?;
        Ok(row)
    }

    pub async fn update_group(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: &GroupInput,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<UserGroup> {
        validate(input)?;
        let current = self.get_group(tenant_id, id).await?;
        let (new_parent_path, new_level) = match input.parent_id {
            Some(parent_id) => {
                if parent_id == id {
                    return Err(AppError::validation(
                        "parent_id",
                        "分组不能作为自己的父节点",
                    ));
                }
                let parent = self.get_group(tenant_id, parent_id).await?;
                if parent.path == current.path
                    || parent.path.starts_with(&format!("{}/", current.path))
                {
                    return Err(AppError::validation(
                        "parent_id",
                        "不能移动到自己的子分组下",
                    ));
                }
                (parent.path, parent.level + 1)
            }
            None => (String::new(), 0),
        };
        let new_path = if new_parent_path.is_empty() {
            format!("/{id}")
        } else {
            format!("{}/{id}", new_parent_path.trim_end_matches('/'))
        };
        let old_path = current.path.clone();
        let level_delta = new_level - current.level;

        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE user_groups SET parent_id = $2, code = $3, name = $4, description = $5,
                    path = $6, level = $7, status = $8, tags = $9, extra = $10,
                    sort_order = $11, updated_at = now()
              WHERE id = $1 AND tenant_id = $12 AND deleted_at IS NULL",
        )
        .bind(id)
        .bind(input.parent_id)
        .bind(input.code.trim())
        .bind(input.name.trim())
        .bind(input.description.as_deref())
        .bind(&new_path)
        .bind(new_level)
        .bind(&input.status)
        .bind(json!(input.tags))
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
                "UPDATE user_groups
                    SET path = $1 || substring(path from $2), level = level + $3, updated_at = now()
                  WHERE tenant_id = $4 AND path LIKE $5 AND deleted_at IS NULL",
            )
            .bind(&new_path)
            .bind((old_path.len() + 1) as i32)
            .bind(level_delta)
            .bind(tenant_id)
            .bind(format!("{old_path}/%"))
            .execute(&mut *tx)
            .await?;
        }
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.group.updated")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user_group", id.to_string())
                .detail(json!({ "code": input.code.trim() }));
            entry.request_context(meta);
            entry
        })
        .await?;
        tx.commit().await?;
        self.get_group(tenant_id, id).await
    }

    pub async fn delete_group(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<()> {
        self.get_group(tenant_id, id).await?;
        let children: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM user_groups
              WHERE tenant_id = $1 AND parent_id = $2 AND deleted_at IS NULL",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_one(&self.pool)
        .await?;
        if children > 0 {
            return Err(AppError::conflict("请先删除子分组"));
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE user_groups SET deleted_at = now(), status = 'disabled', updated_at = now()
              WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM user_group_members WHERE group_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.group.deleted")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user_group", id.to_string());
            entry.request_context(meta);
            entry
        })
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn add_group_members(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        user_ids: &[Uuid],
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<usize> {
        self.get_group(tenant_id, group_id).await?;
        if user_ids.len() > self.config.batch.max_items {
            return Err(AppError::bad_request("单次成员数量超过限制"));
        }
        let mut tx = self.pool.begin().await?;
        let mut added = 0;
        for user_id in user_ids {
            let exists: Option<(Uuid,)> = sqlx::query_as(
                "SELECT id FROM users WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
            )
            .bind(user_id)
            .bind(tenant_id)
            .fetch_optional(&mut *tx)
            .await?;
            if exists.is_none() {
                continue;
            }
            let result = sqlx::query(
                "INSERT INTO user_group_members (group_id, user_id, tenant_id)
                 VALUES ($1, $2, $3) ON CONFLICT (group_id, user_id) DO NOTHING",
            )
            .bind(group_id)
            .bind(user_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
            if result.rows_affected() > 0 {
                added += 1;
            }
            outbox::enqueue(
                &mut tx,
                &OutboxEvent::new(
                    EVENT_GROUP_CHANGED,
                    "user",
                    user_id.to_string(),
                    json!({
                        "identity_id": user_id,
                        "tenant_id": tenant_id,
                        "group_id": group_id,
                        "action": "joined",
                    }),
                )
                .with_trace(meta.trace_id.clone()),
            )
            .await?;
        }
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.group.members_added")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user_group", group_id.to_string())
                .detail(json!({ "added": added }));
            entry.request_context(meta);
            entry
        })
        .await?;
        tx.commit().await?;
        Ok(added)
    }

    pub async fn remove_group_members(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        user_ids: &[Uuid],
        actor_id: Option<Uuid>,
        meta: &RequestMeta,
    ) -> AppResult<usize> {
        self.get_group(tenant_id, group_id).await?;
        let mut tx = self.pool.begin().await?;
        let mut removed = 0;
        for user_id in user_ids {
            let result =
                sqlx::query("DELETE FROM user_group_members WHERE group_id = $1 AND user_id = $2")
                    .bind(group_id)
                    .bind(user_id)
                    .execute(&mut *tx)
                    .await?;
            if result.rows_affected() > 0 {
                removed += 1;
                outbox::enqueue(
                    &mut tx,
                    &OutboxEvent::new(
                        EVENT_GROUP_CHANGED,
                        "user",
                        user_id.to_string(),
                        json!({
                            "identity_id": user_id,
                            "tenant_id": tenant_id,
                            "group_id": group_id,
                            "action": "left",
                        }),
                    )
                    .with_trace(meta.trace_id.clone()),
                )
                .await?;
            }
        }
        audit::record_in_tx(&mut tx, {
            let mut entry = AuditEntry::new("user.group.members_removed")
                .tenant(tenant_id)
                .actor(actor_id)
                .resource("user_group", group_id.to_string())
                .detail(json!({ "removed": removed }));
            entry.request_context(meta);
            entry
        })
        .await?;
        tx.commit().await?;
        Ok(removed)
    }

    pub async fn list_group_members(
        &self,
        tenant_id: Uuid,
        group_id: Uuid,
        page: &PageQuery,
    ) -> AppResult<Page<User>> {
        self.get_group(tenant_id, group_id).await?;
        let total: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM user_group_members m
               JOIN users u ON u.id = m.user_id AND u.deleted_at IS NULL
              WHERE m.group_id = $1",
        )
        .bind(group_id)
        .fetch_one(&self.pool)
        .await?;
        let rows = sqlx::query_as::<_, User>(
            "SELECT u.id, u.tenant_id, u.username, u.email, u.email_verified, u.phone,
                    u.phone_verified, u.display_name, u.avatar_url, u.status, u.source, u.remark,
                    u.last_active_at, u.last_login_at, u.registered_at, u.version, u.created_at,
                    u.updated_at, u.deleted_at
               FROM user_group_members m
               JOIN users u ON u.id = m.user_id AND u.deleted_at IS NULL
              WHERE m.group_id = $1
              ORDER BY m.joined_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(group_id)
        .bind(page.limit())
        .bind(page.offset())
        .fetch_all(&self.pool)
        .await?;
        Ok(Page::new(rows, total, page))
    }

    pub async fn list_user_groups(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AppResult<Vec<UserGroup>> {
        let rows = sqlx::query_as::<_, UserGroup>(
            "SELECT g.id, g.tenant_id, g.parent_id, g.code, g.name, g.description, g.path,
                    g.level, g.status, g.tags, g.extra, g.sort_order, g.created_at, g.updated_at,
                    g.deleted_at
               FROM user_group_members m
               JOIN user_groups g ON g.id = m.group_id AND g.deleted_at IS NULL
              WHERE m.user_id = $1 AND m.tenant_id = $2 ORDER BY g.path",
        )
        .bind(user_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// 供管理端按分组筛选用户。
    pub fn group_filter(group_id: Uuid) -> UserListQuery {
        UserListQuery {
            group_id: Some(group_id),
            ..Default::default()
        }
    }
}
