//! 授权引擎：RBAC + ABAC 策略 + ReBAC 资源关系 + 数据权限。
//!
//! 默认拒绝；拒绝策略优先；超级管理员通过内置角色获得 `admin:access` 等权限，
//! 而不是通过硬编码身份判断。

use std::collections::{HashMap, HashSet};

use redis::aio::ConnectionManager;
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

use crate::domain::{
    AuthzDecision, AuthzRequest, DataPermission, DataScope, DataScopeKind, EffectiveGrants,
    ResourceRef, RoleRef,
};
use crate::shared::{AppError, AppResult};

pub struct AuthzEngine {
    pool: PgPool,
    redis: Option<ConnectionManager>,
    prefix: String,
    cache_ttl_secs: u64,
}

impl Clone for AuthzEngine {
    fn clone(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            redis: self.redis.clone(),
            prefix: self.prefix.clone(),
            cache_ttl_secs: self.cache_ttl_secs,
        }
    }
}

impl AuthzEngine {
    pub fn new(
        pool: PgPool,
        redis: Option<ConnectionManager>,
        prefix: impl Into<String>,
        cache_ttl_secs: u64,
    ) -> Self {
        Self {
            pool,
            redis,
            prefix: prefix.into(),
            cache_ttl_secs,
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    async fn cache_version(&self, tenant_id: Uuid) -> String {
        let Some(redis) = &self.redis else {
            return "0".to_string();
        };
        let key = format!("{}:authz:ver:{tenant_id}", self.prefix);
        crate::infrastructure::redis::get(redis, &key)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| "0".to_string())
    }

    /// 使某租户的授权缓存失效。任何角色、权限、数据权限变更后必须调用。
    pub async fn invalidate_tenant(&self, tenant_id: Uuid) -> AppResult<()> {
        if let Some(redis) = &self.redis {
            let key = format!("{}:authz:ver:{tenant_id}", self.prefix);
            crate::infrastructure::redis::increment(redis, &key, 0).await?;
        }
        Ok(())
    }

    pub async fn effective_grants(
        &self,
        identity_id: Uuid,
        tenant_id: Uuid,
    ) -> AppResult<EffectiveGrants> {
        let version = self.cache_version(tenant_id).await;
        let cache_key = format!(
            "{}:authz:grants:{tenant_id}:{identity_id}:{version}",
            self.prefix
        );
        if let Some(redis) = &self.redis {
            if let Some(cached) =
                crate::infrastructure::redis::get_json::<EffectiveGrants>(redis, &cache_key).await?
            {
                return Ok(cached);
            }
        }

        let rows =
            sqlx::query_as::<_, (Uuid, String, String, String, Option<Uuid>, Option<String>)>(
                "SELECT r.id, r.code, r.name, r.scope, r.tenant_id, p.code
             FROM user_roles ur
             JOIN roles r ON r.id = ur.role_id AND r.status = 'active' AND r.deleted_at IS NULL
             LEFT JOIN role_permissions rp
                    ON rp.role_id = r.id AND (rp.expires_at IS NULL OR rp.expires_at > now())
             LEFT JOIN permissions p
                    ON p.id = rp.permission_id AND p.status = 'active' AND p.deleted_at IS NULL
                    AND (p.tenant_id IS NULL OR p.tenant_id = $2)
             WHERE ur.identity_id = $1
               AND ur.tenant_id = $2
               AND ur.revoked_at IS NULL
               AND ur.valid_from <= now()
               AND (ur.valid_until IS NULL OR ur.valid_until > now())
               AND (r.tenant_id IS NULL OR r.tenant_id = $2)",
            )
            .bind(identity_id)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;

        let mut roles: Vec<RoleRef> = Vec::new();
        let mut seen_roles: HashSet<Uuid> = HashSet::new();
        let mut permissions: HashSet<String> = HashSet::new();
        for (role_id, code, name, scope, role_tenant, permission_code) in rows {
            if seen_roles.insert(role_id) {
                roles.push(RoleRef {
                    id: role_id,
                    code,
                    name,
                    scope,
                    tenant_id: role_tenant,
                });
            }
            if let Some(permission) = permission_code {
                permissions.insert(permission);
            }
        }

        let direct = sqlx::query_as::<_, (String, String)>(
            "SELECT p.code, up.effect
             FROM user_permissions up
             JOIN permissions p ON p.id = up.permission_id AND p.status = 'active' AND p.deleted_at IS NULL
             WHERE up.identity_id = $1 AND up.tenant_id = $2
               AND up.revoked_at IS NULL
               AND up.valid_from <= now()
               AND (up.valid_until IS NULL OR up.valid_until > now())
               AND (p.tenant_id IS NULL OR p.tenant_id = $2)",
        )
        .bind(identity_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let mut denied_permissions = HashSet::new();
        for (code, effect) in direct {
            if effect == "deny" {
                denied_permissions.insert(code);
            } else {
                permissions.insert(code);
            }
        }

        let data_permissions = sqlx::query_as::<_, DataPermission>(
            "SELECT DISTINCT dp.id, dp.tenant_id, dp.role_id, dp.permission_id, dp.scope_type,
                    dp.scope_config, dp.description, dp.created_at, dp.updated_at
             FROM data_permissions dp
             JOIN user_roles ur ON ur.role_id = dp.role_id
             WHERE ur.identity_id = $1 AND ur.tenant_id = $2
               AND ur.revoked_at IS NULL
               AND ur.valid_from <= now()
               AND (ur.valid_until IS NULL OR ur.valid_until > now())
               AND dp.tenant_id = $2",
        )
        .bind(identity_id)
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;

        let grants = EffectiveGrants {
            roles,
            permissions,
            denied_permissions,
            data_permissions,
            computed_at: crate::shared::unix_secs(),
        };

        if let Some(redis) = &self.redis {
            let ttl = self.cache_ttl_secs.max(5);
            crate::infrastructure::redis::set_json(redis, &cache_key, &grants, ttl).await?;
        }
        Ok(grants)
    }

    pub async fn check(&self, request: &AuthzRequest) -> AppResult<AuthzDecision> {
        let grants = self
            .effective_grants(request.subject_id, request.tenant_id)
            .await?;

        if grants.denied_permissions.contains(&request.permission) {
            return Ok(AuthzDecision {
                allowed: false,
                reason: "用户被直接拒绝授予该权限".to_string(),
                matched_roles: grants.roles.iter().map(|role| role.code.clone()).collect(),
                denied_by_policy: None,
                data_scope: None,
            });
        }

        let attributes = self.build_attributes(request, &grants).await?;
        let policies = self.load_policies(request.tenant_id).await?;

        for policy in &policies {
            if policy.effect == "deny" && policy_matches(policy, request, &grants, &attributes) {
                return Ok(AuthzDecision {
                    allowed: false,
                    reason: format!("被拒绝策略 {} 拦截", policy.name),
                    matched_roles: grants.roles.iter().map(|role| role.code.clone()).collect(),
                    denied_by_policy: Some(policy.name.clone()),
                    data_scope: None,
                });
            }
        }

        let mut allowed_by = None;
        if grants.permissions.contains(&request.permission) {
            allowed_by = Some("RBAC");
        }

        let mut relation_roles = Vec::new();
        if allowed_by.is_none() {
            if let Some(resource) = &request.resource {
                if let Some(relation) = self
                    .match_resource_relation(
                        request.subject_id,
                        request.tenant_id,
                        resource,
                        &request.permission,
                        &grants,
                    )
                    .await?
                {
                    relation_roles.push(relation.clone());
                    allowed_by = Some("ReBAC");
                }
            }
        }

        if allowed_by.is_none()
            && policies.iter().any(|policy| {
                policy.effect == "allow" && policy_matches(policy, request, &grants, &attributes)
            })
        {
            allowed_by = Some("ABAC");
        }

        let mut matched_roles: Vec<String> =
            grants.roles.iter().map(|role| role.code.clone()).collect();
        matched_roles.extend(relation_roles);

        match allowed_by {
            Some(source) => {
                let data_scope = self
                    .resolve_data_scope(
                        request.subject_id,
                        request.tenant_id,
                        &grants,
                        &request.permission,
                    )
                    .await?;
                Ok(AuthzDecision {
                    allowed: true,
                    reason: format!("授权来源: {source}"),
                    matched_roles,
                    denied_by_policy: None,
                    data_scope,
                })
            }
            None => Ok(AuthzDecision {
                allowed: false,
                reason: "默认拒绝：用户不具备该权限".to_string(),
                matched_roles,
                denied_by_policy: None,
                data_scope: None,
            }),
        }
    }

    pub async fn require(
        &self,
        identity_id: Uuid,
        tenant_id: Uuid,
        permission: &str,
    ) -> AppResult<()> {
        let decision = self
            .check(&AuthzRequest {
                subject_id: identity_id,
                tenant_id,
                permission: permission.to_string(),
                resource: None,
                context: Value::Object(Default::default()),
            })
            .await?;
        if decision.allowed {
            Ok(())
        } else {
            Err(AppError::forbidden(format!(
                "缺少权限 {permission}: {}",
                decision.reason
            )))
        }
    }

    pub async fn require_with_resource(
        &self,
        identity_id: Uuid,
        tenant_id: Uuid,
        permission: &str,
        resource: ResourceRef,
        context: Value,
    ) -> AppResult<()> {
        let decision = self
            .check(&AuthzRequest {
                subject_id: identity_id,
                tenant_id,
                permission: permission.to_string(),
                resource: Some(resource),
                context,
            })
            .await?;
        if decision.allowed {
            Ok(())
        } else {
            Err(AppError::forbidden(format!(
                "无权访问资源: {}",
                decision.reason
            )))
        }
    }

    async fn build_attributes(
        &self,
        request: &AuthzRequest,
        grants: &EffectiveGrants,
    ) -> AppResult<Value> {
        let identity = sqlx::query_as::<_, (String, Option<String>, Option<String>)>(
            "SELECT status, display_name, email FROM identities WHERE id = $1",
        )
        .bind(request.subject_id)
        .fetch_optional(&self.pool)
        .await?;

        let department_ids: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT department_id::text FROM identity_org_memberships
             WHERE identity_id = $1 AND department_id IS NOT NULL",
        )
        .bind(request.subject_id)
        .fetch_all(&self.pool)
        .await?;

        let organization_ids: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT organization_id::text FROM identity_org_memberships
             WHERE identity_id = $1 AND organization_id IS NOT NULL",
        )
        .bind(request.subject_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(json!({
            "user": {
                "id": request.subject_id,
                "tenant_id": request.tenant_id,
                "status": identity.as_ref().map(|row| row.0.clone()),
                "display_name": identity.as_ref().and_then(|row| row.1.clone()),
                "email": identity.as_ref().and_then(|row| row.2.clone()),
                "roles": grants.roles.iter().map(|role| role.code.clone()).collect::<Vec<_>>(),
                "department_ids": department_ids,
                "organization_ids": organization_ids,
            },
            "resource": request.resource,
            "context": request.context,
        }))
    }

    async fn load_policies(
        &self,
        tenant_id: Uuid,
    ) -> AppResult<Vec<crate::domain::AuthorizationPolicy>> {
        let policies = sqlx::query_as::<_, crate::domain::AuthorizationPolicy>(
            "SELECT id, tenant_id, name, description, effect, subject_type, subject_id, action,
                    resource_type, resource_id, condition, priority, enabled, created_at, updated_at
             FROM authorization_policies
             WHERE enabled = TRUE AND (tenant_id = $1 OR tenant_id IS NULL)
             ORDER BY priority ASC, created_at ASC",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(policies)
    }

    async fn match_resource_relation(
        &self,
        identity_id: Uuid,
        tenant_id: Uuid,
        resource: &ResourceRef,
        permission: &str,
        grants: &EffectiveGrants,
    ) -> AppResult<Option<String>> {
        let role_ids: Vec<String> = grants
            .roles
            .iter()
            .map(|role| role.id.to_string())
            .collect();
        let organization_ids: Vec<String> = sqlx::query_scalar(
            "SELECT DISTINCT organization_id::text FROM identity_org_memberships
             WHERE identity_id = $1 AND organization_id IS NOT NULL",
        )
        .bind(identity_id)
        .fetch_all(&self.pool)
        .await?;

        let relations: Vec<String> = sqlx::query_scalar(
            "SELECT relation FROM resource_relations
             WHERE tenant_id = $1 AND resource_type = $2 AND resource_id = $3
               AND (expires_at IS NULL OR expires_at > now())
               AND (
                    (subject_type = 'identity' AND subject_id = $4)
                 OR (subject_type = 'role' AND subject_id = ANY($5))
                 OR (subject_type = 'organization' AND subject_id = ANY($6))
               )",
        )
        .bind(tenant_id)
        .bind(&resource.resource_type)
        .bind(&resource.resource_id)
        .bind(identity_id.to_string())
        .bind(&role_ids)
        .bind(&organization_ids)
        .fetch_all(&self.pool)
        .await?;

        if relations.is_empty() {
            return Ok(None);
        }

        let allowed_relations = required_relations(permission);
        let matched = relations
            .into_iter()
            .find(|relation| allowed_relations.iter().any(|allowed| allowed == relation));
        Ok(matched)
    }

    async fn resolve_data_scope(
        &self,
        identity_id: Uuid,
        tenant_id: Uuid,
        grants: &EffectiveGrants,
        permission: &str,
    ) -> AppResult<Option<DataScope>> {
        if grants.data_permissions.is_empty() {
            return Ok(None);
        }
        let specific_ids: Vec<Uuid> = grants
            .data_permissions
            .iter()
            .filter_map(|item| item.permission_id)
            .collect();
        let mut permission_codes: HashMap<Uuid, String> = HashMap::new();
        if !specific_ids.is_empty() {
            let rows = sqlx::query_as::<_, (Uuid, String)>(
                "SELECT id, code FROM permissions WHERE id = ANY($1)",
            )
            .bind(&specific_ids)
            .fetch_all(&self.pool)
            .await?;
            permission_codes = rows.into_iter().collect();
        }

        let department_ids = department_ids_for(self, identity_id).await?;
        let mut best: Option<DataScope> = None;
        for item in grants.data_permissions.iter().filter(|item| {
            item.permission_id
                .map(|id| permission_codes.get(&id).map(String::as_str) == Some(permission))
                .unwrap_or(true)
        }) {
            let Some(kind) = DataScopeKind::parse(&item.scope_type) else {
                continue;
            };
            let user_ids = item
                .scope_config
                .get("user_ids")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let scope = DataScope {
                kind: kind.clone(),
                tenant_id,
                department_ids: if matches!(
                    kind,
                    DataScopeKind::Department | DataScopeKind::DepartmentAndChildren
                ) {
                    department_ids.clone()
                } else {
                    item.scope_config
                        .get("department_ids")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter_map(|item| item.as_str().map(str::to_string))
                                .collect()
                        })
                        .unwrap_or_default()
                },
                user_ids: if matches!(kind, DataScopeKind::SelfOnly) {
                    vec![identity_id.to_string()]
                } else {
                    user_ids
                },
                custom: if matches!(kind, DataScopeKind::Custom) {
                    Some(item.scope_config.clone())
                } else {
                    None
                },
            };
            best = Some(more_permissive(best, scope));
        }
        Ok(best)
    }
}

async fn department_ids_for(engine: &AuthzEngine, identity_id: Uuid) -> AppResult<Vec<String>> {
    let ids = sqlx::query_scalar(
        "SELECT DISTINCT department_id::text FROM identity_org_memberships
         WHERE identity_id = $1 AND department_id IS NOT NULL",
    )
    .bind(identity_id)
    .fetch_all(&engine.pool)
    .await?;
    Ok(ids)
}

fn scope_rank(kind: &DataScopeKind) -> u8 {
    match kind {
        DataScopeKind::All => 100,
        DataScopeKind::DepartmentAndChildren => 90,
        DataScopeKind::Department => 80,
        DataScopeKind::Departments => 70,
        DataScopeKind::Users => 60,
        DataScopeKind::Custom => 50,
        DataScopeKind::SelfOnly => 10,
    }
}

fn more_permissive(current: Option<DataScope>, candidate: DataScope) -> DataScope {
    match current {
        Some(current) if scope_rank(&current.kind) >= scope_rank(&candidate.kind) => current,
        _ => candidate,
    }
}

/// 权限后缀映射到资源关系最低要求。
pub fn required_relations(permission: &str) -> Vec<&'static str> {
    let action = permission.rsplit(':').next().unwrap_or(permission);
    match action {
        "read" | "list" | "view" | "get" => {
            vec!["owner", "admin", "editor", "viewer", "reader", "member"]
        }
        "write" | "create" | "update" | "edit" | "manage" => vec!["owner", "admin", "editor"],
        "delete" | "remove" => vec!["owner", "admin"],
        _ => vec!["owner", "admin", "editor"],
    }
}

pub fn policy_matches(
    policy: &crate::domain::AuthorizationPolicy,
    request: &AuthzRequest,
    grants: &EffectiveGrants,
    attributes: &Value,
) -> bool {
    if let Some(subject_type) = &policy.subject_type {
        match subject_type.as_str() {
            "identity" => {
                let matches = policy
                    .subject_id
                    .as_deref()
                    .map(|id| id == "*" || id == request.subject_id.to_string())
                    .unwrap_or(true);
                if !matches {
                    return false;
                }
            }
            "role" => {
                let matches = policy
                    .subject_id
                    .as_deref()
                    .map(|id| {
                        id == "*"
                            || grants
                                .roles
                                .iter()
                                .any(|role| role.code == id || role.id.to_string() == id)
                    })
                    .unwrap_or(true);
                if !matches {
                    return false;
                }
            }
            _ => {}
        }
    }
    if let Some(action) = &policy.action {
        if action != "*" && action != &request.permission {
            return false;
        }
    }
    if let Some(resource_type) = &policy.resource_type {
        let matches = request
            .resource
            .as_ref()
            .map(|resource| resource_type == "*" || &resource.resource_type == resource_type)
            .unwrap_or(resource_type == "*");
        if !matches {
            return false;
        }
    }
    if let Some(resource_id) = &policy.resource_id {
        let matches = request
            .resource
            .as_ref()
            .map(|resource| resource_id == "*" || &resource.resource_id == resource_id)
            .unwrap_or(resource_id == "*");
        if !matches {
            return false;
        }
    }
    evaluate_condition(&policy.condition, attributes)
}

/// ABAC 条件求值器。支持 all/any/not 组合与常见比较操作符。
pub fn evaluate_condition(condition: &Value, attributes: &Value) -> bool {
    match condition {
        Value::Null => true,
        Value::Bool(value) => *value,
        Value::Object(map) => {
            if let Some(items) = map.get("all").and_then(Value::as_array) {
                return items
                    .iter()
                    .all(|item| evaluate_condition(item, attributes));
            }
            if let Some(items) = map.get("any").and_then(Value::as_array) {
                return items
                    .iter()
                    .any(|item| evaluate_condition(item, attributes));
            }
            if let Some(item) = map.get("not") {
                return !evaluate_condition(item, attributes);
            }
            let attr = map.get("attr").and_then(Value::as_str);
            let op = map.get("op").and_then(Value::as_str).unwrap_or("eq");
            let expected = map.get("value").cloned().unwrap_or(Value::Null);
            let Some(attr) = attr else {
                return true;
            };
            let actual = resolve_attr(attributes, attr);
            compare(actual, op, &expected)
        }
        _ => true,
    }
}

fn resolve_attr<'a>(attributes: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = attributes;
    for part in path.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn compare(actual: Option<&Value>, op: &str, expected: &Value) -> bool {
    match op {
        "exists" => actual.is_some(),
        "eq" => actual == Some(expected),
        "ne" => actual != Some(expected),
        "in" => match expected.as_array() {
            Some(items) => actual.map(|value| items.contains(value)).unwrap_or(false),
            None => false,
        },
        "not_in" => match expected.as_array() {
            Some(items) => actual.map(|value| !items.contains(value)).unwrap_or(true),
            None => true,
        },
        "contains" => match actual {
            Some(Value::String(value)) => value.contains(expected.as_str().unwrap_or_default()),
            Some(Value::Array(items)) => items.contains(expected),
            _ => false,
        },
        "starts_with" => actual
            .and_then(Value::as_str)
            .map(|value| value.starts_with(expected.as_str().unwrap_or_default()))
            .unwrap_or(false),
        "gt" | "gte" | "lt" | "lte" => match (actual.and_then(Value::as_f64), expected.as_f64()) {
            (Some(a), Some(b)) => match op {
                "gt" => a > b,
                "gte" => a >= b,
                "lt" => a < b,
                _ => a <= b,
            },
            _ => false,
        },
        _ => false,
    }
}

/// API 路径匹配：仅做整段匹配，支持 `{id}` / `:id` / `*` 单段通配，禁止前缀放行。
pub fn match_api_path(pattern: &str, path: &str) -> bool {
    let pattern_segments: Vec<&str> = pattern.trim_matches('/').split('/').collect();
    let path_segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    if pattern_segments.len() != path_segments.len() {
        return false;
    }
    pattern_segments
        .iter()
        .zip(path_segments.iter())
        .all(|(pattern, actual)| {
            let segment = pattern.trim();
            segment == "*"
                || (segment.starts_with('{') && segment.ends_with('}'))
                || (segment.starts_with(':') && segment.len() > 1)
                || segment == *actual
        })
}

/// 汇总一批权限检查结果，便于前端一次性渲染。
pub async fn check_many(
    engine: &AuthzEngine,
    identity_id: Uuid,
    tenant_id: Uuid,
    permissions: &[String],
) -> AppResult<HashMap<String, bool>> {
    let grants = engine.effective_grants(identity_id, tenant_id).await?;
    Ok(permissions
        .iter()
        .map(|permission| (permission.clone(), grants.permissions.contains(permission)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_path_matching_requires_exact_segments() {
        assert!(match_api_path("/api/v1/users/{id}", "/api/v1/users/123"));
        assert!(match_api_path("/api/v1/users/:id", "/api/v1/users/123"));
        assert!(!match_api_path("/api/v1/users", "/api/v1/users/123"));
        assert!(!match_api_path(
            "/api/v1/users/{id}",
            "/api/v1/users/123/profile"
        ));
        assert!(!match_api_path("/api/v1/users*", "/api/v1/users/123"));
    }

    #[test]
    fn condition_evaluator_supports_composition() {
        let attrs = json!({
            "user": {"department_ids": ["d1", "d2"], "status": "active"},
            "context": {"ip": "10.0.0.1"}
        });
        assert!(evaluate_condition(
            &json!({"all": [
                {"attr": "user.status", "op": "eq", "value": "active"},
                {"attr": "user.department_ids", "op": "contains", "value": "d1"}
            ]}),
            &attrs
        ));
        assert!(!evaluate_condition(
            &json!({"not": {"attr": "user.status", "op": "eq", "value": "active"}}),
            &attrs
        ));
        assert!(evaluate_condition(&json!({}), &attrs));
    }

    #[test]
    fn required_relations_follow_action() {
        assert!(required_relations("document:read").contains(&"viewer"));
        assert!(!required_relations("document:delete").contains(&"viewer"));
    }
}
