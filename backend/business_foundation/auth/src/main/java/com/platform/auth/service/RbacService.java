package com.platform.auth.service;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.Db;
import com.platform.auth.common.Ids;
import com.platform.auth.common.Json;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class RbacService {
    private final Db db;
    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public RbacService(Db db) {
        this.db = db;
    }

    public Set<String> roleCodes(String identityId, String tenantId) {
        return new LinkedHashSet<>(db.list("""
                SELECT DISTINCT r.code FROM user_roles ur
                JOIN roles r ON r.id = ur.role_id
                WHERE ur.identity_id = :id AND ur.tenant_id = :tenant AND ur.revoked_at IS NULL
                  AND (ur.valid_from IS NULL OR ur.valid_from <= now())
                  AND (ur.valid_until IS NULL OR ur.valid_until > now())
                  AND r.status = 'active' AND r.deleted_at IS NULL
                """, Db.params("id", identityId, "tenant", tenantId)).stream()
                .map(r -> String.valueOf(r.get("code"))).toList());
    }

    public Set<String> permissions(String identityId, String tenantId) {
        String key = identityId + ":" + tenantId;
        CacheEntry cached = cache.get(key);
        if (cached != null && cached.expiresAt.isAfter(Instant.now())) {
            return cached.permissions;
        }
        Set<String> roles = roleCodes(identityId, tenantId);
        Set<String> perms = new LinkedHashSet<>();
        if (roles.contains("super_admin")) {
            db.list("SELECT code FROM permissions WHERE status = 'active' AND deleted_at IS NULL")
                    .forEach(r -> perms.add(String.valueOf(r.get("code"))));
        } else {
            db.list("""
                    SELECT DISTINCT p.code FROM (
                        SELECT rp.permission_id FROM user_roles ur
                        JOIN role_permissions rp ON rp.role_id = ur.role_id
                        WHERE ur.identity_id = :id AND ur.tenant_id = :tenant AND ur.revoked_at IS NULL
                          AND (ur.valid_from IS NULL OR ur.valid_from <= now())
                          AND (ur.valid_until IS NULL OR ur.valid_until > now())
                          AND (rp.expires_at IS NULL OR rp.expires_at > now())
                        UNION
                        SELECT up.permission_id FROM user_permissions up
                        WHERE up.identity_id = :id AND up.tenant_id = :tenant AND up.effect = 'allow'
                          AND up.revoked_at IS NULL
                          AND (up.valid_until IS NULL OR up.valid_until > now())
                    ) x JOIN permissions p ON p.id = x.permission_id
                    WHERE p.status = 'active' AND p.deleted_at IS NULL
                    """, Db.params("id", identityId, "tenant", tenantId))
                    .forEach(r -> perms.add(String.valueOf(r.get("code"))));
            db.list("""
                    SELECT DISTINCT p.code FROM user_permissions up
                    JOIN permissions p ON p.id = up.permission_id
                    WHERE up.identity_id = :id AND up.tenant_id = :tenant AND up.effect = 'deny'
                      AND up.revoked_at IS NULL AND (up.valid_until IS NULL OR up.valid_until > now())
                    """, Db.params("id", identityId, "tenant", tenantId))
                    .forEach(r -> perms.remove(String.valueOf(r.get("code"))));
        }
        cache.put(key, new CacheEntry(perms, Instant.now().plusSeconds(30)));
        return perms;
    }

    public void invalidate(String identityId) {
        if (identityId == null) {
            cache.clear();
        } else {
            cache.keySet().removeIf(k -> k.startsWith(identityId + ":"));
        }
    }

    public Map<String, Object> check(String identityId, String tenantId, String permission,
                                     String resourceType, String resourceId, Map<String, Object> context) {
        boolean allowed = permissions(identityId, tenantId).contains(permission);
        if (resourceType != null && resourceId != null) {
            allowed = allowed && relationAllows(identityId, tenantId, permission, resourceType, resourceId);
        }
        String policyEffect = evaluatePolicies(identityId, tenantId, permission, resourceType, resourceId, context);
        if ("deny".equals(policyEffect)) {
            allowed = false;
        } else if ("allow".equals(policyEffect)) {
            allowed = true;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("allowed", allowed);
        out.put("identity_id", identityId);
        out.put("permission", permission);
        out.put("resource_type", resourceType);
        out.put("resource_id", resourceId);
        return out;
    }

    private boolean relationAllows(String identityId, String tenantId, String permission,
                                   String resourceType, String resourceId) {
        List<Map<String, Object>> relations = db.list("""
                SELECT relation FROM resource_relations
                WHERE tenant_id = :tenant AND resource_type = :rtype AND resource_id = :rid
                  AND ((subject_type = 'identity' AND subject_id = :subject) OR (subject_type = 'tenant' AND subject_id = :tenant))
                  AND (expires_at IS NULL OR expires_at > now())
                """, Db.params("tenant", tenantId, "rtype", resourceType, "rid", resourceId, "subject", identityId));
        Set<String> allowedRelations = permission.contains("write") || permission.contains("manage")
                || permission.contains("delete") || permission.contains("update")
                ? Set.of("owner", "admin", "editor")
                : Set.of("owner", "admin", "editor", "viewer", "reader", "member");
        return relations.stream().anyMatch(r -> allowedRelations.contains(String.valueOf(r.get("relation"))));
    }

    private String evaluatePolicies(String identityId, String tenantId, String permission,
                                    String resourceType, String resourceId, Map<String, Object> context) {
        List<Map<String, Object>> policies = db.list("""
                SELECT * FROM authorization_policies
                WHERE enabled = TRUE AND (tenant_id IS NULL OR tenant_id = :tenant)
                ORDER BY priority ASC
                """, Db.params("tenant", tenantId));
        for (Map<String, Object> policy : policies) {
            if (!matches(policy.get("subject_type"), policy.get("subject_id"), identityId)) {
                continue;
            }
            if (!matches(policy.get("action"), null, permission) && !"*".equals(policy.get("action"))) {
                continue;
            }
            if (!matches(policy.get("resource_type"), policy.get("resource_id"),
                    resourceType == null ? null : resourceType + ":" + resourceId)) {
                continue;
            }
            Map<String, Object> condition = Json.readMap(policy.get("condition"));
            if (!conditionMatches(condition, context)) {
                continue;
            }
            return String.valueOf(policy.get("effect"));
        }
        return null;
    }

    private boolean matches(Object expected, Object expectedId, String actual) {
        if (expected == null || String.valueOf(expected).isBlank() || "*".equals(String.valueOf(expected))) {
            return true;
        }
        if (actual == null) {
            return false;
        }
        if (expectedId != null && String.valueOf(expectedId).equals(actual)) {
            return true;
        }
        return String.valueOf(expected).equals(actual);
    }

    private boolean conditionMatches(Map<String, Object> condition, Map<String, Object> context) {
        if (condition == null || condition.isEmpty()) {
            return true;
        }
        if (context == null) {
            context = Map.of();
        }
        Object ip = condition.get("ip_prefix");
        if (ip != null && !String.valueOf(context.getOrDefault("ip", "")).startsWith(String.valueOf(ip))) {
            return false;
        }
        Object mfa = condition.get("require_mfa");
        if (Boolean.TRUE.equals(mfa) && !String.valueOf(context.getOrDefault("amr", "")).contains("otp")
                && !String.valueOf(context.getOrDefault("amr", "")).contains("webauthn")) {
            return false;
        }
        Object attr = condition.get("attribute");
        if (attr instanceof Map<?, ?> map) {
            String name = String.valueOf(map.get("name"));
            Object expected = map.get("value");
            if (!String.valueOf(context.getOrDefault(name, "")).equals(String.valueOf(expected))) {
                return false;
            }
        }
        return true;
    }

    public Map<String, Object> me(String identityId, String tenantId, String sessionId) {
        Set<String> roles = roleCodes(identityId, tenantId);
        Set<String> perms = permissions(identityId, tenantId);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("identity_id", identityId);
        out.put("tenant_id", tenantId);
        out.put("session_id", sessionId);
        out.put("roles", roles);
        out.put("permissions", perms);
        out.put("menus", menus(tenantId, perms));
        out.put("buttons", buttons(tenantId, perms));
        out.put("apis", apis(tenantId, perms));
        out.put("data_scope", dataScope(identityId, tenantId));
        out.put("organizations", db.list("""
                SELECT * FROM identity_org_memberships WHERE identity_id = :id AND tenant_id = :tenant
                """, Db.params("id", identityId, "tenant", tenantId)));
        return out;
    }

    public List<Map<String, Object>> menus(String tenantId, Set<String> permissions) {
        List<Map<String, Object>> rows = db.list("""
                SELECT m.*, p.code AS permission_code FROM menu_resources m
                LEFT JOIN permissions p ON p.id = m.permission_id
                WHERE m.deleted_at IS NULL AND m.status = 'active' AND (m.tenant_id IS NULL OR m.tenant_id = :tenant)
                ORDER BY m.sort_order, m.created_at
                """, Db.params("tenant", tenantId));
        List<Map<String, Object>> filtered = rows.stream()
                .filter(r -> r.get("permission_code") == null || permissions.contains(String.valueOf(r.get("permission_code"))))
                .toList();
        return tree(filtered, "id", "parent_id");
    }

    public List<Map<String, Object>> buttons(String tenantId, Set<String> permissions) {
        return db.list("""
                SELECT b.*, p.code AS permission_code FROM button_resources b
                LEFT JOIN permissions p ON p.id = b.permission_id
                WHERE b.deleted_at IS NULL AND b.status = 'active' AND (b.tenant_id IS NULL OR b.tenant_id = :tenant)
                ORDER BY b.created_at
                """, Db.params("tenant", tenantId)).stream()
                .filter(r -> r.get("permission_code") == null || permissions.contains(String.valueOf(r.get("permission_code"))))
                .toList();
    }

    public List<Map<String, Object>> apis(String tenantId, Set<String> permissions) {
        return db.list("""
                SELECT a.*, p.code AS permission_code FROM api_resources a
                LEFT JOIN permissions p ON p.id = a.permission_id
                WHERE a.deleted_at IS NULL AND a.status = 'active' AND (a.tenant_id IS NULL OR a.tenant_id = :tenant)
                ORDER BY a.created_at
                """, Db.params("tenant", tenantId)).stream()
                .filter(r -> r.get("permission_code") == null || permissions.contains(String.valueOf(r.get("permission_code"))))
                .toList();
    }

    public List<Map<String, Object>> dataScope(String identityId, String tenantId) {
        List<Map<String, Object>> rows = db.list("""
                SELECT dp.* FROM data_permissions dp
                WHERE dp.tenant_id = :tenant AND (
                    dp.role_id IN (SELECT ur.role_id FROM user_roles ur
                                   WHERE ur.identity_id = :id AND ur.revoked_at IS NULL)
                    OR dp.permission_id IN (SELECT up.permission_id FROM user_permissions up
                                            WHERE up.identity_id = :id AND up.revoked_at IS NULL AND up.effect = 'allow')
                )
                ORDER BY dp.created_at
                """, Db.params("id", identityId, "tenant", tenantId));
        if (rows.isEmpty()) {
            return List.of(Map.of("scope_type", "self", "scope_config", Map.of()));
        }
        return rows;
    }

    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> tree(List<Map<String, Object>> rows, String idKey, String parentKey) {
        Map<String, Map<String, Object>> index = new HashMap<>();
        List<Map<String, Object>> roots = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            Map<String, Object> copy = new LinkedHashMap<>(row);
            copy.put("children", new ArrayList<Map<String, Object>>());
            index.put(String.valueOf(copy.get(idKey)), copy);
        }
        for (Map<String, Object> row : rows) {
            Object parent = row.get(parentKey);
            Map<String, Object> node = index.get(String.valueOf(row.get(idKey)));
            if (parent != null && index.containsKey(String.valueOf(parent))) {
                ((List<Map<String, Object>>) index.get(String.valueOf(parent)).get("children")).add(node);
            } else {
                roots.add(node);
            }
        }
        return roots;
    }

    public Map<String, Object> permissionTree(String tenantId) {
        List<Map<String, Object>> rows = db.list("""
                SELECT * FROM permissions WHERE deleted_at IS NULL AND (tenant_id IS NULL OR tenant_id = :tenant)
                ORDER BY category, code
                """, Db.params("tenant", tenantId));
        return Map.of("items", tree(rows, "id", "parent_id"));
    }

    public void grantRole(String identityId, String tenantId, String roleId, String grantedBy) {
        db.update("""
                INSERT INTO user_roles (id, identity_id, role_id, tenant_id, scope, granted_by)
                SELECT :id, :identity, r.id, :tenant, r.scope, :by FROM roles r WHERE r.id = :role
                ON CONFLICT DO NOTHING
                """, Db.params("id", Ids.uuid(), "identity", identityId, "tenant", tenantId,
                "by", grantedBy, "role", roleId));
        invalidate(identityId);
    }

    public void revokeRole(String identityId, String roleId) {
        db.update("UPDATE user_roles SET revoked_at = now(), revoked_by = NULL WHERE identity_id = :id AND role_id = :role AND revoked_at IS NULL",
                Db.params("id", identityId, "role", roleId));
        invalidate(identityId);
    }

    public void grantPermission(String identityId, String tenantId, String permissionId, String grantedBy, String effect) {
        db.update("""
                INSERT INTO user_permissions (id, identity_id, permission_id, tenant_id, effect, granted_by)
                VALUES (:id, :identity, :permission, :tenant, :effect, :by)
                ON CONFLICT (identity_id, permission_id, tenant_id) WHERE revoked_at IS NULL
                DO UPDATE SET effect = EXCLUDED.effect
                """, Db.params("id", Ids.uuid(), "identity", identityId, "permission", permissionId,
                "tenant", tenantId, "effect", effect == null ? "allow" : effect, "by", grantedBy));
        invalidate(identityId);
    }

    public void revokePermission(String identityId, String permissionId) {
        db.update("UPDATE user_permissions SET revoked_at = now() WHERE identity_id = :id AND permission_id = :p AND revoked_at IS NULL",
                Db.params("id", identityId, "p", permissionId));
        invalidate(identityId);
    }

    public void setRolePermissions(String roleId, List<String> permissionIds, String grantedBy) {
        db.inTx(() -> {
            db.update("DELETE FROM role_permissions WHERE role_id = :role", Db.params("role", roleId));
            for (String permissionId : permissionIds) {
                db.update("""
                        INSERT INTO role_permissions (role_id, permission_id, granted_by) VALUES (:role, :p, :by)
                        ON CONFLICT DO NOTHING
                        """, Db.params("role", roleId, "p", permissionId, "by", grantedBy));
            }
        });
        cache.clear();
    }

    public void assertAdmin(String permission, String identityId, String tenantId) {
        if (identityId == null) {
            throw ApiException.unauthorized("缺少身份");
        }
        if (!permissions(identityId, tenantId).contains(permission)) {
            throw ApiException.forbidden("缺少权限: " + permission);
        }
    }

    private record CacheEntry(Set<String> permissions, Instant expiresAt) {}
}
