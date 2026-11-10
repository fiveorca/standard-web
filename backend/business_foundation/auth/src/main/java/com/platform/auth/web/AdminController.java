package com.platform.auth.web;

import com.platform.auth.common.Api;
import com.platform.auth.common.ApiException;
import com.platform.auth.common.AuditService;
import com.platform.auth.common.AuthContext;
import com.platform.auth.common.Db;
import com.platform.auth.common.Ids;
import com.platform.auth.common.Json;
import com.platform.auth.security.KeyService;
import com.platform.auth.service.FederationService;
import com.platform.auth.service.IdentityService;
import com.platform.auth.service.MfaService;
import com.platform.auth.service.OAuthService;
import com.platform.auth.service.RbacService;
import com.platform.auth.service.SamlService;
import com.platform.auth.service.SessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {
    private final Db db;
    private final RbacService rbac;
    private final IdentityService identities;
    private final MfaService mfa;
    private final OAuthService oauth;
    private final FederationService federation;
    private final SamlService saml;
    private final AuditService audit;
    private final KeyService keys;

    public AdminController(Db db, RbacService rbac, IdentityService identities, MfaService mfa,
                           OAuthService oauth, FederationService federation, SamlService saml,
                           AuditService audit, KeyService keys) {
        this.db = db;
        this.rbac = rbac;
        this.identities = identities;
        this.mfa = mfa;
        this.oauth = oauth;
        this.federation = federation;
        this.saml = saml;
        this.audit = audit;
        this.keys = keys;
    }

    // ---------------- 身份 ----------------

    @GetMapping("/identities")
    public Map<String, Object> identities(AuthContext ctx,
                                          @RequestParam(defaultValue = "1") int page,
                                          @RequestParam(defaultValue = "20") int page_size,
                                          @RequestParam(required = false) String status,
                                          @RequestParam(required = false) String keyword) {
        require(ctx, "identity:read");
        return Api.ok(identities.adminList(page(page), pageSize(page_size), status, keyword));
    }

    @PostMapping("/identities")
    public ResponseEntity<Map<String, Object>> createIdentity(@RequestBody Map<String, Object> body, AuthContext ctx,
                                              HttpServletRequest request) {
        require(ctx, "identity:write");
        String tenant = body.get("tenant_id") == null ? tenant(ctx) : String.valueOf(body.get("tenant_id"));
        String status = body.get("status") == null ? "active" : String.valueOf(body.get("status"));
        Map<String, Object> created = identities.create(body, tenant, status, meta(request), "admin");
        if (body.get("role_codes") instanceof List<?> codes) {
            for (Object code : codes) {
                Map<String, Object> role = db.list("SELECT id FROM roles WHERE code = :code AND deleted_at IS NULL",
                        Db.params("code", String.valueOf(code))).stream().findFirst().orElse(null);
                if (role != null) {
                    rbac.grantRole(String.valueOf(created.get("id")), tenant, String.valueOf(role.get("id")),
                            ctx.identityId());
                }
            }
        }
        return Api.created(created);
    }

    @GetMapping("/identities/{id}")
    public Map<String, Object> identity(@PathVariable String id, AuthContext ctx) {
        require(ctx, "identity:read");
        Map<String, Object> out = new LinkedHashMap<>(identities.get(id));
        out.put("identifiers", db.list("""
                SELECT kind, value, normalized_value, verified_at, is_primary FROM identity_identifiers
                WHERE identity_id = :id ORDER BY kind
                """, Db.params("id", id)));
        out.put("roles", identities.rolesOf(id));
        out.put("mfa_factors", mfa.status(id));
        out.put("sessions", db.count("SELECT count(*) FROM auth_sessions WHERE identity_id = :id AND status = 'active'",
                Db.params("id", id)));
        return Api.ok(out);
    }

    @PatchMapping("/identities/{id}")
    public Map<String, Object> updateIdentity(@PathVariable String id, @RequestBody Map<String, Object> body,
                                              AuthContext ctx, HttpServletRequest request) {
        require(ctx, "identity:write");
        return Api.ok(identities.adminUpdate(id, body, ctx.identityId(), meta(request)));
    }

    @PutMapping("/identities/{id}/status")
    public Map<String, Object> identityStatus(@PathVariable String id, @RequestBody Map<String, Object> body,
                                              AuthContext ctx, HttpServletRequest request) {
        require(ctx, "identity:write");
        return Api.ok(identities.setStatus(id, body, ctx.identityId(), meta(request)));
    }

    @GetMapping("/identities/{id}/roles")
    public Map<String, Object> identityRoles(@PathVariable String id, AuthContext ctx) {
        require(ctx, "user_role:read");
        return Api.ok(Map.of("items", identities.rolesOf(id)));
    }

    @PostMapping("/identities/{id}/roles")
    public Map<String, Object> assignRole(@PathVariable String id, @RequestBody Map<String, Object> body,
                                          AuthContext ctx) {
        require(ctx, "user_role:write");
        String roleId = resolveRole(body);
        rbac.grantRole(id, tenant(ctx), roleId, ctx.identityId());
        return Api.ok(Map.of("assigned", true));
    }

    @DeleteMapping("/identities/{id}/roles/{roleId}")
    public Map<String, Object> revokeRole(@PathVariable String id, @PathVariable String roleId, AuthContext ctx) {
        require(ctx, "user_role:write");
        rbac.revokeRole(id, roleId);
        return Api.ok(Map.of("revoked", true));
    }

    @GetMapping("/identities/{id}/permissions")
    public Map<String, Object> identityPermissions(@PathVariable String id, AuthContext ctx) {
        require(ctx, "permission:read");
        return Api.ok(Map.of("items", rbac.permissions(id, tenant(ctx)),
                "direct", db.list("SELECT * FROM user_permissions WHERE identity_id = :id AND revoked_at IS NULL",
                        Db.params("id", id))));
    }

    @PostMapping("/identities/{id}/permissions")
    public Map<String, Object> grantPermission(@PathVariable String id, @RequestBody Map<String, Object> body,
                                              AuthContext ctx) {
        require(ctx, "permission:write");
        String permissionId = resolvePermission(body);
        rbac.grantPermission(id, tenant(ctx), permissionId, ctx.identityId(),
                body.get("effect") == null ? "allow" : String.valueOf(body.get("effect")));
        return Api.ok(Map.of("granted", true));
    }

    @DeleteMapping("/identities/{id}/permissions/{permissionId}")
    public Map<String, Object> revokePermission(@PathVariable String id, @PathVariable String permissionId,
                                                AuthContext ctx) {
        require(ctx, "permission:write");
        rbac.revokePermission(id, permissionId);
        return Api.ok(Map.of("revoked", true));
    }

    @PostMapping("/identities/{id}/mfa/reset")
    public Map<String, Object> resetMfa(@PathVariable String id, AuthContext ctx) {
        require(ctx, "mfa:reset");
        mfa.adminReset(id);
        audit.log(tenant(ctx), ctx.identityId(), "identity.mfa_reset", "identity", id, "success", null, null, Map.of());
        return Api.ok(Map.of("reset", true));
    }

    // ---------------- 角色 ----------------

    private static final Spec ROLES = new Spec("roles",
            Set.of("tenant_id", "code", "name", "description", "kind", "scope", "parent_id", "status", "is_builtin", "metadata"),
            Set.of("metadata"), true, "created_at DESC", "code,name");
    private static final Spec PERMISSIONS = new Spec("permissions",
            Set.of("tenant_id", "code", "name", "description", "category", "kind", "parent_id", "status"),
            Set.of(), true, "category, code", "code,name");
    private static final Spec POLICIES = new Spec("authorization_policies",
            Set.of("tenant_id", "name", "description", "effect", "subject_type", "subject_id", "action",
                    "resource_type", "resource_id", "condition", "priority", "enabled"),
            Set.of("condition"), false, "priority ASC", "name");
    private static final Spec RELATIONS = new Spec("resource_relations",
            Set.of("tenant_id", "resource_type", "resource_id", "relation", "subject_type", "subject_id", "expires_at"),
            Set.of(), false, "created_at DESC", "resource_type,resource_id");
    private static final Spec TENANTS = new Spec("tenants",
            Set.of("code", "name", "status", "settings"), Set.of("settings"), true, "created_at DESC", "code,name");
    private static final Spec MENUS = new Spec("menu_resources",
            Set.of("tenant_id", "parent_id", "code", "name", "route", "icon", "menu_type", "sort_order",
                    "visible", "permission_id", "status"),
            Set.of(), true, "sort_order, created_at", "code,name");
    private static final Spec BUTTONS = new Spec("button_resources",
            Set.of("tenant_id", "menu_id", "api_resource_id", "code", "name", "permission_id", "status"),
            Set.of(), true, "created_at", "code,name");
    private static final Spec APIS = new Spec("api_resources",
            Set.of("tenant_id", "method", "path_pattern", "permission_id", "description", "status"),
            Set.of(), true, "created_at DESC", "path_pattern,method");
    private static final Spec DATA_PERMISSIONS = new Spec("data_permissions",
            Set.of("tenant_id", "role_id", "permission_id", "scope_type", "scope_config", "description"),
            Set.of("scope_config"), false, "created_at DESC", "scope_type");

    @GetMapping("/roles")
    public Map<String, Object> roles(AuthContext ctx, @RequestParam(defaultValue = "1") int page,
                                     @RequestParam(defaultValue = "20") int page_size,
                                     @RequestParam(required = false) String q,
                                     @RequestParam(required = false) String status) {
        require(ctx, "role:read");
        return Api.ok(listSpec(ROLES, page, page_size, q, status));
    }

    @PostMapping("/roles")
    public ResponseEntity<Map<String, Object>> createRole(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "role:write");
        body.putIfAbsent("tenant_id", tenant(ctx));
        return Api.created(createSpec(ROLES, body));
    }

    @GetMapping("/roles/{id}")
    public Map<String, Object> role(@PathVariable String id, AuthContext ctx) {
        require(ctx, "role:read");
        Map<String, Object> role = findSpec(ROLES, id);
        role.put("permissions", db.list("""
                SELECT p.id, p.code, p.name FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id
                WHERE rp.role_id = :id ORDER BY p.code
                """, Db.params("id", id)));
        return Api.ok(role);
    }

    @PatchMapping("/roles/{id}")
    public Map<String, Object> updateRole(@PathVariable String id, @RequestBody Map<String, Object> body,
                                          AuthContext ctx) {
        require(ctx, "role:write");
        return Api.ok(updateSpec(ROLES, id, body));
    }

    @DeleteMapping("/roles/{id}")
    public Map<String, Object> deleteRole(@PathVariable String id, AuthContext ctx) {
        require(ctx, "role:write");
        deleteSpec(ROLES, id);
        return Api.ok(Map.of("deleted", true));
    }

    @PutMapping("/roles/{id}/permissions")
    @SuppressWarnings("unchecked")
    public Map<String, Object> setRolePermissions(@PathVariable String id, @RequestBody Map<String, Object> body,
                                                  AuthContext ctx) {
        require(ctx, "role:write");
        List<String> ids;
        Object raw = body.get("permission_ids");
        if (raw instanceof List<?> list) {
            ids = list.stream().map(String::valueOf).toList();
        } else if (body.get("codes") instanceof List<?> codes) {
            ids = codes.stream().map(code -> db.list("SELECT id FROM permissions WHERE code = :code AND deleted_at IS NULL",
                            Db.params("code", String.valueOf(code))).stream().findFirst()
                    .map(r -> String.valueOf(r.get("id"))).orElse(null))
                    .filter(java.util.Objects::nonNull).toList();
        } else {
            ids = List.of();
        }
        rbac.setRolePermissions(id, ids, ctx.identityId());
        return Api.ok(Map.of("updated", true, "permissions", ids));
    }

    @PostMapping("/roles/{id}/assign")
    @SuppressWarnings("unchecked")
    public Map<String, Object> assignRoleMembers(@PathVariable String id, @RequestBody Map<String, Object> body,
                                                 AuthContext ctx) {
        require(ctx, "user_role:write");
        List<String> identityIds = body.get("identity_ids") instanceof List<?> list
                ? list.stream().map(String::valueOf).toList()
                : List.of(String.valueOf(body.get("identity_id")));
        identityIds.forEach(identityId -> rbac.grantRole(identityId, tenant(ctx), id, ctx.identityId()));
        return Api.ok(Map.of("assigned", identityIds.size()));
    }

    @GetMapping("/roles/{id}/members")
    public Map<String, Object> roleMembers(@PathVariable String id, AuthContext ctx) {
        require(ctx, "user_role:read");
        return Api.ok(Map.of("items", db.list("""
                SELECT ur.id, ur.identity_id, i.username, i.email, i.display_name, i.status
                FROM user_roles ur JOIN identities i ON i.id = ur.identity_id
                WHERE ur.role_id = :id AND ur.revoked_at IS NULL ORDER BY ur.created_at DESC
                """, Db.params("id", id))));
    }

    // ---------------- 权限 ----------------

    @GetMapping("/permissions")
    public Map<String, Object> permissions(AuthContext ctx, @RequestParam(defaultValue = "1") int page,
                                           @RequestParam(defaultValue = "100") int page_size,
                                           @RequestParam(required = false) String q,
                                           @RequestParam(required = false) String status) {
        require(ctx, "permission:read");
        return Api.ok(listSpec(PERMISSIONS, page, page_size, q, status));
    }

    @GetMapping("/permissions/tree")
    public Map<String, Object> permissionTree(AuthContext ctx) {
        require(ctx, "permission:read");
        return Api.ok(rbac.permissionTree(tenant(ctx)));
    }

    @PostMapping("/permissions")
    public ResponseEntity<Map<String, Object>> createPermission(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "permission:write");
        return Api.created(createSpec(PERMISSIONS, body));
    }

    @GetMapping("/permissions/{id}")
    public Map<String, Object> permission(@PathVariable String id, AuthContext ctx) {
        require(ctx, "permission:read");
        return Api.ok(findSpec(PERMISSIONS, id));
    }

    @PatchMapping("/permissions/{id}")
    public Map<String, Object> updatePermission(@PathVariable String id, @RequestBody Map<String, Object> body,
                                                AuthContext ctx) {
        require(ctx, "permission:write");
        rbac.invalidate(null);
        return Api.ok(updateSpec(PERMISSIONS, id, body));
    }

    @DeleteMapping("/permissions/{id}")
    public Map<String, Object> deletePermission(@PathVariable String id, AuthContext ctx) {
        require(ctx, "permission:write");
        deleteSpec(PERMISSIONS, id);
        rbac.invalidate(null);
        return Api.ok(Map.of("deleted", true));
    }

    // ---------------- 策略 / 关系 ----------------

    @GetMapping("/policies")
    public Map<String, Object> policies(AuthContext ctx, @RequestParam(defaultValue = "1") int page,
                                        @RequestParam(defaultValue = "20") int page_size,
                                        @RequestParam(required = false) String q) {
        require(ctx, "policy:read");
        return Api.ok(listSpec(POLICIES, page, page_size, q, null));
    }

    @PostMapping("/policies")
    public ResponseEntity<Map<String, Object>> createPolicy(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "policy:write");
        body.putIfAbsent("tenant_id", tenant(ctx));
        return Api.created(createSpec(POLICIES, body));
    }

    @GetMapping("/policies/{id}")
    public Map<String, Object> policy(@PathVariable String id, AuthContext ctx) {
        require(ctx, "policy:read");
        return Api.ok(findSpec(POLICIES, id));
    }

    @PatchMapping("/policies/{id}")
    public Map<String, Object> updatePolicy(@PathVariable String id, @RequestBody Map<String, Object> body,
                                            AuthContext ctx) {
        require(ctx, "policy:write");
        return Api.ok(updateSpec(POLICIES, id, body));
    }

    @DeleteMapping("/policies/{id}")
    public Map<String, Object> deletePolicy(@PathVariable String id, AuthContext ctx) {
        require(ctx, "policy:write");
        deleteSpec(POLICIES, id);
        return Api.ok(Map.of("deleted", true));
    }

    @GetMapping("/resource-relations")
    public Map<String, Object> relations(AuthContext ctx, @RequestParam(defaultValue = "1") int page,
                                         @RequestParam(defaultValue = "20") int page_size,
                                         @RequestParam(required = false) String q,
                                         @RequestParam(required = false) String resource_type,
                                         @RequestParam(required = false) String resource_id) {
        require(ctx, "resource:read");
        Map<String, Object> params = new LinkedHashMap<>();
        StringBuilder where = new StringBuilder(" WHERE tenant_id = :tenant");
        params.put("tenant", tenant(ctx));
        if (resource_type != null) {
            where.append(" AND resource_type = :rtype");
            params.put("rtype", resource_type);
        }
        if (resource_id != null) {
            where.append(" AND resource_id = :rid");
            params.put("rid", resource_id);
        }
        long total = db.count("SELECT count(*) FROM resource_relations" + where, params);
        params.put("limit", pageSize(page_size));
        params.put("offset", (page(page) - 1) * pageSize(page_size));
        return Api.ok(Db.page(db.list("SELECT * FROM resource_relations" + where
                + " ORDER BY created_at DESC LIMIT :limit OFFSET :offset", params), total, page(page), pageSize(page_size)));
    }

    @PostMapping("/resource-relations")
    public ResponseEntity<Map<String, Object>> createRelation(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "resource:write");
        body.putIfAbsent("tenant_id", tenant(ctx));
        return Api.created(createSpec(RELATIONS, body));
    }

    @DeleteMapping("/resource-relations/{id}")
    public Map<String, Object> deleteRelation(@PathVariable String id, AuthContext ctx) {
        require(ctx, "resource:write");
        deleteSpec(RELATIONS, id);
        return Api.ok(Map.of("deleted", true));
    }

    // ---------------- 菜单 / 按钮 / API / 数据权限 ----------------

    @GetMapping("/menus")
    public Map<String, Object> menus(AuthContext ctx, @RequestParam(defaultValue = "1") int page,
                                     @RequestParam(defaultValue = "100") int page_size,
                                     @RequestParam(required = false) String q) {
        require(ctx, "menu:read");
        return Api.ok(listSpec(MENUS, page, page_size, q, null));
    }

    @PostMapping("/menus")
    public ResponseEntity<Map<String, Object>> createMenu(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "menu:write");
        body.putIfAbsent("tenant_id", tenant(ctx));
        return Api.created(createSpec(MENUS, body));
    }

    @PatchMapping("/menus/{id}")
    public Map<String, Object> updateMenu(@PathVariable String id, @RequestBody Map<String, Object> body,
                                          AuthContext ctx) {
        require(ctx, "menu:write");
        return Api.ok(updateSpec(MENUS, id, body));
    }

    @DeleteMapping("/menus/{id}")
    public Map<String, Object> deleteMenu(@PathVariable String id, AuthContext ctx) {
        require(ctx, "menu:write");
        deleteSpec(MENUS, id);
        return Api.ok(Map.of("deleted", true));
    }

    @GetMapping("/buttons")
    public Map<String, Object> buttons(AuthContext ctx, @RequestParam(defaultValue = "1") int page,
                                       @RequestParam(defaultValue = "100") int page_size,
                                       @RequestParam(required = false) String q) {
        require(ctx, "button:read");
        return Api.ok(listSpec(BUTTONS, page, page_size, q, null));
    }

    @PostMapping("/buttons")
    public ResponseEntity<Map<String, Object>> createButton(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "button:write");
        body.putIfAbsent("tenant_id", tenant(ctx));
        return Api.created(createSpec(BUTTONS, body));
    }

    @PatchMapping("/buttons/{id}")
    public Map<String, Object> updateButton(@PathVariable String id, @RequestBody Map<String, Object> body,
                                            AuthContext ctx) {
        require(ctx, "button:write");
        return Api.ok(updateSpec(BUTTONS, id, body));
    }

    @DeleteMapping("/buttons/{id}")
    public Map<String, Object> deleteButton(@PathVariable String id, AuthContext ctx) {
        require(ctx, "button:write");
        deleteSpec(BUTTONS, id);
        return Api.ok(Map.of("deleted", true));
    }

    @GetMapping("/api-resources")
    public Map<String, Object> apiResources(AuthContext ctx, @RequestParam(defaultValue = "1") int page,
                                            @RequestParam(defaultValue = "100") int page_size,
                                            @RequestParam(required = false) String q) {
        require(ctx, "api:read");
        return Api.ok(listSpec(APIS, page, page_size, q, null));
    }

    @PostMapping("/api-resources")
    public ResponseEntity<Map<String, Object>> createApi(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "api:write");
        body.putIfAbsent("tenant_id", tenant(ctx));
        return Api.created(createSpec(APIS, body));
    }

    @PatchMapping("/api-resources/{id}")
    public Map<String, Object> updateApi(@PathVariable String id, @RequestBody Map<String, Object> body,
                                         AuthContext ctx) {
        require(ctx, "api:write");
        return Api.ok(updateSpec(APIS, id, body));
    }

    @DeleteMapping("/api-resources/{id}")
    public Map<String, Object> deleteApi(@PathVariable String id, AuthContext ctx) {
        require(ctx, "api:write");
        deleteSpec(APIS, id);
        return Api.ok(Map.of("deleted", true));
    }

    @GetMapping("/data-permissions")
    public Map<String, Object> dataPermissions(AuthContext ctx, @RequestParam(defaultValue = "1") int page,
                                               @RequestParam(defaultValue = "100") int page_size,
                                               @RequestParam(required = false) String q) {
        require(ctx, "data:read");
        return Api.ok(listSpec(DATA_PERMISSIONS, page, page_size, q, null));
    }

    @PostMapping("/data-permissions")
    public ResponseEntity<Map<String, Object>> createDataPermission(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "data:write");
        body.putIfAbsent("tenant_id", tenant(ctx));
        return Api.created(createSpec(DATA_PERMISSIONS, body));
    }

    @PatchMapping("/data-permissions/{id}")
    public Map<String, Object> updateDataPermission(@PathVariable String id, @RequestBody Map<String, Object> body,
                                                    AuthContext ctx) {
        require(ctx, "data:write");
        return Api.ok(updateSpec(DATA_PERMISSIONS, id, body));
    }

    @DeleteMapping("/data-permissions/{id}")
    public Map<String, Object> deleteDataPermission(@PathVariable String id, AuthContext ctx) {
        require(ctx, "data:write");
        deleteSpec(DATA_PERMISSIONS, id);
        return Api.ok(Map.of("deleted", true));
    }

    // ---------------- 租户 ----------------

    @GetMapping("/tenants")
    public Map<String, Object> tenants(AuthContext ctx, @RequestParam(defaultValue = "1") int page,
                                       @RequestParam(defaultValue = "20") int page_size,
                                       @RequestParam(required = false) String q) {
        require(ctx, "tenant:read");
        return Api.ok(listSpec(TENANTS, page, page_size, q, null));
    }

    @PostMapping("/tenants")
    public ResponseEntity<Map<String, Object>> createTenant(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "tenant:write");
        return Api.created(createSpec(TENANTS, body));
    }

    @PutMapping("/tenants/{id}/status")
    public Map<String, Object> tenantStatus(@PathVariable String id, @RequestBody Map<String, Object> body,
                                            AuthContext ctx) {
        require(ctx, "tenant:write");
        return Api.ok(updateSpec(TENANTS, id, Map.of("status", body.get("status"))));
    }

    // ---------------- 审计 / 密钥 ----------------

    @GetMapping("/audit-logs")
    public Map<String, Object> auditLogs(AuthContext ctx, @RequestParam(defaultValue = "1") int page,
                                         @RequestParam(defaultValue = "50") int page_size,
                                         @RequestParam(required = false) String action,
                                         @RequestParam(required = false) String actor_id,
                                         @RequestParam(required = false) String from,
                                         @RequestParam(required = false) String to) {
        require(ctx, "audit:read");
        return Api.ok(audit.list(tenant(ctx), page(page), pageSize(page_size), action, actor_id, from, to));
    }

    @GetMapping("/signing-keys")
    public Map<String, Object> signingKeys(AuthContext ctx) {
        require(ctx, "signing_key:rotate");
        return Api.ok(Map.of("items", db.list("""
                SELECT id, kid, algorithm, status, created_at, activated_at, retired_at, not_after
                FROM signing_keys ORDER BY created_at DESC
                """)));
    }

    @PostMapping("/signing-keys/rotate")
    public Map<String, Object> rotateSigningKey(AuthContext ctx) {
        require(ctx, "signing_key:rotate");
        Map<String, Object> out = keys.rotate();
        audit.log(tenant(ctx), ctx.identityId(), "signing_key.rotated", "signing_key",
                String.valueOf(out.get("kid")), "success", null, null, Map.of());
        return Api.ok(out);
    }

    // ---------------- OAuth 客户端 / Scope ----------------

    @GetMapping("/oauth/clients")
    public Map<String, Object> clients(AuthContext ctx, @RequestParam(defaultValue = "1") int page,
                                       @RequestParam(defaultValue = "20") int page_size,
                                       @RequestParam(required = false) String q) {
        require(ctx, "client:read");
        return Api.ok(oauth.listClients(page(page), pageSize(page_size), q));
    }

    @PostMapping("/oauth/clients")
    public ResponseEntity<Map<String, Object>> createClient(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "client:write");
        body.putIfAbsent("tenant_id", tenant(ctx));
        return Api.created(oauth.createClient(body));
    }

    @GetMapping("/oauth/clients/{clientId}")
    public Map<String, Object> client(@PathVariable String clientId, AuthContext ctx) {
        require(ctx, "client:read");
        Map<String, Object> out = new LinkedHashMap<>(oauth.client(clientId));
        out.remove("client_secret_hash");
        return Api.ok(out);
    }

    @PatchMapping("/oauth/clients/{clientId}")
    public Map<String, Object> updateClient(@PathVariable String clientId, @RequestBody Map<String, Object> body,
                                            AuthContext ctx) {
        require(ctx, "client:write");
        return Api.ok(oauth.updateClient(clientId, body));
    }

    @DeleteMapping("/oauth/clients/{clientId}")
    public Map<String, Object> deleteClient(@PathVariable String clientId, AuthContext ctx) {
        require(ctx, "client:write");
        db.update("DELETE FROM oauth_clients WHERE client_id = :id", Db.params("id", clientId));
        return Api.ok(Map.of("deleted", true));
    }

    @PostMapping("/oauth/clients/{clientId}/secret")
    public Map<String, Object> rotateSecret(@PathVariable String clientId, AuthContext ctx) {
        require(ctx, "client:write");
        return Api.ok(oauth.rotateSecret(clientId));
    }

    @PutMapping("/oauth/clients/{clientId}/status")
    public Map<String, Object> clientStatus(@PathVariable String clientId, @RequestBody Map<String, Object> body,
                                            AuthContext ctx) {
        require(ctx, "client:write");
        return Api.ok(oauth.setClientStatus(clientId, String.valueOf(body.get("status"))));
    }

    @GetMapping("/oauth/scopes")
    public Map<String, Object> scopes(AuthContext ctx) {
        require(ctx, "scope:read");
        return Api.ok(Map.of("items", oauth.listScopes()));
    }

    @PostMapping("/oauth/scopes")
    public ResponseEntity<Map<String, Object>> createScope(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "scope:write");
        return Api.created(oauth.createScope(body));
    }

    @DeleteMapping("/oauth/scopes/{name}")
    public Map<String, Object> deleteScope(@PathVariable String name, AuthContext ctx) {
        require(ctx, "scope:write");
        oauth.deleteScope(name);
        return Api.ok(Map.of("deleted", true));
    }

    // ---------------- 身份提供商 / SAML ----------------

    @GetMapping("/identity-providers")
    public Map<String, Object> providers(AuthContext ctx) {
        require(ctx, "idp:manage");
        return Api.ok(Map.of("items", federation.providers()));
    }

    @PostMapping("/identity-providers")
    public ResponseEntity<Map<String, Object>> createProvider(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "idp:manage");
        return Api.created(federation.createProvider(body, ctx.identityId()));
    }

    @GetMapping("/identity-providers/{code}")
    public Map<String, Object> provider(@PathVariable String code, AuthContext ctx) {
        require(ctx, "idp:manage");
        Map<String, Object> out = new LinkedHashMap<>(federation.provider(code));
        out.remove("client_secret_encrypted");
        return Api.ok(out);
    }

    @PatchMapping("/identity-providers/{code}")
    public Map<String, Object> updateProvider(@PathVariable String code, @RequestBody Map<String, Object> body,
                                              AuthContext ctx) {
        require(ctx, "idp:manage");
        return Api.ok(federation.updateProvider(code, body, ctx.identityId()));
    }

    @DeleteMapping("/identity-providers/{code}")
    public Map<String, Object> deleteProvider(@PathVariable String code, AuthContext ctx) {
        require(ctx, "idp:manage");
        db.update("DELETE FROM identity_providers WHERE code = :code", Db.params("code", code));
        return Api.ok(Map.of("deleted", true));
    }

    @GetMapping("/saml/idp")
    public Map<String, Object> samlIdp(AuthContext ctx) {
        require(ctx, "saml:manage");
        Map<String, Object> out = new LinkedHashMap<>(saml.idpConfig());
        out.remove("private_key_encrypted");
        return Api.ok(out);
    }

    @PutMapping("/saml/idp")
    public Map<String, Object> updateSamlIdp(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "saml:manage");
        return Api.ok(saml.updateIdp(body));
    }

    @PostMapping("/saml/idp/rotate-certificate")
    public Map<String, Object> rotateSamlCertificate(AuthContext ctx) {
        require(ctx, "saml:manage");
        Map<String, Object> out = new LinkedHashMap<>(saml.rotateCertificate());
        out.remove("private_key_encrypted");
        return Api.ok(out);
    }

    @GetMapping("/saml/sps")
    public Map<String, Object> samlSps(AuthContext ctx) {
        require(ctx, "saml:manage");
        return Api.ok(Map.of("items", saml.listSps()));
    }

    @PostMapping("/saml/sps")
    public ResponseEntity<Map<String, Object>> upsertSamlSp(@RequestBody Map<String, Object> body, AuthContext ctx) {
        require(ctx, "saml:manage");
        body.putIfAbsent("tenant_id", tenant(ctx));
        return Api.created(saml.upsertSp(body));
    }

    @DeleteMapping("/saml/sps/{code}")
    public Map<String, Object> deleteSamlSp(@PathVariable String code, AuthContext ctx) {
        require(ctx, "saml:manage");
        saml.deleteSp(code);
        return Api.ok(Map.of("deleted", true));
    }

    // ---------------- 通用 CRUD ----------------

    private Map<String, Object> listSpec(Spec spec, int page, int size, String q, String status) {
        Map<String, Object> params = new LinkedHashMap<>();
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (spec.softDelete) {
            where.append(" AND deleted_at IS NULL");
        }
        if (status != null && !status.isBlank()) {
            where.append(" AND status = :status");
            params.put("status", status);
        }
        if (q != null && !q.isBlank() && spec.keywordColumns != null) {
            where.append(" AND (");
            String[] columns = spec.keywordColumns.split(",");
            for (int i = 0; i < columns.length; i++) {
                if (i > 0) {
                    where.append(" OR ");
                }
                where.append("lower(").append(columns[i]).append(") LIKE lower(:q)");
            }
            where.append(")");
            params.put("q", "%" + q + "%");
        }
        long total = db.count("SELECT count(*) FROM " + spec.table + where, params);
        params.put("limit", size);
        params.put("offset", (page - 1) * size);
        return Db.page(db.list("SELECT * FROM " + spec.table + where + " ORDER BY " + spec.order
                + " LIMIT :limit OFFSET :offset", params), total, page, size);
    }

    private Map<String, Object> findSpec(Spec spec, String id) {
        String where = spec.softDelete ? " WHERE id = :id AND deleted_at IS NULL" : " WHERE id = :id";
        return db.list("SELECT * FROM " + spec.table + where, Db.params("id", id)).stream().findFirst()
                .orElseThrow(() -> ApiException.notFound("记录不存在"));
    }

    private Map<String, Object> createSpec(Spec spec, Map<String, Object> body) {
        String id = Ids.uuidStr();
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("id", id);
        List<String> columns = new java.util.ArrayList<>();
        List<String> values = new java.util.ArrayList<>();
        columns.add("id");
        values.add(":id");
        for (String column : spec.columns) {
            if (body.containsKey(column)) {
                columns.add(column);
                values.add(":" + column);
                params.put(column, spec.jsonColumns.contains(column) && body.get(column) != null
                        ? Json.jsonb(body.get(column)) : body.get(column));
            }
        }
        try {
            db.update("INSERT INTO " + spec.table + " (" + String.join(", ", columns) + ") VALUES ("
                    + String.join(", ", values) + ")", params);
        } catch (org.springframework.dao.DataIntegrityViolationException e) {
            throw ApiException.badRequest("数据不满足约束: " + rootMessage(e));
        }
        return findSpec(spec, id);
    }

    private Map<String, Object> updateSpec(Spec spec, String id, Map<String, Object> body) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("id", id);
        List<String> sets = new java.util.ArrayList<>();
        for (String column : spec.columns) {
            if (body.containsKey(column)) {
                sets.add(column + " = :" + column);
                params.put(column, spec.jsonColumns.contains(column) && body.get(column) != null
                        ? Json.jsonb(body.get(column)) : body.get(column));
            }
        }
        if (sets.isEmpty()) {
            return findSpec(spec, id);
        }
        if (spec.tableHasUpdatedAt) {
            sets.add("updated_at = now()");
        }
        db.update("UPDATE " + spec.table + " SET " + String.join(", ", sets)
                + " WHERE id = :id" + (spec.softDelete ? " AND deleted_at IS NULL" : ""), params);
        return findSpec(spec, id);
    }

    private void deleteSpec(Spec spec, String id) {
        int count = spec.softDelete
                ? db.update("UPDATE " + spec.table + " SET deleted_at = now() WHERE id = :id AND deleted_at IS NULL",
                Db.params("id", id))
                : db.update("DELETE FROM " + spec.table + " WHERE id = :id", Db.params("id", id));
        if (count == 0) {
            throw ApiException.notFound("记录不存在");
        }
    }

    private static String rootMessage(Throwable e) {
        Throwable current = e;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        return current.getMessage() == null ? "约束冲突" : current.getMessage();
    }

    private void require(AuthContext ctx, String permission) {
        rbac.assertAdmin(permission, ctx.identityId(), tenant(ctx));
    }

    private String tenant(AuthContext ctx) {
        return ctx.tenantId() == null ? IdentityService.DEFAULT_TENANT : ctx.tenantId();
    }

    private String resolveRole(Map<String, Object> body) {
        if (body.get("role_id") != null) {
            return String.valueOf(body.get("role_id"));
        }
        return db.list("SELECT id FROM roles WHERE code = :code AND deleted_at IS NULL",
                        Db.params("code", String.valueOf(body.get("role_code")))).stream().findFirst()
                .map(r -> String.valueOf(r.get("id")))
                .orElseThrow(() -> ApiException.notFound("角色不存在"));
    }

    private String resolvePermission(Map<String, Object> body) {
        if (body.get("permission_id") != null) {
            return String.valueOf(body.get("permission_id"));
        }
        return db.list("SELECT id FROM permissions WHERE code = :code AND deleted_at IS NULL",
                        Db.params("code", String.valueOf(body.get("permission_code")))).stream().findFirst()
                .map(r -> String.valueOf(r.get("id")))
                .orElseThrow(() -> ApiException.notFound("权限不存在"));
    }

    private SessionService.LoginMeta meta(HttpServletRequest request) {
        return new SessionService.LoginMeta(AuthController.clientIp(request), request.getHeader("User-Agent"),
                request.getHeader("X-Device-Id"), request.getHeader("X-Device-Name"),
                request.getHeader("X-Request-Id"));
    }

    private static int page(int page) {
        return Math.max(1, page);
    }

    private static int pageSize(int size) {
        return Math.min(500, Math.max(1, size));
    }

    private record Spec(String table, Set<String> columns, Set<String> jsonColumns, boolean softDelete,
                        String order, String keywordColumns, boolean tableHasUpdatedAt) {
        Spec(String table, Set<String> columns, Set<String> jsonColumns, boolean softDelete,
             String order, String keywordColumns) {
            this(table, new LinkedHashSet<>(columns), new LinkedHashSet<>(jsonColumns), softDelete, order,
                    keywordColumns, !Set.of("resource_relations").contains(table));
        }
    }
}
