package com.platform.auth.bootstrap;

import com.platform.auth.common.Db;
import com.platform.auth.common.Json;
import com.platform.auth.config.AppProps;
import com.platform.auth.security.KeyService;
import com.platform.auth.security.PasswordService;
import com.platform.auth.service.IdentityService;
import com.platform.auth.service.RbacService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 启动引导：确保签名密钥、默认租户、内置管理员、内置客户端与资源目录存在。
 * 所有操作幂等，重复启动不会产生重复数据。
 */
@Component
public class SeedRunner implements ApplicationRunner {
    private static final Logger log = LoggerFactory.getLogger(SeedRunner.class);
    private static final String TENANT = "00000000-0000-0000-0000-000000000001";

    private final AppProps props;
    private final Db db;
    private final KeyService keys;
    private final PasswordService passwords;
    private final IdentityService identities;
    private final RbacService rbac;

    public SeedRunner(AppProps props, Db db, KeyService keys, PasswordService passwords,
                      IdentityService identities, RbacService rbac) {
        this.props = props;
        this.db = db;
        this.keys = keys;
        this.passwords = passwords;
        this.identities = identities;
        this.rbac = rbac;
    }

    @Override
    public void run(ApplicationArguments args) {
        keys.ensureKey();
        if (!props.isBootstrapEnabled()) {
            return;
        }
        seedTenant();
        String adminId = seedAdmin();
        seedClients();
        seedResources();
        String roleId = findRoleId("super_admin");
        if (adminId != null && roleId != null) {
            rbac.grantRole(adminId, TENANT, roleId, null);
        }
        log.info("auth-center bootstrap completed");
    }

    private void seedTenant() {
        db.update("""
                INSERT INTO tenants (id, code, name) VALUES (CAST(:id AS uuid), 'default', 'Default Tenant')
                ON CONFLICT (id) DO NOTHING
                """, Db.params("id", TENANT));
    }

    private String seedAdmin() {
        Map<String, Object> existing = db.find(
                "SELECT id FROM identities WHERE lower(username) = lower(:u) AND deleted_at IS NULL",
                Db.params("u", props.getBootstrapAdminUsername())).orElse(null);
        if (existing != null) {
            return String.valueOf(existing.get("id"));
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("username", props.getBootstrapAdminUsername());
        body.put("email", props.getBootstrapAdminEmail());
        body.put("password", props.getBootstrapAdminPassword());
        body.put("tenant", "default");
        body.put("display_name", "Administrator");
        Map<String, Object> created = identities.create(body, TENANT, "active", null, "bootstrap");
        log.info("bootstrap administrator '{}' created", props.getBootstrapAdminUsername());
        return String.valueOf(created.get("id"));
    }

    private String findRoleId(String code) {
        return db.find("SELECT id FROM roles WHERE code = :code AND tenant_id IS NULL AND deleted_at IS NULL",
                        Db.params("code", code))
                .map(r -> String.valueOf(r.get("id")))
                .orElse(null);
    }

    private void seedClients() {
        String secret = passwords.hash(props.getBootstrapClientSecret());
        upsertClient("auth-console", "Auth Console", "管理控制台 Web 客户端", "confidential", secret,
                List.of("http://localhost:3000/callback", "http://localhost:5173/callback"),
                List.of("http://localhost:3000", "http://localhost:5173"),
                List.of("authorization_code", "refresh_token"),
                List.of("openid", "profile", "email", "offline_access"), true);
        upsertClient("user-center", "User Center", "用户中心服务客户端（机器到机器）", "confidential", secret,
                List.of(),
                List.of(),
                List.of("client_credentials"),
                List.of("internal"), false);
        upsertClient("web-app", "Web Application", "公共 SPA 客户端（强制 PKCE）", "public", null,
                List.of("http://localhost:3000/callback", "http://localhost:5173/callback"),
                List.of("http://localhost:3000", "http://localhost:5173"),
                List.of("authorization_code", "refresh_token"),
                List.of("openid", "profile", "email", "offline_access"), true);
    }

    private void upsertClient(String clientId, String name, String description, String kind, String secretHash,
                              List<String> redirects, List<String> logoutRedirects,
                              List<String> grants, List<String> scopes, boolean requirePkce) {
        db.update("""
                INSERT INTO oauth_clients (tenant_id, client_id, client_secret_hash, name, description, kind,
                                           redirect_uris, post_logout_redirect_uris, grant_types, scopes, require_pkce)
                VALUES (CAST(:tenant AS uuid), :client_id, :secret, :name, :description, :kind,
                        :redirects, :logout, :grants, :scopes, :pkce)
                ON CONFLICT (client_id) DO NOTHING
                """, Db.params("tenant", TENANT, "client_id", clientId, "secret", secretHash, "name", name,
                "description", description, "kind", kind,
                "redirects", Json.jsonb(redirects), "logout", Json.jsonb(logoutRedirects),
                "grants", Json.jsonb(grants), "scopes", Json.jsonb(scopes), "pkce", requirePkce));
    }

    private void seedResources() {
        menu("system", null, "系统管理", null, null, 10);
        menu("identity", "system", "身份管理", "/identities", "identity:read", 20);
        menu("rbac", "system", "权限管理", "/rbac", "role:read", 30);
        menu("oauth", "system", "OAuth 客户端", "/oauth-clients", "client:read", 40);
        menu("audit", "system", "审计日志", "/audit-logs", "audit:read", 50);

        button("identity.create", "identity", "新增身份", "identity:write");
        button("identity.disable", "identity", "禁用身份", "identity:write");
        button("role.create", "rbac", "新增角色", "role:write");
        button("role.assign", "rbac", "分配角色", "user_role:write");
        button("client.create", "oauth", "新增客户端", "client:write");

        api("GET", "/api/v1/admin/identities", "identity:read", "查询身份列表");
        api("POST", "/api/v1/admin/identities", "identity:write", "创建身份");
        api("PATCH", "/api/v1/admin/identities/{id}", "identity:write", "更新身份");
        api("GET", "/api/v1/admin/roles", "role:read", "查询角色列表");
        api("POST", "/api/v1/admin/roles", "role:write", "创建角色");
        api("GET", "/api/v1/admin/permissions", "permission:read", "查询权限列表");
        api("GET", "/api/v1/admin/audit-logs", "audit:read", "查询审计日志");
        api("POST", "/api/v1/admin/signing-keys/rotate", "signing_key:rotate", "轮换签名密钥");
        api("POST", "/api/v1/authz/check", "authz:check", "授权检查");
    }

    private void menu(String code, String parentCode, String name, String route, String permissionCode, int sort) {
        db.update("""
                INSERT INTO menu_resources (tenant_id, parent_id, code, name, route, menu_type, sort_order, permission_id)
                SELECT NULL,
                       (SELECT id FROM menu_resources WHERE code = :parent AND tenant_id IS NULL AND deleted_at IS NULL),
                       :code, :name, :route, :type, :sort,
                       (SELECT id FROM permissions WHERE code = :perm AND tenant_id IS NULL LIMIT 1)
                WHERE NOT EXISTS (
                    SELECT 1 FROM menu_resources WHERE code = :code AND tenant_id IS NULL AND deleted_at IS NULL)
                """, Db.params("parent", parentCode, "code", code, "name", name, "route", route,
                "type", parentCode == null ? "directory" : "menu", "sort", sort, "perm", permissionCode));
    }

    private void button(String code, String menuCode, String name, String permissionCode) {
        db.update("""
                INSERT INTO button_resources (tenant_id, menu_id, code, name, permission_id)
                SELECT NULL,
                       (SELECT id FROM menu_resources WHERE code = :menu AND tenant_id IS NULL AND deleted_at IS NULL),
                       :code, :name,
                       (SELECT id FROM permissions WHERE code = :perm AND tenant_id IS NULL LIMIT 1)
                WHERE NOT EXISTS (
                    SELECT 1 FROM button_resources WHERE code = :code AND tenant_id IS NULL AND deleted_at IS NULL)
                """, Db.params("menu", menuCode, "code", code, "name", name, "perm", permissionCode));
    }

    private void api(String method, String path, String permissionCode, String description) {
        db.update("""
                INSERT INTO api_resources (tenant_id, method, path_pattern, permission_id, description)
                SELECT NULL, :method, :path,
                       (SELECT id FROM permissions WHERE code = :perm AND tenant_id IS NULL LIMIT 1), :description
                WHERE NOT EXISTS (
                    SELECT 1 FROM api_resources
                    WHERE tenant_id IS NULL AND upper(method) = upper(:method) AND path_pattern = :path
                      AND deleted_at IS NULL)
                """, Db.params("method", method, "path", path, "perm", permissionCode, "description", description));
    }
}
