package com.platform.auth.web;

import com.platform.auth.common.Api;
import com.platform.auth.common.AuthContext;
import com.platform.auth.service.RbacService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/authz")
public class AuthzController {
    private final RbacService rbac;

    public AuthzController(RbacService rbac) {
        this.rbac = rbac;
    }

    private String tenant(AuthContext ctx) {
        return ctx.tenantId() == null ? com.platform.auth.service.IdentityService.DEFAULT_TENANT : ctx.tenantId();
    }

    @GetMapping("/me")
    public Map<String, Object> me(AuthContext ctx) {
        return Api.ok(rbac.me(ctx.identityId(), tenant(ctx), ctx.sessionId()));
    }

    @GetMapping("/me/permissions")
    public Map<String, Object> myPermissions(AuthContext ctx) {
        return Api.ok(Map.of("items", rbac.permissions(ctx.identityId(), tenant(ctx))));
    }

    @GetMapping("/me/menus")
    public Map<String, Object> myMenus(AuthContext ctx) {
        return Api.ok(Map.of("items", rbac.menus(tenant(ctx), rbac.permissions(ctx.identityId(), tenant(ctx)))));
    }

    @GetMapping("/me/buttons")
    public Map<String, Object> myButtons(AuthContext ctx) {
        return Api.ok(Map.of("items", rbac.buttons(tenant(ctx), rbac.permissions(ctx.identityId(), tenant(ctx)))));
    }

    @GetMapping("/me/apis")
    public Map<String, Object> myApis(AuthContext ctx) {
        return Api.ok(Map.of("items", rbac.apis(tenant(ctx), rbac.permissions(ctx.identityId(), tenant(ctx)))));
    }

    @GetMapping("/me/data-scope")
    public Map<String, Object> myDataScope(AuthContext ctx) {
        return Api.ok(Map.of("items", rbac.dataScope(ctx.identityId(), tenant(ctx))));
    }

    @PostMapping("/check")
    public Map<String, Object> check(@RequestBody Map<String, Object> body, AuthContext ctx) {
        String identityId = body.get("identity_id") == null || !ctx.isAdmin()
                ? ctx.identityId() : String.valueOf(body.get("identity_id"));
        String tenantId = body.get("tenant_id") == null ? tenant(ctx) : String.valueOf(body.get("tenant_id"));
        String permission = String.valueOf(body.get("permission"));
        Object context = body.get("context");
        return Api.ok(rbac.check(identityId, tenantId, permission,
                body.get("resource_type") == null ? null : String.valueOf(body.get("resource_type")),
                body.get("resource_id") == null ? null : String.valueOf(body.get("resource_id")),
                context instanceof Map<?, ?> map ? com.platform.auth.common.Json.readMap(map) : Map.of()));
    }

    @SuppressWarnings("unchecked")
    @PostMapping("/batch-check")
    public Map<String, Object> batchCheck(@RequestBody Map<String, Object> body, AuthContext ctx) {
        List<Map<String, Object>> checks = (List<Map<String, Object>>) body.getOrDefault("checks", List.of());
        List<Map<String, Object>> results = checks.stream().map(item -> {
            String identityId = item.get("identity_id") == null || !ctx.isAdmin()
                    ? ctx.identityId() : String.valueOf(item.get("identity_id"));
            return rbac.check(identityId,
                    item.get("tenant_id") == null ? tenant(ctx) : String.valueOf(item.get("tenant_id")),
                    String.valueOf(item.get("permission")),
                    item.get("resource_type") == null ? null : String.valueOf(item.get("resource_type")),
                    item.get("resource_id") == null ? null : String.valueOf(item.get("resource_id")),
                    item.get("context") instanceof Map<?, ?> map ? com.platform.auth.common.Json.readMap(map) : Map.of());
        }).toList();
        return Api.ok(Map.of("results", results));
    }
}
