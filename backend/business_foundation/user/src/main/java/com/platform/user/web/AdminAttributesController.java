package com.platform.user.web;

import com.platform.user.bootstrap.AuthClient;
import com.platform.user.common.Api;
import com.platform.user.common.AuthContext;
import com.platform.user.common.Body;
import com.platform.user.common.CurrentUser;
import com.platform.user.service.AttributeService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin/attributes")
public class AdminAttributesController {
    private final AttributeService attributes;
    private final AuthClient authClient;
    private final RequestContext ctx;

    public AdminAttributesController(AttributeService attributes, AuthClient authClient, RequestContext ctx) {
        this.attributes = attributes;
        this.authClient = authClient;
        this.ctx = ctx;
    }

    @GetMapping
    public Map<String, Object> list(@CurrentUser AuthContext auth, @RequestParam Map<String, String> query) {
        authClient.requirePermission(auth, "identity:manage");
        return Api.ok(attributes.listDefinitions(auth.tenantId(), query));
    }

    @PostMapping
    public Map<String, Object> create(@CurrentUser AuthContext auth,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest request) {
        authClient.requirePermission(auth, "identity:manage");
        return Api.ok(attributes.createDefinition(auth.tenantId(), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@CurrentUser AuthContext auth, @PathVariable String id) {
        authClient.requirePermission(auth, "identity:manage");
        return Api.ok(attributes.getDefinition(auth.tenantId(), ctx.id(id, "id")));
    }

    @PatchMapping("/{id}")
    public Map<String, Object> update(@CurrentUser AuthContext auth, @PathVariable String id,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest request) {
        authClient.requirePermission(auth, "identity:manage");
        return Api.ok(attributes.updateDefinition(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }

    @DeleteMapping("/{id}")
    public Map<String, Object> delete(@CurrentUser AuthContext auth, @PathVariable String id,
                                      HttpServletRequest request) {
        authClient.requirePermission(auth, "identity:manage");
        attributes.deleteDefinition(auth.tenantId(), ctx.id(id, "id"), auth.identityId(), ctx.meta(request));
        return Api.ok(Map.of("id", id));
    }
}
