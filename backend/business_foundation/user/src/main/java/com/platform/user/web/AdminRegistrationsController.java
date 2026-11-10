package com.platform.user.web;

import com.platform.user.bootstrap.AuthClient;
import com.platform.user.common.Api;
import com.platform.user.common.AuthContext;
import com.platform.user.common.Body;
import com.platform.user.common.CurrentUser;
import com.platform.user.service.RegistrationService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin/registrations")
public class AdminRegistrationsController {
    private final RegistrationService registrations;
    private final AuthClient authClient;
    private final RequestContext ctx;

    public AdminRegistrationsController(RegistrationService registrations, AuthClient authClient, RequestContext ctx) {
        this.registrations = registrations;
        this.authClient = authClient;
        this.ctx = ctx;
    }

    @GetMapping
    public Map<String, Object> list(@CurrentUser AuthContext auth, @RequestParam Map<String, String> query) {
        authClient.requirePermission(auth, "identity:manage");
        return Api.ok(registrations.list(auth.tenantId(), query));
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@CurrentUser AuthContext auth, @PathVariable String id) {
        authClient.requirePermission(auth, "identity:manage");
        return Api.ok(registrations.get(auth.tenantId(), ctx.id(id, "id")));
    }

    @PostMapping("/{id}/review")
    public Map<String, Object> review(@CurrentUser AuthContext auth, @PathVariable String id,
                                      @RequestBody(required = false) Map<String, Object> body,
                                      HttpServletRequest request) {
        authClient.requirePermission(auth, "identity:manage");
        return Api.ok(registrations.review(auth.tenantId(), ctx.id(id, "id"), Body.of(body),
                auth.identityId(), ctx.meta(request)));
    }
}
