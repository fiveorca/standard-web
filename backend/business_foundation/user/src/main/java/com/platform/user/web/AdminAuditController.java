package com.platform.user.web;

import com.platform.user.bootstrap.AuthClient;
import com.platform.user.common.Api;
import com.platform.user.common.AuthContext;
import com.platform.user.common.CurrentUser;
import com.platform.user.service.AuditService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/admin/audit-logs")
public class AdminAuditController {
    private final AuditService audit;
    private final AuthClient authClient;

    public AdminAuditController(AuditService audit, AuthClient authClient) {
        this.audit = audit;
        this.authClient = authClient;
    }

    @GetMapping
    public Map<String, Object> list(@CurrentUser AuthContext auth, @RequestParam Map<String, String> query) {
        authClient.requirePermission(auth, "audit:read");
        return Api.ok(audit.list(auth.tenantId(), query));
    }
}
