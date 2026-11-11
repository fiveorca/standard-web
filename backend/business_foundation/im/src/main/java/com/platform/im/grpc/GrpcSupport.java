package com.platform.im.grpc;

import com.platform.im.security.AuthPrincipal;
import com.platform.im.shared.ApiException;

import java.util.UUID;

final class GrpcSupport {
    private GrpcSupport() {
    }

    static AuthPrincipal principal() {
        AuthPrincipal principal = GrpcAuthInterceptor.PRINCIPAL.get();
        return principal == null ? AuthPrincipal.system("grpc-anonymous") : principal;
    }

    static UUID tenant(String requested, AuthPrincipal principal) {
        UUID tenantId = null;
        if (requested != null && !requested.isBlank()) {
            try {
                tenantId = UUID.fromString(requested.trim());
            } catch (IllegalArgumentException e) {
                throw ApiException.validation("tenant_id", "必须是合法的 UUID");
            }
        }
        if (principal != null && principal.tenantId() != null) {
            if (tenantId != null && !tenantId.equals(principal.tenantId())) {
                throw ApiException.forbidden("无权操作其他租户的资源");
            }
            return principal.tenantId();
        }
        return tenantId;
    }

    static UUID uuid(String value, String field) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value.trim());
        } catch (IllegalArgumentException e) {
            throw ApiException.validation(field, "必须是合法的 UUID");
        }
    }
}
