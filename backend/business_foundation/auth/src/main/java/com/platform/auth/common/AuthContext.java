package com.platform.auth.common;

import java.time.Instant;
import java.util.Map;
import java.util.Set;

public record AuthContext(
        String identityId,
        String tenantId,
        String sessionId,
        String clientId,
        String tokenId,
        Set<String> roles,
        Set<String> permissions,
        Set<String> amr,
        String acr,
        String scope,
        Instant expiresAt,
        Map<String, Object> claims
) {
    public boolean isAdmin() {
        return permissions.contains("admin:access") || roles.contains("super_admin");
    }

    public boolean hasPermission(String permission) {
        return permissions.contains(permission) || isAdmin();
    }

    public void require(String permission) {
        if (!hasPermission(permission)) {
            throw ApiException.forbidden("缺少权限: " + permission);
        }
    }
}
