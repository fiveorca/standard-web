package com.platform.im.security;

import com.platform.im.config.AppProperties;

import java.util.Set;
import java.util.UUID;

public record AuthPrincipal(String subject, UUID tenantId, Set<String> roles, PrincipalType type, String deviceId) {
    public enum PrincipalType {
        ADMIN, SERVICE, DEVICE, SYSTEM, INTERNAL
    }

    public static AuthPrincipal system(String subject) {
        return new AuthPrincipal(subject, null, Set.of(), PrincipalType.SYSTEM, null);
    }

    public static AuthPrincipal internal() {
        return new AuthPrincipal("internal", null, Set.of(), PrincipalType.INTERNAL, null);
    }

    public static AuthPrincipal device(String deviceId, UUID tenantId) {
        return new AuthPrincipal(deviceId, tenantId, Set.of("DEVICE"), PrincipalType.DEVICE, deviceId);
    }

    public boolean hasRole(String role) {
        return role != null && (roles.contains(role) || roles.contains("ADMIN") || roles.contains("ROLE_" + role));
    }

    public boolean isAdmin(AppProperties props) {
        return type == PrincipalType.ADMIN || type == PrincipalType.SYSTEM
                || hasRole(props.security.adminRole) || hasRole("IM_ADMIN");
    }

    public boolean isDevice() {
        return type == PrincipalType.DEVICE;
    }
}
