package com.platform.user.common;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public record AuthContext(
        UUID identityId,
        UUID tenantId,
        List<String> roles,
        List<String> permissions,
        List<String> scopes,
        String clientId,
        Map<String, Object> claims) {

    public boolean hasPermission(String permission) {
        return permissions != null && permissions.contains(permission);
    }

    public boolean hasScope(String scope) {
        return scopes != null && (scopes.contains(scope) || scopes.contains("internal"));
    }

    public static List<String> stringList(Object value) {
        if (value instanceof List<?> list) {
            Set<String> out = new LinkedHashSet<>();
            list.forEach(item -> {
                if (item != null) {
                    out.add(String.valueOf(item));
                }
            });
            return List.copyOf(out);
        }
        if (value instanceof String text && !text.isBlank()) {
            Set<String> out = new LinkedHashSet<>();
            for (String part : text.split("[\\s,]+")) {
                if (!part.isBlank()) {
                    out.add(part);
                }
            }
            return List.copyOf(out);
        }
        return List.of();
    }
}
