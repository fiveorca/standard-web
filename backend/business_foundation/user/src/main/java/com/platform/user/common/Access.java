package com.platform.user.common;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class Access {
    private Access() {
    }

    public static void requirePermission(boolean allowed, String permission) {
        if (!allowed) {
            throw ApiException.forbidden("缺少权限: " + permission);
        }
    }

    public static void requireInternal(String provided, String expected) {
        if (expected == null || expected.isBlank() || !tokenMatches(provided, expected)) {
            throw ApiException.unauthorized("内部服务令牌无效");
        }
    }

    public static boolean tokenMatches(String provided, String expected) {
        if (provided == null || expected == null || expected.isBlank()) {
            return false;
        }
        return MessageDigest.isEqual(
                provided.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8));
    }
}
