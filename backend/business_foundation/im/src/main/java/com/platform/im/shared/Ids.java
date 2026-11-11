package com.platform.im.shared;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

public final class Ids {
    private static final SecureRandom RANDOM = new SecureRandom();

    private Ids() {
    }

    public static UUID uuid() {
        return UUID.randomUUID();
    }

    public static String randomToken(int bytes) {
        byte[] buffer = new byte[bytes];
        RANDOM.nextBytes(buffer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
    }

    public static UUID parseUuid(String value, String field) {
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
