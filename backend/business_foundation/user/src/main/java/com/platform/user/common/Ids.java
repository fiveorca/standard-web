package com.platform.user.common;

import java.util.UUID;

public final class Ids {
    private Ids() {
    }

    public static String uuid() {
        return UUID.randomUUID().toString();
    }

    public static UUID uuidValue() {
        return UUID.randomUUID();
    }

    public static UUID parse(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value.trim());
        } catch (Exception e) {
            return null;
        }
    }
}
