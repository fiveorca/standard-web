package com.platform.file.infrastructure.persistence;

import com.platform.file.shared.Json;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public final class Rows {
    private Rows() {
    }

    public static UUID uuid(Map<String, Object> row, String key) {
        Object value = row.get(key);
        if (value == null) {
            return null;
        }
        return value instanceof UUID id ? id : UUID.fromString(String.valueOf(value));
    }

    public static String text(Map<String, Object> row, String key) {
        Object value = row.get(key);
        return value == null ? null : String.valueOf(value);
    }

    public static long longValue(Map<String, Object> row, String key) {
        Object value = row.get(key);
        return value == null ? 0 : ((Number) value).longValue();
    }

    public static Long nullableLong(Map<String, Object> row, String key) {
        Object value = row.get(key);
        return value == null ? null : ((Number) value).longValue();
    }

    public static int integer(Map<String, Object> row, String key) {
        Object value = row.get(key);
        return value == null ? 0 : ((Number) value).intValue();
    }

    public static boolean bool(Map<String, Object> row, String key) {
        Object value = row.get(key);
        return value instanceof Boolean b ? b : value != null && Boolean.parseBoolean(String.valueOf(value));
    }

    public static Instant instant(Map<String, Object> row, String key) {
        Object value = row.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Instant i) {
            return i;
        }
        return Instant.parse(String.valueOf(value));
    }

    public static Map<String, Object> jsonMap(Map<String, Object> row, String key) {
        return Json.readMap(row.get(key));
    }
}
