package com.platform.user.common;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

public final class Times {
    private Times() {
    }

    public static Timestamp parse(String value, String field) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String text = value.trim();
        try {
            return Timestamp.from(Instant.parse(text));
        } catch (Exception ignored) {
            // try other formats
        }
        try {
            return Timestamp.from(OffsetDateTime.parse(text).toInstant());
        } catch (Exception ignored) {
            // try other formats
        }
        try {
            return Timestamp.from(LocalDateTime.parse(text).toInstant(ZoneOffset.UTC));
        } catch (Exception ignored) {
            // try other formats
        }
        try {
            return Timestamp.from(LocalDate.parse(text).atStartOfDay().toInstant(ZoneOffset.UTC));
        } catch (Exception e) {
            throw ApiException.validation(field, "时间格式不合法，应为 ISO-8601");
        }
    }

    public static Timestamp now() {
        return Timestamp.from(Instant.now());
    }
}
