package com.platform.file.shared;

import java.util.Map;

public record PageQuery(int page, int size) {
    public static PageQuery of(Map<String, String> query) {
        int page = intValue(query.get("page"), 1);
        int size = intValue(query.get("page_size"), 20);
        if (page < 1) {
            page = 1;
        }
        if (size < 1) {
            size = 20;
        }
        if (size > 200) {
            size = 200;
        }
        return new PageQuery(page, size);
    }

    public int offset() {
        return (page - 1) * size;
    }

    private static int intValue(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw ApiException.badRequest("分页参数格式不合法");
        }
    }
}
