package com.platform.user.common;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Api {
    private Api() {
    }

    public static Map<String, Object> ok(Object data) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("code", "ok");
        out.put("data", data);
        return out;
    }

    public static Map<String, Object> ok() {
        return ok(Map.of());
    }

    public static Map<String, Object> page(List<Map<String, Object>> items, long total, int page, int size) {
        return ok(Db.page(items, total, page, size));
    }
}
