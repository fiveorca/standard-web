package com.platform.im.shared;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

public final class Api {
    private Api() {
    }

    public static Map<String, Object> ok(Object data) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("code", 0);
        out.put("message", "success");
        out.put("data", data);
        out.put("timestamp", Instant.now().toString());
        return out;
    }

    public static Map<String, Object> ok() {
        return ok(Map.of());
    }

    public static Map<String, Object> page(PageResult<?> result) {
        return ok(result.toMap());
    }
}
