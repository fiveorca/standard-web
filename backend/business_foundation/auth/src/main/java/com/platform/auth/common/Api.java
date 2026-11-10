package com.platform.auth.common;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.LinkedHashMap;
import java.util.Map;

public final class Api {
    private Api() {}

    public static Map<String, Object> ok(Object data) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", "ok");
        body.put("data", data);
        return body;
    }

    public static ResponseEntity<Map<String, Object>> created(Object data) {
        return ResponseEntity.status(HttpStatus.CREATED).body(ok(data));
    }

    public static ResponseEntity<Map<String, Object>> noContent() {
        return ResponseEntity.noContent().build();
    }
}
