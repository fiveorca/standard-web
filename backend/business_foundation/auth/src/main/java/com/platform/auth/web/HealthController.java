package com.platform.auth.web;

import com.platform.auth.common.Api;
import com.platform.auth.common.Db;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class HealthController {
    private final Db db;

    public HealthController(Db db) {
        this.db = db;
    }

    @GetMapping({"/health", "/health/live", "/live"})
    public Map<String, Object> health() {
        return Map.of("status", "ok");
    }

    @GetMapping({"/ready", "/health/ready", "/readiness"})
    public ResponseEntity<Map<String, Object>> ready() {
        Map<String, Object> checks = new LinkedHashMap<>();
        boolean database;
        try {
            db.count("SELECT 1", Map.of());
            database = true;
        } catch (Exception e) {
            database = false;
        }
        checks.put("database", database ? "up" : "down");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", database ? "ok" : "unavailable");
        body.put("checks", checks);
        return ResponseEntity.status(database ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE).body(body);
    }
}
