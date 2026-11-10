package com.platform.file.interfaces.web;

import com.platform.file.shared.Db;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class MetaController {
    private final Db db;

    public MetaController(Db db) {
        this.db = db;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of("status", "ok", "service", "file-service");
    }

    @GetMapping("/live")
    public Map<String, Object> live() {
        return Map.of("status", "ok");
    }

    @GetMapping({"/ready", "/readyz"})
    public ResponseEntity<Map<String, Object>> ready() {
        try {
            if (db.ping()) {
                return ResponseEntity.ok(Map.of("status", "ok"));
            }
        } catch (Exception ignored) {
            // 数据库不可用。
        }
        return ResponseEntity.status(503).body(Map.of("status", "unavailable"));
    }
}
