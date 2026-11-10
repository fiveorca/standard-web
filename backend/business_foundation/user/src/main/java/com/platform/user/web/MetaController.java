package com.platform.user.web;

import com.platform.user.common.Db;
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
        return Map.of("status", "ok");
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
            // fall through to unavailable
        }
        return ResponseEntity.status(503).body(Map.of("status", "unavailable"));
    }

    @GetMapping("/openapi.json")
    public Map<String, Object> openapi() {
        return OpenApiDocument.build();
    }

    @GetMapping(value = "/docs", produces = "text/html; charset=utf-8")
    public String docs() {
        return """
                <!DOCTYPE html>
                <html lang="zh-CN">
                <head>
                  <meta charset="utf-8"/>
                  <meta name="viewport" content="width=device-width, initial-scale=1"/>
                  <title>User Center API</title>
                  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui.css"/>
                  <style>body{margin:0;background:#fafafa}</style>
                </head>
                <body>
                  <div id="swagger-ui"></div>
                  <script src="https://unpkg.com/swagger-ui-dist@5.17.14/swagger-ui-bundle.js"></script>
                  <script>
                    window.onload = function () {
                      window.ui = SwaggerUIBundle({
                        url: '/openapi.json',
                        dom_id: '#swagger-ui',
                        deepLinking: true,
                        persistAuthorization: true,
                        displayRequestDuration: true
                      });
                    };
                  </script>
                </body>
                </html>
                """;
    }
}
