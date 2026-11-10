package com.platform.auth.common;

import com.platform.auth.config.AppProps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;

@Service
public class OutboxService {
    private static final Logger log = LoggerFactory.getLogger(OutboxService.class);
    private final Db db;
    private final AppProps props;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    public OutboxService(Db db, AppProps props) {
        this.db = db;
        this.props = props;
    }

    public void publish(String eventType, String aggregateType, String aggregateId, Map<String, Object> payload) {
        db.update("""
                INSERT INTO outbox_events (id, event_type, aggregate_type, aggregate_id, payload, trace_id, occurred_at)
                VALUES (:id, :type, :atype, :aid, :payload, :trace, now())
                """, Db.params(
                "id", Ids.uuid(), "type", eventType, "atype", aggregateType, "aid", aggregateId,
                "payload", Json.jsonb(payload), "trace", org.slf4j.MDC.get("traceId")));
    }

    @Scheduled(fixedDelay = 2000, initialDelay = 3000)
    public void dispatch() {
        List<Map<String, Object>> claimed;
        try {
            claimed = db.inTx(() -> {
                List<Map<String, Object>> rows = db.list("""
                        SELECT id, event_type, payload, attempts FROM outbox_events
                        WHERE status = 'pending' AND next_attempt_at <= now()
                        ORDER BY next_attempt_at LIMIT 20 FOR UPDATE SKIP LOCKED
                        """);
                for (Map<String, Object> row : rows) {
                    db.update("UPDATE outbox_events SET status = 'publishing' WHERE id = :id",
                            Db.params("id", row.get("id")));
                }
                return rows;
            });
        } catch (Exception e) {
            log.debug("outbox claim skipped: {}", e.getMessage());
            return;
        }
        for (Map<String, Object> row : claimed) {
            String id = String.valueOf(row.get("id"));
            String body = Json.write(Map.of(
                    "event_id", id,
                    "event_type", row.get("event_type"),
                    "aggregate_type", "identity",
                    "payload", row.get("payload")));
            try {
                HttpRequest request = HttpRequest.newBuilder(URI.create(props.getEventsTarget()))
                        .timeout(Duration.ofSeconds(4))
                        .header("Content-Type", "application/json")
                        .header("x-internal-token", props.getInternalToken())
                        .POST(HttpRequest.BodyPublishers.ofString(body))
                        .build();
                HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
                if (response.statusCode() / 100 == 2) {
                    db.update("UPDATE outbox_events SET status = 'published', published_at = now(), last_error = NULL WHERE id = :id",
                            Db.params("id", id));
                } else {
                    fail(id, row, "HTTP " + response.statusCode());
                }
            } catch (Exception e) {
                fail(id, row, e.getMessage());
            }
        }
    }

    private void fail(String id, Map<String, Object> row, String error) {
        int attempts = ((Number) row.getOrDefault("attempts", 0)).intValue() + 1;
        boolean dead = attempts >= 10;
        long delay = Math.min(300, (long) Math.pow(2, Math.min(attempts, 8)));
        db.update("""
                UPDATE outbox_events SET status = :status, attempts = :attempts, last_error = :error,
                next_attempt_at = now() + (:delay || ' seconds')::interval
                WHERE id = :id
                """, Db.params("status", dead ? "dead" : "pending", "attempts", attempts,
                "error", error == null ? "unknown" : error.substring(0, Math.min(500, error.length())),
                "delay", String.valueOf(delay), "id", id));
        log.warn("outbox event {} failed (attempt {}): {}", id, attempts, error);
    }
}
