package com.platform.user.bootstrap;

import com.platform.user.common.Db;
import com.platform.user.common.Ids;
import com.platform.user.common.Json;
import com.platform.user.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class OutboxService {
    private static final Logger log = LoggerFactory.getLogger(OutboxService.class);
    private static final int MAX_ATTEMPTS = 10;

    private final Db db;
    private final AppProperties props;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(3)).build();

    public OutboxService(Db db, AppProperties props) {
        this.db = db;
        this.props = props;
    }

    public void publish(String eventType, String aggregateType, String aggregateId, Map<String, Object> payload) {
        Map<String, Object> body = payload == null ? new LinkedHashMap<>() : new LinkedHashMap<>(payload);
        db.update("""
                INSERT INTO outbox_events (id, event_type, aggregate_type, aggregate_id, payload, trace_id, occurred_at)
                VALUES (:id, :type, :atype, :aid, :payload, :trace, now())
                """, Db.params(
                "id", Ids.uuidValue(),
                "type", eventType,
                "atype", aggregateType,
                "aid", String.valueOf(aggregateId),
                "payload", Json.jsonb(body),
                "trace", MDC.get("traceId")));
    }

    @Scheduled(fixedDelay = 2000, initialDelay = 3000)
    public void dispatch() {
        List<Map<String, Object>> claimed;
        try {
            claimed = db.inTx(() -> {
                List<Map<String, Object>> rows = db.list("""
                        SELECT id, event_type, aggregate_type, aggregate_id, payload, trace_id, version, occurred_at, attempts
                        FROM outbox_events
                        WHERE published_at IS NULL AND dead_lettered_at IS NULL AND next_attempt_at <= now()
                        ORDER BY next_attempt_at
                        LIMIT 20
                        FOR UPDATE SKIP LOCKED
                        """);
                for (Map<String, Object> row : rows) {
                    db.update("UPDATE outbox_events SET next_attempt_at = now() + interval '60 seconds' WHERE id = :id",
                            Db.params("id", row.get("id")));
                }
                return rows;
            });
        } catch (Exception e) {
            log.debug("outbox claim skipped: {}", e.getMessage());
            return;
        }
        for (Map<String, Object> row : claimed) {
            deliver(row);
        }
    }

    private void deliver(Map<String, Object> row) {
        String id = String.valueOf(row.get("id"));
        Map<String, Object> envelope = new LinkedHashMap<>();
        envelope.put("event_id", id);
        envelope.put("event_type", row.get("event_type"));
        envelope.put("aggregate_type", row.get("aggregate_type"));
        envelope.put("aggregate_id", row.get("aggregate_id"));
        envelope.put("occurred_at", row.get("occurred_at"));
        envelope.put("version", row.get("version"));
        envelope.put("trace_id", row.get("trace_id"));
        envelope.put("payload", row.get("payload"));
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(props.getEventsTarget()))
                    .timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json")
                    .header("x-internal-token", props.getInternalToken() == null ? "" : props.getInternalToken())
                    .POST(HttpRequest.BodyPublishers.ofString(Json.write(envelope)))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 == 2) {
                db.update("""
                        UPDATE outbox_events SET published_at = now(), attempts = attempts + 1, last_error = NULL
                        WHERE id = :id
                        """, Db.params("id", id));
            } else {
                fail(id, row, "HTTP " + response.statusCode());
            }
        } catch (Exception e) {
            fail(id, row, e.getMessage());
        }
    }

    private void fail(String id, Map<String, Object> row, String error) {
        int attempts = ((Number) row.getOrDefault("attempts", 0)).intValue() + 1;
        boolean dead = attempts >= MAX_ATTEMPTS;
        long delay = Math.min(300, 5L << Math.min(attempts, 6));
        db.update("""
                UPDATE outbox_events
                SET attempts = :attempts,
                    last_error = :error,
                    dead_lettered_at = CASE WHEN :dead THEN now() ELSE dead_lettered_at END,
                    next_attempt_at = CASE WHEN :dead THEN next_attempt_at
                                           ELSE now() + (:delay * interval '1 second') END
                WHERE id = :id
                """, Db.params(
                "attempts", attempts,
                "error", error == null ? "unknown" : error.substring(0, Math.min(500, error.length())),
                "dead", dead,
                "delay", (int) delay,
                "id", id));
        log.warn("outbox event {} failed (attempt {}): {}", id, attempts, error);
    }
}
