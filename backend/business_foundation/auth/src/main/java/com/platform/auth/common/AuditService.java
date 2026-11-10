package com.platform.auth.common;

import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class AuditService {
    private final Db db;

    public AuditService(Db db) {
        this.db = db;
    }

    public void log(String tenantId, String actorId, String action, String resourceType, String resourceId,
                    String result, String ip, String userAgent, Map<String, Object> detail) {
        try {
            db.inTx(() -> {
                String prev = db.list("SELECT hash FROM security_audit_logs ORDER BY id DESC LIMIT 1")
                        .stream().findFirst().map(r -> String.valueOf(r.get("hash"))).orElse("");
                String payload = Json.write(detail == null ? Map.of() : detail);
                String hash = Ids.sha256(prev + "|" + tenantId + "|" + actorId + "|" + action + "|"
                        + resourceType + "|" + resourceId + "|" + result + "|" + payload + "|" + System.currentTimeMillis());
                db.update("""
                        INSERT INTO security_audit_logs
                        (tenant_id, actor_id, actor_type, action, resource_type, resource_id, result, ip, user_agent,
                         trace_id, detail, prev_hash, hash)
                        VALUES (:tenant, :actor, 'user', :action, :rtype, :rid, :result, :ip, :ua, :trace, :detail, :prev, :hash)
                        """, Db.params(
                        "tenant", tenantId, "actor", actorId, "action", action, "rtype", resourceType,
                        "rid", resourceId, "result", result == null ? "success" : result, "ip", ip,
                        "ua", userAgent, "trace", MDC.get("traceId"), "detail", Json.jsonb(detail == null ? Map.of() : detail),
                        "prev", prev.isBlank() ? null : prev, "hash", hash));
            });
        } catch (Exception ignored) {
            // 审计失败不应阻断主流程，但需在日志中体现
        }
        org.slf4j.LoggerFactory.getLogger(AuditService.class)
                .info("audit action={} actor={} result={} resource={}:{}", action, actorId, result, resourceType, resourceId);
    }

    public Map<String, Object> list(String tenantId, int page, int size, String action, String actorId,
                                    String from, String to) {
        Map<String, Object> params = new LinkedHashMap<>();
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (tenantId != null) {
            where.append(" AND tenant_id = :tenant");
            params.put("tenant", tenantId);
        }
        if (action != null && !action.isBlank()) {
            where.append(" AND action = :action");
            params.put("action", action);
        }
        if (actorId != null && !actorId.isBlank()) {
            where.append(" AND actor_id = :actor");
            params.put("actor", actorId);
        }
        if (from != null && !from.isBlank()) {
            where.append(" AND created_at >= :from");
            params.put("from", from);
        }
        if (to != null && !to.isBlank()) {
            where.append(" AND created_at <= :to");
            params.put("to", to);
        }
        long total = db.count("SELECT count(*) FROM security_audit_logs" + where, params);
        params.put("limit", size);
        params.put("offset", (page - 1) * size);
        List<Map<String, Object>> items = db.list(
                "SELECT * FROM security_audit_logs" + where + " ORDER BY id DESC LIMIT :limit OFFSET :offset", params);
        return Db.page(items, total, page, size);
    }
}
