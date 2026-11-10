package com.platform.user.service;

import com.platform.user.common.Api;
import com.platform.user.common.Db;
import com.platform.user.common.Json;
import com.platform.user.common.PageQuery;
import com.platform.user.common.RequestMeta;
import com.platform.user.common.Text;
import com.platform.user.common.Times;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class AuditService {
    private final Db db;

    public AuditService(Db db) {
        this.db = db;
    }

    public void record(UUID tenantId, UUID actorId, String action, String resourceType, String resourceId,
                       String result, RequestMeta meta, Map<String, Object> detail) {
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("tenant", tenantId);
        params.put("actor", actorId);
        params.put("action", action);
        params.put("rtype", resourceType);
        params.put("rid", resourceId);
        params.put("result", result == null ? "success" : result);
        params.put("ip", meta == null ? null : meta.ip());
        params.put("ua", meta == null ? null : Text.limit(meta.userAgent(), 500));
        params.put("trace", meta == null ? null : meta.traceId());
        params.put("detail", Json.jsonb(detail == null ? Map.of() : detail));
        db.update("""
                INSERT INTO user_audit_logs
                    (tenant_id, actor_id, action, resource_type, resource_id, result, ip, user_agent, trace_id, detail)
                VALUES
                    (:tenant, :actor, :action, :rtype, :rid, :result, :ip, :ua, :trace, :detail)
                """, params);
    }

    public void success(UUID tenantId, UUID actorId, String action, String resourceType, String resourceId,
                        RequestMeta meta, Map<String, Object> detail) {
        record(tenantId, actorId, action, resourceType, resourceId, "success", meta, detail);
    }

    public void statusHistory(UUID tenantId, UUID userId, String fromStatus, String toStatus,
                              String reason, UUID operatorId) {
        db.update("""
                INSERT INTO user_status_history (tenant_id, user_id, from_status, to_status, reason, operator_id)
                VALUES (:tenant, :user, :from, :to, :reason, :operator)
                """, Db.params("tenant", tenantId, "user", userId, "from", fromStatus, "to", toStatus,
                "reason", Text.limit(reason, 500), "operator", operatorId));
    }

    public List<Map<String, Object>> statusHistory(UUID tenantId, UUID userId, PageQuery page) {
        return db.list("""
                SELECT * FROM user_status_history
                WHERE tenant_id = :tenant AND user_id = :user
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
                """, Db.params("tenant", tenantId, "user", userId, "limit", page.limit(), "offset", page.offset()));
    }

    public void orgHistory(UUID tenantId, UUID userId, UUID organizationId, UUID departmentId,
                           String action, UUID operatorId, Map<String, Object> detail) {
        db.update("""
                INSERT INTO user_organization_history
                    (tenant_id, user_id, organization_id, department_id, action, operator_id, detail)
                VALUES (:tenant, :user, :org, :dept, :action, :operator, :detail)
                """, Db.params("tenant", tenantId, "user", userId, "org", organizationId, "dept", departmentId,
                "action", action, "operator", operatorId,
                "detail", Json.jsonb(detail == null ? Map.of() : detail)));
    }

    public List<Map<String, Object>> orgHistory(UUID tenantId, UUID userId) {
        return db.list("""
                SELECT h.*, o.name AS organization_name, d.name AS department_name
                FROM user_organization_history h
                LEFT JOIN organizations o ON o.id = h.organization_id
                LEFT JOIN departments d ON d.id = h.department_id
                WHERE h.tenant_id = :tenant AND h.user_id = :user
                ORDER BY h.created_at DESC
                LIMIT 200
                """, Db.params("tenant", tenantId, "user", userId));
    }

    public Map<String, Object> list(UUID tenantId, Map<String, String> query) {
        int page = intValue(query.get("page"), 1);
        int size = intValue(query.get("page_size"), 20);
        PageQuery pq = PageQuery.of(page, size);
        StringBuilder where = new StringBuilder(" WHERE tenant_id = :tenant");
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("tenant", tenantId);
        String action = blank(query.get("action"));
        if (action != null) {
            where.append(" AND action = :action");
            params.put("action", action);
        }
        String actor = blank(query.get("actor_id") != null ? query.get("actor_id") : query.get("actor"));
        if (actor != null) {
            UUID actorId = com.platform.user.common.Ids.parse(actor);
            if (actorId == null) {
                throw com.platform.user.common.ApiException.validation("actor", "ID 格式不合法");
            }
            where.append(" AND actor_id = :actor");
            params.put("actor", actorId);
        }
        String result = blank(query.get("result"));
        if (result != null) {
            where.append(" AND result = :result");
            params.put("result", result);
        }
        String resourceType = blank(query.get("resource_type"));
        if (resourceType != null) {
            where.append(" AND resource_type = :rtype");
            params.put("rtype", resourceType);
        }
        String from = blank(query.get("created_from") != null ? query.get("created_from") : query.get("from"));
        if (from != null) {
            where.append(" AND created_at >= :from");
            params.put("from", Times.parse(from, "created_from"));
        }
        String to = blank(query.get("created_to") != null ? query.get("created_to") : query.get("to"));
        if (to != null) {
            where.append(" AND created_at <= :to");
            params.put("to", Times.parse(to, "created_to"));
        }
        long total = db.count("SELECT count(*) FROM user_audit_logs" + where, params);
        Map<String, Object> pageParams = new LinkedHashMap<>(params);
        pageParams.put("limit", pq.limit());
        pageParams.put("offset", pq.offset());
        List<Map<String, Object>> items = db.list("""
                SELECT * FROM user_audit_logs
                """ + where + " ORDER BY created_at DESC, id DESC LIMIT :limit OFFSET :offset", pageParams);
        return (Map<String, Object>) Api.page(items, total, pq.page(), pq.pageSize()).get("data");
    }

    static int intValue(String value, int fallback) {
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            throw com.platform.user.common.ApiException.validation("page", "必须为整数");
        }
    }

    static String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    public List<Map<String, Object>> recent(UUID tenantId, int limit) {
        List<Map<String, Object>> out = new ArrayList<>();
        out.addAll(db.list("""
                SELECT * FROM user_audit_logs WHERE tenant_id = :tenant ORDER BY created_at DESC LIMIT :limit
                """, Db.params("tenant", tenantId, "limit", limit)));
        return out;
    }
}
