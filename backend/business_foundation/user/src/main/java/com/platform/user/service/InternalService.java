package com.platform.user.service;

import com.platform.user.common.ApiException;
import com.platform.user.common.Body;
import com.platform.user.common.Db;
import com.platform.user.common.Ids;
import com.platform.user.common.Json;
import com.platform.user.common.RequestMeta;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class InternalService {
    private static final Logger log = LoggerFactory.getLogger(InternalService.class);
    public static final String CONSUMER = "user-center";

    private final Db db;
    private final UserService users;
    private final ContactService contacts;

    public InternalService(Db db, UserService users, ContactService contacts) {
        this.db = db;
        this.users = users;
        this.contacts = contacts;
    }

    public Map<String, Object> ensure(UUID tenantId, Body input, RequestMeta meta) {
        return users.ensureInternal(tenantId, input, meta);
    }

    public Map<String, Object> user(UUID tenantId, UUID userId) {
        UUID resolved = tenantId == null ? tenantOf(userId) : tenantId;
        if (resolved == null) {
            throw ApiException.notFound("用户不存在");
        }
        return users.internalUser(resolved, userId);
    }

    public Map<String, Object> updateStatus(UUID tenantId, UUID userId, Body input, RequestMeta meta) {
        UUID resolved = tenantId == null ? tenantOf(userId) : tenantId;
        if (resolved == null) {
            throw ApiException.notFound("用户不存在");
        }
        return users.internalStatus(resolved, userId, input, meta);
    }

    public List<Map<String, Object>> contactsInternal(UUID tenantId, UUID userId) {
        UUID resolved = tenantId == null ? tenantOf(userId) : tenantId;
        if (resolved == null) {
            throw ApiException.notFound("用户不存在");
        }
        return contacts.listInternal(resolved, userId);
    }

    private UUID tenantOf(UUID userId) {
        return db.find("SELECT tenant_id FROM users WHERE id = :id", Db.params("id", userId))
                .map(row -> Ids.parse(str(row.get("tenant_id")))).orElse(null);
    }

    public Map<String, Object> receiveEvent(Map<String, Object> envelope) {
        UUID eventId = Ids.parse(str(envelope.get("event_id")));
        if (eventId == null) {
            throw ApiException.validation("event_id", "event_id 不能为空");
        }
        String eventType = str(envelope.get("event_type"));
        if (eventType == null || eventType.isBlank()) {
            throw ApiException.validation("event_type", "event_type 不能为空");
        }
        Map<String, Object> payload = Json.readMap(envelope.get("payload"));
        int claimed = db.update("""
                INSERT INTO inbox_events (event_id, consumer, event_type, aggregate_id, payload, status)
                VALUES (:event, :consumer, :type, :aggregate, :payload, 'failed')
                ON CONFLICT (event_id, consumer) DO UPDATE
                SET event_type = EXCLUDED.event_type, aggregate_id = EXCLUDED.aggregate_id,
                    payload = EXCLUDED.payload, error = NULL, status = 'failed'
                WHERE inbox_events.status = 'failed'
                """, Db.params("event", eventId, "consumer", CONSUMER, "type", eventType,
                "aggregate", str(envelope.get("aggregate_id")),
                "payload", Json.jsonb(payload)));
        if (claimed == 0) {
            return Map.of("duplicate", true, "event_id", eventId.toString(), "status", "processed");
        }
        try {
            process(eventType, payload, envelope);
            db.update("""
                    UPDATE inbox_events SET status = 'processed', processed_at = now(), error = NULL
                    WHERE event_id = :event AND consumer = :consumer
                    """, Db.params("event", eventId, "consumer", CONSUMER));
            return Map.of("duplicate", false, "event_id", eventId.toString(), "status", "processed");
        } catch (Exception e) {
            db.update("""
                    UPDATE inbox_events SET status = 'failed', error = :error
                    WHERE event_id = :event AND consumer = :consumer
                    """, Db.params("event", eventId, "consumer", CONSUMER,
                    "error", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage()));
            log.warn("处理事件 {} 失败: {}", eventType, e.getMessage());
            throw new ApiException(500, "event_processing_failed", "事件处理失败");
        }
    }

    private void process(String rawType, Map<String, Object> payload, Map<String, Object> envelope) {
        String type = rawType.startsWith("auth.") ? rawType.substring(5) : rawType;
        UUID identityId = Ids.parse(first(payload, "identity_id", "user_id", "id"));
        if (identityId == null) {
            identityId = Ids.parse(str(envelope.get("aggregate_id")));
        }
        if (identityId == null) {
            throw ApiException.validation("identity_id", "事件缺少 identity_id");
        }
        UUID tenantId = resolveTenant(payload, identityId);
        switch (type) {
            case "identity.registered", "identity.created" -> {
                if (tenantId == null) {
                    throw ApiException.validation("tenant_id", "事件缺少 tenant_id");
                }
                Map<String, Object> body = new LinkedHashMap<>(payload);
                body.put("identity_id", identityId);
                body.put("tenant_id", tenantId);
                body.putIfAbsent("status", "active");
                body.putIfAbsent("source", "auth");
                users.ensureInternal(tenantId, Body.of(body), null);
            }
            case "identity.status_changed", "identity.activated", "identity.disabled",
                    "identity.locked", "identity.deleted", "identity.suspended" -> {
                if (tenantId == null) {
                    return;
                }
                String status = mapStatus(type, payload);
                if (status != null) {
                    users.applyExternalStatus(tenantId, identityId, status, str(payload.get("reason")));
                }
            }
            case "identity.contacts_changed", "identity.contact_changed" -> {
                if (tenantId == null) {
                    return;
                }
                List<Object> list;
                if (payload.get("contacts") instanceof List<?>) {
                    list = Json.readList(Json.write(payload.get("contacts")));
                } else {
                    list = new java.util.ArrayList<>();
                    if (first(payload, "email") != null) {
                        list.add(Map.of("kind", "email", "value", first(payload, "email"),
                                "verified", payload.getOrDefault("email_verified", false), "is_primary", true));
                    }
                    if (first(payload, "phone") != null) {
                        list.add(Map.of("kind", "phone", "value", first(payload, "phone"),
                                "verified", payload.getOrDefault("phone_verified", false), "is_primary", true));
                    }
                }
                contacts.replaceFromAuth(tenantId, identityId, list);
            }
            case "identity.updated" -> {
                if (tenantId == null) {
                    return;
                }
                Map<String, Object> fields = new LinkedHashMap<>();
                if (payload.get("display_name") != null) {
                    fields.put("display_name", payload.get("display_name"));
                }
                if (payload.get("avatar_url") != null) {
                    fields.put("avatar_url", payload.get("avatar_url"));
                }
                if (!fields.isEmpty()) {
                    try {
                        users.update(tenantId, identityId, Body.of(fields), null, null, null);
                    } catch (ApiException e) {
                        log.debug("identity.updated 同步跳过 {}: {}", identityId, e.getMessage());
                    }
                }
            }
            default -> log.debug("忽略未知事件类型: {}", rawType);
        }
    }

    private UUID resolveTenant(Map<String, Object> payload, UUID identityId) {
        UUID tenantId = Ids.parse(first(payload, "tenant_id", "tenantId"));
        if (tenantId != null) {
            return tenantId;
        }
        Map<String, Object> row = db.find("""
                SELECT tenant_id FROM users WHERE id = :id
                """, Db.params("id", identityId)).orElse(null);
        return row == null ? null : Ids.parse(str(row.get("tenant_id")));
    }

    private static String mapStatus(String type, Map<String, Object> payload) {
        return switch (type) {
            case "identity.activated" -> "active";
            case "identity.disabled" -> "disabled";
            case "identity.locked" -> "locked";
            case "identity.deleted" -> "deleted";
            default -> {
                String status = first(payload, "to_status", "status", "new_status");
                if (status == null) {
                    String change = first(payload, "status_change", "to");
                    yield change;
                }
                yield status;
            }
        };
    }

    private static String first(Map<String, Object> map, String... keys) {
        for (String key : keys) {
            Object value = map.get(key);
            if (value != null && !String.valueOf(value).isBlank()) {
                return String.valueOf(value);
            }
        }
        return null;
    }

    private static String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
