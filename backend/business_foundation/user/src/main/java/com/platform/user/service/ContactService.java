package com.platform.user.service;

import com.platform.user.bootstrap.AuthClient;
import com.platform.user.bootstrap.OutboxService;
import com.platform.user.bootstrap.RedisSupport;
import com.platform.user.common.ApiException;
import com.platform.user.common.Body;
import com.platform.user.common.Db;
import com.platform.user.common.Ids;
import com.platform.user.common.Json;
import com.platform.user.common.RequestMeta;
import com.platform.user.common.Text;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class ContactService {
    private final Db db;
    private final AuditService audit;
    private final OutboxService outbox;
    private final AuthClient auth;
    private final RedisSupport redis;
    private final TransactionTemplate tx;

    public ContactService(Db db, AuditService audit, OutboxService outbox, AuthClient auth,
                          RedisSupport redis, TransactionTemplate tx) {
        this.db = db;
        this.audit = audit;
        this.outbox = outbox;
        this.auth = auth;
        this.redis = redis;
        this.tx = tx;
    }

    public static String kindOf(String channel) {
        String value = channel == null ? "" : channel.trim().toLowerCase();
        return switch (value) {
            case "email", "mail" -> "email";
            case "phone", "sms", "tel", "mobile" -> "phone";
            default -> throw ApiException.validation("channel", "仅支持 email 或 phone");
        };
    }

    public static String normalizeValue(String kind, String value) {
        return "email".equals(kind) ? Text.requireEmail(value, "value") : Text.requirePhone(value, "value");
    }

    public List<Map<String, Object>> list(UUID tenantId, UUID userId, boolean mask) {
        List<Map<String, Object>> rows = db.list("""
                SELECT id, kind, value, normalized_value, verified, is_primary, verified_at, created_at, updated_at
                FROM user_contacts WHERE tenant_id = :tenant AND user_id = :user
                ORDER BY is_primary DESC, created_at
                """, Db.params("tenant", tenantId, "user", userId));
        List<Map<String, Object>> out = new ArrayList<>(rows.size());
        for (Map<String, Object> row : rows) {
            out.add(view(row, mask));
        }
        return out;
    }

    public List<Map<String, Object>> listInternal(UUID tenantId, UUID userId) {
        return list(tenantId, userId, false);
    }

    private Map<String, Object> view(Map<String, Object> row, boolean mask) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", row.get("id"));
        String kind = String.valueOf(row.get("kind"));
        String value = row.get("value") == null ? null : String.valueOf(row.get("value"));
        out.put("kind", kind);
        out.put("value", mask ? ("email".equals(kind) ? Text.maskEmail(value) : Text.maskPhone(value)) : value);
        out.put("normalized_value", row.get("normalized_value"));
        out.put("verified", row.get("verified"));
        out.put("is_primary", row.get("is_primary"));
        out.put("verified_at", row.get("verified_at"));
        out.put("created_at", row.get("created_at"));
        out.put("updated_at", row.get("updated_at"));
        return out;
    }

    public Map<String, Object> requestChange(UUID tenantId, UUID userId, Body input, RequestMeta meta) {
        String kind = kindOf(input.str("kind") != null ? input.str("kind") : input.required("channel", "渠道"));
        String normalized = normalizeValue(kind, input.required("value", "联系方式"));
        redis.requireRateLimit("contact:request:" + userId, 5, 600);

        auth.requestContactChange(userId, kind, normalized, tenantId);

        String value = input.trimmed("value");
        Map<String, Object> existing = db.find("""
                SELECT id, user_id, verified FROM user_contacts
                WHERE kind = :kind AND normalized_value = :nv
                """, Db.params("kind", kind, "nv", normalized)).orElse(null);
        if (existing != null && !userId.toString().equals(String.valueOf(existing.get("user_id")))) {
            throw ApiException.conflict("该联系方式已被其他用户使用");
        }
        db.inTx(() -> {
            if (existing != null) {
                db.update("""
                        UPDATE user_contacts SET value = :value, updated_at = now()
                        WHERE id = :id
                        """, Db.params("value", value, "id", existing.get("id")));
            } else {
                boolean primary = db.count("""
                        SELECT count(*) FROM user_contacts
                        WHERE tenant_id = :tenant AND user_id = :user AND kind = :kind AND is_primary = TRUE
                        """, Db.params("tenant", tenantId, "user", userId, "kind", kind)) == 0;
                db.update("""
                        INSERT INTO user_contacts
                            (id, tenant_id, user_id, kind, value, normalized_value, verified, is_primary)
                        VALUES (:id, :tenant, :user, :kind, :value, :nv, FALSE, :primary)
                        """, Db.params("id", Ids.uuidValue(), "tenant", tenantId, "user", userId, "kind", kind,
                        "value", value, "nv", normalized, "primary", primary));
            }
        });
        audit.success(tenantId, userId, "user.contact_request", "user", userId.toString(), meta,
                Map.of("kind", kind, "value", mask(kind, normalized)));
        return Map.of("sent", true, "channel", kind, "pending", true);
    }

    public List<Map<String, Object>> confirmChange(UUID tenantId, UUID userId, Body input, RequestMeta meta) {
        String kind = kindOf(input.str("kind") != null ? input.str("kind") : input.required("channel", "渠道"));
        String normalized = normalizeValue(kind, input.required("value", "联系方式"));
        String code = input.required("code", "验证码");
        auth.confirmContactChange(userId, kind, normalized, code, tenantId);

        tx.executeWithoutResult(status -> {
            Map<String, Object> row = db.find("""
                    SELECT id FROM user_contacts
                    WHERE tenant_id = :tenant AND user_id = :user AND kind = :kind AND normalized_value = :nv
                    """, Db.params("tenant", tenantId, "user", userId, "kind", kind, "nv", normalized)).orElse(null);
            if (row == null) {
                db.update("""
                        INSERT INTO user_contacts
                            (id, tenant_id, user_id, kind, value, normalized_value, verified, is_primary, verified_at)
                        VALUES (:id, :tenant, :user, :kind, :value, :nv, TRUE, TRUE, now())
                        """, Db.params("id", Ids.uuidValue(), "tenant", tenantId, "user", userId, "kind", kind,
                        "value", input.trimmed("value"), "nv", normalized));
            } else {
                db.update("""
                        UPDATE user_contacts SET verified = TRUE, verified_at = now(), updated_at = now()
                        WHERE id = :id
                        """, Db.params("id", row.get("id")));
            }
            db.update("""
                    UPDATE user_contacts SET is_primary = FALSE, updated_at = now()
                    WHERE tenant_id = :tenant AND user_id = :user AND kind = :kind AND normalized_value <> :nv
                    """, Db.params("tenant", tenantId, "user", userId, "kind", kind, "nv", normalized));
            db.update("""
                    UPDATE user_contacts SET is_primary = TRUE, updated_at = now()
                    WHERE tenant_id = :tenant AND user_id = :user AND kind = :kind AND normalized_value = :nv
                    """, Db.params("tenant", tenantId, "user", userId, "kind", kind, "nv", normalized));
            applyPrimaryToUser(tenantId, userId, kind, input.trimmed("value"), true);
        });
        audit.success(tenantId, userId, "user.contact_confirm", "user", userId.toString(), meta,
                Map.of("kind", kind));
        outbox.publish("user.updated", "user", userId.toString(),
                Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "kind", kind));
        return list(tenantId, userId, true);
    }

    public List<Map<String, Object>> unbind(UUID tenantId, UUID userId, String kindRaw, RequestMeta meta) {
        String kind = kindOf(kindRaw);
        auth.clearContact(userId, kind, tenantId);
        deleteKind(tenantId, userId, kind);
        audit.success(tenantId, userId, "user.contact_remove", "user", userId.toString(), meta, Map.of("kind", kind));
        outbox.publish("user.updated", "user", userId.toString(),
                Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "kind", kind));
        return list(tenantId, userId, true);
    }

    public void deleteKind(UUID tenantId, UUID userId, String kind) {
        tx.executeWithoutResult(status -> {
            db.update("""
                    DELETE FROM user_contacts WHERE tenant_id = :tenant AND user_id = :user AND kind = :kind
                    """, Db.params("tenant", tenantId, "user", userId, "kind", kind));
            applyPrimaryToUser(tenantId, userId, kind, null, false);
        });
    }

    public Map<String, Object> adminSet(UUID tenantId, UUID userId, String kindRaw, Body input,
                                         UUID actorId, RequestMeta meta) {
        String kind = kindOf(kindRaw != null ? kindRaw : input.str("kind"));
        String normalized = normalizeValue(kind, input.required("value", "联系方式"));
        String value = input.trimmed("value");
        boolean verified = input.bool("verified", true);
        Boolean requestedPrimary = input.bool("is_primary");

        Map<String, Object> existing = db.find("""
                SELECT id, user_id, is_primary FROM user_contacts
                WHERE kind = :kind AND normalized_value = :nv
                """, Db.params("kind", kind, "nv", normalized)).orElse(null);
        if (existing != null && !userId.toString().equals(String.valueOf(existing.get("user_id")))) {
            throw ApiException.conflict("该联系方式已被其他用户使用");
        }
        boolean hasPrimary = db.count("""
                SELECT count(*) FROM user_contacts
                WHERE tenant_id = :tenant AND user_id = :user AND kind = :kind AND is_primary = TRUE
                """, Db.params("tenant", tenantId, "user", userId, "kind", kind)) > 0;
        boolean primary = requestedPrimary != null ? requestedPrimary : !hasPrimary;

        tx.executeWithoutResult(status -> {
            if (existing != null) {
                db.update("""
                        UPDATE user_contacts
                        SET value = :value, verified = :verified,
                            verified_at = CASE WHEN :verified THEN now() ELSE verified_at END,
                            is_primary = :primary, updated_at = now()
                        WHERE id = :id
                        """, Db.params("value", value, "verified", verified, "primary", primary, "id", existing.get("id")));
            } else {
                db.update("""
                        INSERT INTO user_contacts
                            (id, tenant_id, user_id, kind, value, normalized_value, verified, is_primary, verified_at)
                        VALUES (:id, :tenant, :user, :kind, :value, :nv, :verified, :primary,
                                CASE WHEN :verified THEN now() ELSE NULL END)
                        """, Db.params("id", Ids.uuidValue(), "tenant", tenantId, "user", userId, "kind", kind,
                        "value", value, "nv", normalized, "verified", verified, "primary", primary));
            }
            if (primary) {
                db.update("""
                        UPDATE user_contacts SET is_primary = FALSE, updated_at = now()
                        WHERE tenant_id = :tenant AND user_id = :user AND kind = :kind AND normalized_value <> :nv
                        """, Db.params("tenant", tenantId, "user", userId, "kind", kind, "nv", normalized));
                applyPrimaryToUser(tenantId, userId, kind, value, verified);
            }
        });
        audit.success(tenantId, actorId, "user.contact_set", "user", userId.toString(), meta,
                Map.of("kind", kind, "value", mask(kind, normalized), "verified", verified, "is_primary", primary));
        outbox.publish("user.updated", "user", userId.toString(),
                Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "kind", kind));
        return db.find("""
                SELECT * FROM user_contacts WHERE tenant_id = :tenant AND user_id = :user AND kind = :kind
                ORDER BY is_primary DESC, created_at
                """, Db.params("tenant", tenantId, "user", userId, "kind", kind))
                .map(row -> view(row, false)).orElseGet(LinkedHashMap::new);
    }

    public void adminRemove(UUID tenantId, UUID userId, String kindRaw, UUID actorId, RequestMeta meta) {
        String kind = kindOf(kindRaw);
        deleteKind(tenantId, userId, kind);
        audit.success(tenantId, actorId, "user.contact_remove", "user", userId.toString(), meta, Map.of("kind", kind));
        outbox.publish("user.updated", "user", userId.toString(),
                Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "kind", kind));
    }

    public void replaceFromAuth(UUID tenantId, UUID userId, List<Object> contacts) {
        tx.executeWithoutResult(status -> {
            db.update("DELETE FROM user_contacts WHERE tenant_id = :tenant AND user_id = :user",
                    Db.params("tenant", tenantId, "user", userId));
            for (Object item : contacts) {
                Map<String, Object> contact = Json.readMap(item);
                String kind;
                try {
                    kind = kindOf(contact.get("kind") == null ? null : String.valueOf(contact.get("kind")));
                } catch (ApiException e) {
                    continue;
                }
                Object rawValue = contact.get("value");
                if (rawValue == null) {
                    continue;
                }
                String normalized;
                try {
                    normalized = normalizeValue(kind, String.valueOf(rawValue));
                } catch (ApiException e) {
                    continue;
                }
                boolean verified = Boolean.TRUE.equals(contact.get("verified"))
                        || "true".equalsIgnoreCase(String.valueOf(contact.get("verified")));
                boolean primary = Boolean.TRUE.equals(contact.get("is_primary"))
                        || "true".equalsIgnoreCase(String.valueOf(contact.get("is_primary")));
                Map<String, Object> other = db.find("""
                        SELECT user_id FROM user_contacts WHERE kind = :kind AND normalized_value = :nv
                        """, Db.params("kind", kind, "nv", normalized)).orElse(null);
                if (other != null && !userId.toString().equals(String.valueOf(other.get("user_id")))) {
                    continue;
                }
                db.update("""
                        INSERT INTO user_contacts
                            (id, tenant_id, user_id, kind, value, normalized_value, verified, is_primary, verified_at)
                        VALUES (:id, :tenant, :user, :kind, :value, :nv, :verified, :primary,
                                CASE WHEN :verified THEN now() ELSE NULL END)
                        ON CONFLICT (kind, normalized_value) DO UPDATE
                        SET value = EXCLUDED.value, verified = EXCLUDED.verified,
                            is_primary = EXCLUDED.is_primary, updated_at = now()
                        """, Db.params("id", Ids.uuidValue(), "tenant", tenantId, "user", userId, "kind", kind,
                        "value", String.valueOf(rawValue), "nv", normalized, "verified", verified, "primary", primary));
                if (primary && verified) {
                    applyPrimaryToUser(tenantId, userId, kind, String.valueOf(rawValue), true);
                }
            }
        });
    }

    private void applyPrimaryToUser(UUID tenantId, UUID userId, String kind, String value, boolean verified) {
        if ("email".equals(kind)) {
            db.update("""
                    UPDATE users SET email = :value, email_verified = :verified, updated_at = now(), version = version + 1
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("value", value, "verified", verified, "tenant", tenantId, "id", userId));
        } else {
            db.update("""
                    UPDATE users SET phone = :value, phone_verified = :verified, updated_at = now(), version = version + 1
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("value", value, "verified", verified, "tenant", tenantId, "id", userId));
        }
    }

    private static String mask(String kind, String value) {
        return "email".equals(kind) ? Text.maskEmail(value) : Text.maskPhone(value);
    }
}
