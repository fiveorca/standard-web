package com.platform.user.service;

import com.platform.user.bootstrap.OutboxService;
import com.platform.user.bootstrap.RedisSupport;
import com.platform.user.common.ApiException;
import com.platform.user.common.Body;
import com.platform.user.common.Db;
import com.platform.user.common.Ids;
import com.platform.user.common.Json;
import com.platform.user.common.PageQuery;
import com.platform.user.common.RequestMeta;
import com.platform.user.common.Text;
import com.platform.user.common.Times;
import com.platform.user.config.AppProperties;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class RegistrationService {
    private final Db db;
    private final AuditService audit;
    private final OutboxService outbox;
    private final UserService users;
    private final RedisSupport redis;
    private final AppProperties props;
    private final TransactionTemplate tx;

    public RegistrationService(Db db, AuditService audit, OutboxService outbox, UserService users,
                               RedisSupport redis, AppProperties props, TransactionTemplate tx) {
        this.db = db;
        this.audit = audit;
        this.outbox = outbox;
        this.users = users;
        this.redis = redis;
        this.props = props;
        this.tx = tx;
    }

    public Map<String, Object> register(Body input, RequestMeta meta) {
        if (!props.getRegistration().isEnabled()) {
            throw new ApiException(403, "registration_disabled", "注册通道已关闭");
        }
        String ip = meta == null || meta.ip() == null ? "unknown" : meta.ip();
        redis.requireRateLimit("registration:" + ip, props.getRegistration().getRateLimitPerMinute(), 60);

        UUID tenantId = input.uuid("tenant_id");
        if (tenantId == null) {
            tenantId = Ids.parse(props.getRegistration().getDefaultTenantId());
        }
        if (tenantId == null) {
            throw ApiException.validation("tenant_id", "租户配置不合法");
        }
        String username = Text.requireUsername(input.str("username"), "username");
        String email = input.str("email") == null ? null : Text.requireEmail(input.str("email"), "email");
        String phone = input.str("phone") == null ? null : Text.requirePhone(input.str("phone"), "phone");
        String source = input.str("source", "web");
        String channel = input.trimmed("channel");
        String campaign = input.trimmed("campaign");
        String inviteCode = input.trimmed("invite_code");
        Map<String, Object> payload = input.map("payload");
        if (input.has("display_name")) {
            payload.put("display_name", input.trimmed("display_name"));
        }

        if (db.count("""
                SELECT count(*) FROM users
                WHERE tenant_id = :tenant AND lower(username) = lower(:username) AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "username", username)) > 0) {
            throw ApiException.conflict("用户名已存在");
        }
        if (email != null && db.count("""
                SELECT count(*) FROM users WHERE lower(email) = lower(:email) AND deleted_at IS NULL
                """, Db.params("email", email)) > 0) {
            throw ApiException.conflict("邮箱已被使用");
        }
        if (phone != null && db.count("""
                SELECT count(*) FROM users WHERE phone = :phone AND deleted_at IS NULL
                """, Db.params("phone", phone)) > 0) {
            throw ApiException.conflict("手机号已被使用");
        }
        if (db.count("""
                SELECT count(*) FROM user_registration_records
                WHERE tenant_id = :tenant AND status = 'pending'
                  AND (lower(username) = lower(:username) OR (:email IS NOT NULL AND lower(email) = lower(:email)))
                """, Db.params("tenant", tenantId, "username", username, "email", email)) > 0) {
            throw ApiException.conflict("已有待审核的注册申请");
        }

        UUID id = Ids.uuidValue();
        db.update("""
                INSERT INTO user_registration_records
                    (id, tenant_id, username, email, phone, source, channel, campaign, invite_code, status, payload)
                VALUES
                    (:id, :tenant, :username, :email, :phone, :source, :channel, :campaign, :invite, 'pending', :payload)
                """, Db.params("id", id, "tenant", tenantId, "username", username, "email", email, "phone", phone,
                "source", source, "channel", channel, "campaign", campaign, "invite", inviteCode,
                "payload", Json.jsonb(payload)));
        audit.record(tenantId, null, "registration.submit", "registration", id.toString(), "success", meta,
                Map.of("username", username, "source", source));
        if (!props.getRegistration().isRequireReview()) {
            Map<String, Object> reviewed = review(tenantId, id, Body.of(Map.of("approve", true, "reason", "auto approve")),
                    null, meta, "system");
            return Map.of("id", id.toString(), "status", reviewed.get("status"),
                    "user_id", reviewed.get("user_id") == null ? "" : reviewed.get("user_id"),
                    "requires_review", false);
        }
        return Map.of("id", id.toString(), "status", "pending", "requires_review", true);
    }

    public Map<String, Object> list(UUID tenantId, Map<String, String> query) {
        PageQuery page = PageQuery.parse(query.get("page"), query.get("page_size"));
        StringBuilder where = new StringBuilder(" WHERE tenant_id = :tenant");
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("tenant", tenantId);
        String status = blank(query.get("status"));
        if (status != null) {
            where.append(" AND status = :status");
            params.put("status", status);
        }
        String source = blank(query.get("source"));
        if (source != null) {
            where.append(" AND source = :source");
            params.put("source", source);
        }
        String keyword = blank(query.get("keyword"));
        if (keyword != null) {
            where.append(" AND (username ILIKE :kw ESCAPE '\\' OR email ILIKE :kw ESCAPE '\\'"
                    + " OR phone ILIKE :kw ESCAPE '\\')");
            params.put("kw", Text.likePattern(keyword));
        }
        String from = blank(query.get("created_from"));
        if (from != null) {
            where.append(" AND created_at >= :from");
            params.put("from", Times.parse(from, "created_from"));
        }
        String to = blank(query.get("created_to"));
        if (to != null) {
            where.append(" AND created_at <= :to");
            params.put("to", Times.parse(to, "created_to"));
        }
        long total = db.count("SELECT count(*) FROM user_registration_records" + where, params);
        Map<String, Object> pageParams = new LinkedHashMap<>(params);
        pageParams.put("limit", page.limit());
        pageParams.put("offset", page.offset());
        List<Map<String, Object>> items = db.list("SELECT * FROM user_registration_records" + where
                + " ORDER BY created_at DESC LIMIT :limit OFFSET :offset", pageParams);
        return Db.page(items, total, page.page(), page.pageSize());
    }

    public Map<String, Object> get(UUID tenantId, UUID id) {
        return db.one("""
                SELECT * FROM user_registration_records WHERE tenant_id = :tenant AND id = :id
                """, Db.params("tenant", tenantId, "id", id));
    }

    public Map<String, Object> review(UUID tenantId, UUID id, Body input, UUID actorId, RequestMeta meta) {
        return review(tenantId, id, input, actorId, meta, null);
    }

    private Map<String, Object> review(UUID tenantId, UUID id, Body input, UUID actorId, RequestMeta meta,
                                       String actorLabel) {
        Map<String, Object> record = get(tenantId, id);
        String currentStatus = String.valueOf(record.get("status"));
        if (!"pending".equals(currentStatus)) {
            throw ApiException.conflict("该申请已处理，当前状态: " + currentStatus);
        }
        boolean approve = input.bool("approve", true);
        String reason = input.trimmed("reason");
        String username = String.valueOf(record.get("username"));
        String email = record.get("email") == null ? null : String.valueOf(record.get("email"));
        String phone = record.get("phone") == null ? null : String.valueOf(record.get("phone"));

        if (!approve) {
            db.update("""
                    UPDATE user_registration_records
                    SET status = 'rejected', reviewer_id = :reviewer, reviewed_at = now(),
                        reject_reason = :reason, updated_at = now()
                    WHERE tenant_id = :tenant AND id = :id AND status = 'pending'
                    """, Db.params("reviewer", actorId, "reason", reason, "tenant", tenantId, "id", id));
            audit.success(tenantId, actorId, "registration.review", "registration", id.toString(), meta,
                    Map.of("decision", "reject", "reason", reason == null ? "" : reason));
            outbox.publish("user.registration_reviewed", "registration", id.toString(), Map.of(
                    "registration_id", id.toString(),
                    "tenant_id", tenantId.toString(),
                    "decision", "reject",
                    "reason", reason == null ? "" : reason));
            return get(tenantId, id);
        }

        UUID userId = tx.execute(status -> {
            UUID existing = Ids.parse(str(record.get("user_id")));
            if (existing == null) {
                Map<String, Object> user = db.find("""
                        SELECT id FROM users
                        WHERE tenant_id = :tenant AND deleted_at IS NULL AND lower(username) = lower(:username)
                        """, Db.params("tenant", tenantId, "username", username)).orElse(null);
                if (user != null) {
                    existing = Ids.parse(str(user.get("id")));
                }
            }
            if (existing == null && email != null) {
                Map<String, Object> user = db.find("""
                        SELECT id FROM users WHERE lower(email) = lower(:email) AND deleted_at IS NULL
                        """, Db.params("email", email)).orElse(null);
                if (user != null) {
                    existing = Ids.parse(str(user.get("id")));
                }
            }
            if (existing == null && phone != null) {
                Map<String, Object> user = db.find("""
                        SELECT id FROM users WHERE phone = :phone AND deleted_at IS NULL
                        """, Db.params("phone", phone)).orElse(null);
                if (user != null) {
                    existing = Ids.parse(str(user.get("id")));
                }
            }
            if (existing == null) {
                Map<String, Object> payload = Json.readMap(record.get("payload"));
                Map<String, Object> created = new LinkedHashMap<>();
                created.put("tenant_id", tenantId);
                created.put("username", username);
                created.put("email", email);
                created.put("phone", phone);
                created.put("display_name", payload.get("display_name"));
                created.put("status", "active");
                created.put("source", record.get("source") == null ? "registration" : record.get("source"));
                created.put("remark", "registration:" + id);
                if (payload.get("tags") instanceof List<?>) {
                    created.put("tags", payload.get("tags"));
                }
                Map<String, Object> user = users.createFromRegistration(tenantId, Body.of(created), actorId, meta);
                existing = Ids.parse(str(user.get("id")));
            }
            db.update("""
                    UPDATE user_registration_records
                    SET status = 'approved', user_id = :user, reviewer_id = :reviewer, reviewed_at = now(),
                        reject_reason = NULL, updated_at = now()
                    WHERE tenant_id = :tenant AND id = :id AND status = 'pending'
                    """, Db.params("user", existing, "reviewer", actorId, "tenant", tenantId, "id", id));
            return existing;
        });

        if (userId == null) {
            throw ApiException.conflict("注册申请关联用户失败");
        }
        audit.success(tenantId, actorId, "registration.review", "registration", id.toString(), meta,
                Map.of("decision", "approve", "user_id", userId.toString(),
                        "actor", actorLabel == null ? "" : actorLabel));
        outbox.publish("user.registered", "user", userId.toString(), Map.of(
                "identity_id", userId.toString(),
                "tenant_id", tenantId.toString(),
                "registration_id", id.toString(),
                "username", username,
                "email", email == null ? "" : email,
                "phone", phone == null ? "" : phone));
        outbox.publish("user.registration_reviewed", "registration", id.toString(), Map.of(
                "registration_id", id.toString(),
                "tenant_id", tenantId.toString(),
                "user_id", userId.toString(),
                "decision", "approve"));
        return get(tenantId, id);
    }

    public Map<String, Object> userRegistration(UUID tenantId, UUID userId) {
        return db.find("""
                SELECT * FROM user_registration_records
                WHERE tenant_id = :tenant AND user_id = :user ORDER BY created_at DESC LIMIT 1
                """, Db.params("tenant", tenantId, "user", userId)).orElseGet(LinkedHashMap::new);
    }

    private static String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
