package com.platform.user.service;

import com.platform.user.bootstrap.AuthClient;
import com.platform.user.bootstrap.OutboxService;
import com.platform.user.common.ApiException;
import com.platform.user.common.AuthContext;
import com.platform.user.common.Body;
import com.platform.user.common.Db;
import com.platform.user.common.Ids;
import com.platform.user.common.Json;
import com.platform.user.common.PageQuery;
import com.platform.user.common.RequestMeta;
import com.platform.user.common.StatusMachine;
import com.platform.user.common.Text;
import com.platform.user.common.Times;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.sql.Date;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

@Service
public class UserService {
    private static final Logger log = LoggerFactory.getLogger(UserService.class);

    private static final Map<String, String> SORTS = Map.of(
            "created_at_desc", "u.created_at DESC",
            "created_at_asc", "u.created_at ASC",
            "updated_at_desc", "u.updated_at DESC",
            "registered_at_desc", "u.registered_at DESC",
            "last_login_desc", "u.last_login_at DESC NULLS LAST",
            "username_asc", "u.username ASC",
            "username_desc", "u.username DESC");

    private final Db db;
    private final AuditService audit;
    private final OutboxService outbox;
    private final AuthClient auth;
    private final ContactService contacts;
    private final AttributeService attributes;
    private final GroupService groups;
    private final OrgService orgs;
    private final TransactionTemplate tx;

    public UserService(Db db, AuditService audit, OutboxService outbox, AuthClient auth,
                       ContactService contacts, AttributeService attributes, GroupService groups,
                       OrgService orgs, TransactionTemplate tx) {
        this.db = db;
        this.audit = audit;
        this.outbox = outbox;
        this.auth = auth;
        this.contacts = contacts;
        this.attributes = attributes;
        this.groups = groups;
        this.orgs = orgs;
        this.tx = tx;
    }

    // ───────────────────────── 自助 ─────────────────────────

    public Map<String, Object> ensureFromContext(AuthContext ctx, RequestMeta meta) {
        Map<String, Object> existing = db.find("""
                SELECT id FROM users WHERE id = :id AND tenant_id = :tenant AND deleted_at IS NULL
                """, Db.params("id", ctx.identityId(), "tenant", ctx.tenantId())).orElse(null);
        if (existing != null) {
            return detail(ctx.tenantId(), ctx.identityId(), true);
        }
        Map<String, Object> identity = auth.getIdentity(ctx.identityId().toString());
        Map<String, Object> input = new LinkedHashMap<>(identity);
        input.put("id", ctx.identityId());
        Object username = input.get("username");
        if (username == null || String.valueOf(username).isBlank()) {
            input.put("username", "user_" + ctx.identityId().toString().substring(0, 8));
        }
        input.putIfAbsent("display_name", input.get("nickname"));
        String status = input.get("status") == null ? "active" : String.valueOf(input.get("status"));
        if (!StatusMachine.STATUSES.contains(status) || "deleted".equals(status)) {
            status = "active";
        }
        input.put("status", status);
        input.put("source", input.get("source") == null ? "sso" : input.get("source"));
        try {
            create(ctx.tenantId(), Body.of(input), ctx.identityId(), meta);
        } catch (ApiException e) {
            if (e.status() != 409) {
                throw e;
            }
            // 并发首次访问时另一个请求已创建，重新读取。
        }
        return detail(ctx.tenantId(), ctx.identityId(), true);
    }

    public Map<String, Object> detail(UUID tenantId, UUID userId, boolean maskContacts) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("user", view(tenantId, userId));
        out.put("contacts", contacts.list(tenantId, userId, maskContacts));
        out.put("groups", groups.userGroups(tenantId, userId));
        out.put("memberships", orgs.memberships(tenantId, userId));
        out.put("attributes", attributes.listValues(tenantId, userId));
        return out;
    }

    public Map<String, Object> view(UUID tenantId, UUID userId) {
        Map<String, Object> row = db.one("""
                SELECT u.*, p.gender, p.birthday, p.bio, p.region, p.timezone, p.locale,
                       p.website, p.company, p.job_title, p.extra AS profile_extra, p.completeness
                FROM users u
                LEFT JOIN user_profiles p ON p.user_id = u.id
                WHERE u.tenant_id = :tenant AND u.id = :id
                """, Db.params("tenant", tenantId, "id", userId));
        List<Map<String, Object>> tagRows = db.list("""
                SELECT tag FROM user_tags WHERE tenant_id = :tenant AND user_id = :user ORDER BY tag
                """, Db.params("tenant", tenantId, "user", userId));
        row.put("tags", tagRows.stream().map(t -> t.get("tag")).toList());
        return row;
    }

    public Map<String, Object> profile(UUID tenantId, UUID userId) {
        requireActiveUser(tenantId, userId);
        Map<String, Object> row = db.find("""
                SELECT * FROM user_profiles WHERE user_id = :user
                """, Db.params("user", userId)).orElse(null);
        if (row == null) {
            db.update("INSERT INTO user_profiles (user_id) VALUES (:user) ON CONFLICT DO NOTHING",
                    Db.params("user", userId));
            row = db.one("SELECT * FROM user_profiles WHERE user_id = :user", Db.params("user", userId));
        }
        return row;
    }

    public Map<String, Object> updateProfile(UUID tenantId, UUID userId, Body input, UUID actorId, RequestMeta meta) {
        requireActiveUser(tenantId, userId);
        Map<String, Object> existing = db.find("SELECT * FROM user_profiles WHERE user_id = :user",
                Db.params("user", userId)).orElse(Map.of());
        String gender = input.has("gender") ? blank(input.str("gender"))
                : existing.get("gender") == null ? null : String.valueOf(existing.get("gender"));
        if (gender != null && !List.of("male", "female", "other", "undisclosed").contains(gender)) {
            throw ApiException.validation("gender", "性别取值不合法");
        }
        LocalDate birthday = input.has("birthday")
                ? parseDate(input.str("birthday"), "birthday")
                : existing.get("birthday") == null ? null : parseDate(String.valueOf(existing.get("birthday")), "birthday");
        Map<String, Object> extra = Json.readMap(existing.get("extra"));
        if (input.has("extra")) {
            extra.putAll(input.map("extra"));
        }
        String bio = input.has("bio") ? blank(input.str("bio")) : str(existing.get("bio"));
        String region = input.has("region") ? blank(input.str("region")) : str(existing.get("region"));
        String timezone = input.has("timezone") ? blank(input.str("timezone")) : str(existing.get("timezone"));
        String locale = input.has("locale") ? blank(input.str("locale")) : str(existing.get("locale"));
        String website = input.has("website") ? blank(input.str("website")) : str(existing.get("website"));
        String company = input.has("company") ? blank(input.str("company")) : str(existing.get("company"));
        String jobTitle = input.has("job_title") ? blank(input.str("job_title")) : str(existing.get("job_title"));
        int completeness = completeness(gender, birthday, bio, region, timezone, locale, website, company, jobTitle);
        db.update("""
                INSERT INTO user_profiles
                    (user_id, gender, birthday, bio, region, timezone, locale, website, company, job_title,
                     extra, completeness)
                VALUES
                    (:user, :gender, :birthday, :bio, :region, :timezone, :locale, :website, :company, :job,
                     :extra, :completeness)
                ON CONFLICT (user_id) DO UPDATE
                SET gender = EXCLUDED.gender, birthday = EXCLUDED.birthday, bio = EXCLUDED.bio,
                    region = EXCLUDED.region, timezone = EXCLUDED.timezone, locale = EXCLUDED.locale,
                    website = EXCLUDED.website, company = EXCLUDED.company, job_title = EXCLUDED.job_title,
                    extra = EXCLUDED.extra, completeness = EXCLUDED.completeness, updated_at = now()
                """, Db.params("user", userId, "gender", gender,
                "birthday", birthday == null ? null : Date.valueOf(birthday), "bio", bio,
                "region", region, "timezone", timezone, "locale", locale, "website", website,
                "company", company, "job", jobTitle, "extra", Json.jsonb(extra), "completeness", completeness));
        audit.success(tenantId, actorId, "user.profile_update", "user", userId.toString(), meta, Map.of());
        outbox.publish("user.updated", "user", userId.toString(),
                Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "fields", List.of("profile")));
        syncProfileBestEffort(userId, Map.of("display_name", view(tenantId, userId).get("display_name"),
                "profile", Map.of("bio", bio == null ? "" : bio, "company", company == null ? "" : company)));
        return profile(tenantId, userId);
    }

    // ───────────────────────── 管理端 CRUD ─────────────────────────

    public Map<String, Object> create(UUID tenantId, Body input, UUID actorId, RequestMeta meta) {
        Map<String, Object> created = createInternal(tenantId, input, actorId, meta, null);
        return created;
    }

    public Map<String, Object> createFromRegistration(UUID tenantId, Body input, UUID actorId, RequestMeta meta) {
        input.map().putIfAbsent("status", "active");
        input.map().putIfAbsent("source", "registration");
        return createInternal(tenantId, input, actorId, meta, "registration");
    }

    private Map<String, Object> createInternal(UUID tenantId, Body input, UUID actorId, RequestMeta meta, String sourceOverride) {
        UUID id = input.uuid("id");
        if (id == null) {
            id = Ids.uuidValue();
        } else if (db.count("SELECT count(*) FROM users WHERE id = :id", Db.params("id", id)) > 0) {
            throw ApiException.conflict("用户 ID 已存在");
        }
        String username = Text.requireUsername(input.str("username"), "username");
        String email = input.str("email") == null ? null : Text.requireEmail(input.str("email"), "email");
        String phone = input.str("phone") == null ? null : Text.requirePhone(input.str("phone"), "phone");
        String status = input.str("status", "pending");
        StatusMachine.validateTarget(status);
        String source = sourceOverride != null ? sourceOverride : input.str("source", "admin");
        String displayName = input.trimmed("display_name");
        String avatarUrl = input.trimmed("avatar_url");
        String remark = input.trimmed("remark");
        boolean emailVerified = input.bool("email_verified", false);
        boolean phoneVerified = input.bool("phone_verified", false);
        String password = input.str("password");
        List<Object> rawTags = input.list("tags");
        List<String> tags = normalizeTags(rawTags.stream().map(String::valueOf).toList());
        Map<String, Object> profileInput = input.map("profile");

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

        final UUID userId = id;
        tx.executeWithoutResult(txStatus -> {
            db.update("""
                    INSERT INTO users
                        (id, tenant_id, username, email, email_verified, phone, phone_verified, display_name,
                         avatar_url, status, source, remark, registered_at)
                    VALUES
                        (:id, :tenant, :username, :email, :email_verified, :phone, :phone_verified, :display,
                         :avatar, :status, :source, :remark, now())
                    """, Db.params("id", userId, "tenant", tenantId, "username", username, "email", email,
                    "email_verified", emailVerified, "phone", phone, "phone_verified", phoneVerified,
                    "display", displayName, "avatar", avatarUrl, "status", status, "source", source,
                    "remark", remark));
            db.update("""
                    INSERT INTO user_profiles (user_id, gender, birthday, bio, region, timezone, locale,
                                               website, company, job_title, extra)
                    VALUES (:user, :gender, :birthday, :bio, :region, :timezone, :locale, :website,
                            :company, :job, :extra)
                    ON CONFLICT DO NOTHING
                    """, Db.params("user", userId,
                    "gender", blank(str(profileInput.get("gender"))),
                    "birthday", parseDate(str(profileInput.get("birthday")), "birthday"),
                    "bio", blank(str(profileInput.get("bio"))),
                    "region", blank(str(profileInput.get("region"))),
                    "timezone", blank(str(profileInput.get("timezone"))),
                    "locale", blank(str(profileInput.get("locale"))),
                    "website", blank(str(profileInput.get("website"))),
                    "company", blank(str(profileInput.get("company"))),
                    "job", blank(str(profileInput.get("job_title"))),
                    "extra", Json.jsonb(profileInput.get("extra") == null ? Map.of() : profileInput.get("extra"))));
            if (email != null) {
                insertContact(tenantId, userId, "email", email, emailVerified, true);
            }
            if (phone != null) {
                insertContact(tenantId, userId, "phone", phone, phoneVerified, true);
            }
            for (String tag : tags) {
                db.update("""
                        INSERT INTO user_tags (id, tenant_id, user_id, tag)
                        VALUES (:id, :tenant, :user, :tag) ON CONFLICT DO NOTHING
                        """, Db.params("id", Ids.uuidValue(), "tenant", tenantId, "user", userId, "tag", tag));
            }
        });

        audit.success(tenantId, actorId, "user.create", "user", userId.toString(), meta,
                Map.of("username", username, "source", source));
        outbox.publish("user.created", "user", userId.toString(), Map.of(
                "identity_id", userId.toString(),
                "tenant_id", tenantId.toString(),
                "username", username,
                "email", email == null ? "" : email,
                "phone", phone == null ? "" : phone,
                "status", status));
        if (password != null && !password.isBlank()) {
            try {
                auth.ensureIdentity(Map.of(
                        "identity_id", userId.toString(),
                        "tenant_id", tenantId.toString(),
                        "username", username,
                        "email", email == null ? "" : email,
                        "phone", phone == null ? "" : phone,
                        "password", password,
                        "display_name", displayName == null ? "" : displayName));
            } catch (Exception e) {
                log.warn("同步认证中心身份失败 {}: {}", userId, e.getMessage());
            }
        }
        return view(tenantId, userId);
    }

    private void insertContact(UUID tenantId, UUID userId, String kind, String value, boolean verified, boolean primary) {
        String normalized = "email".equals(kind) ? Text.normalizeEmail(value) : Text.normalizePhone(value);
        db.update("""
                DELETE FROM user_contacts
                WHERE kind = :kind AND normalized_value = :nv
                  AND user_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL)
                """, Db.params("kind", kind, "nv", normalized));
        Map<String, Object> owner = db.find("""
                SELECT user_id FROM user_contacts WHERE kind = :kind AND normalized_value = :nv
                """, Db.params("kind", kind, "nv", normalized)).orElse(null);
        if (owner != null && !userId.toString().equals(String.valueOf(owner.get("user_id")))) {
            throw ApiException.conflict("联系方式已被其他用户使用");
        }
        if (owner != null) {
            db.update("""
                    UPDATE user_contacts SET value = :value, verified = :verified, is_primary = :primary,
                        verified_at = CASE WHEN :verified THEN now() ELSE verified_at END, updated_at = now()
                    WHERE kind = :kind AND normalized_value = :nv
                    """, Db.params("value", value, "verified", verified, "primary", primary,
                    "kind", kind, "nv", normalized));
        } else {
            db.update("""
                    INSERT INTO user_contacts
                        (id, tenant_id, user_id, kind, value, normalized_value, verified, is_primary, verified_at)
                    VALUES (:id, :tenant, :user, :kind, :value, :nv, :verified, :primary,
                            CASE WHEN :verified THEN now() ELSE NULL END)
                    """, Db.params("id", Ids.uuidValue(), "tenant", tenantId, "user", userId, "kind", kind,
                    "value", value, "nv", normalized, "verified", verified, "primary", primary));
        }
    }

    public Map<String, Object> list(UUID tenantId, Map<String, String> query) {
        PageQuery page = PageQuery.parse(query.get("page"), query.get("page_size"));
        Filter filter = filter(tenantId, query);
        long total = db.count("SELECT count(*) FROM users u" + filter.where, filter.params);
        Map<String, Object> params = new LinkedHashMap<>(filter.params);
        params.put("limit", page.limit());
        params.put("offset", page.offset());
        String sort = SORTS.getOrDefault(blank(query.get("sort")), SORTS.get("created_at_desc"));
        List<Map<String, Object>> items = db.list("""
                SELECT u.*, p.completeness
                FROM users u LEFT JOIN user_profiles p ON p.user_id = u.id
                """ + filter.where + " ORDER BY " + sort + " LIMIT :limit OFFSET :offset", params);
        attachTags(items);
        return Db.page(items, total, page.page(), page.pageSize());
    }

    private Filter filter(UUID tenantId, Map<String, String> query) {
        StringBuilder where = new StringBuilder(" WHERE u.tenant_id = :tenant");
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("tenant", tenantId);
        boolean includeDeleted = "true".equalsIgnoreCase(query.get("include_deleted"));
        if (!includeDeleted) {
            where.append(" AND u.deleted_at IS NULL");
        }
        String status = blank(query.get("status"));
        if (status != null) {
            where.append(" AND u.status = :status");
            params.put("status", status);
        }
        String source = blank(query.get("source"));
        if (source != null) {
            where.append(" AND u.source = :source");
            params.put("source", source);
        }
        String keyword = blank(query.get("keyword"));
        if (keyword != null) {
            where.append(" AND (u.username ILIKE :kw ESCAPE '\\' OR u.email ILIKE :kw ESCAPE '\\'"
                    + " OR u.phone ILIKE :kw ESCAPE '\\' OR u.display_name ILIKE :kw ESCAPE '\\')");
            params.put("kw", Text.likePattern(keyword));
        }
        String tag = blank(query.get("tag"));
        if (tag != null) {
            where.append(" AND EXISTS (SELECT 1 FROM user_tags t WHERE t.user_id = u.id AND t.tag = :tag)");
            params.put("tag", tag);
        }
        String groupId = blank(query.get("group_id"));
        if (groupId != null) {
            where.append(" AND EXISTS (SELECT 1 FROM user_group_members gm WHERE gm.user_id = u.id AND gm.group_id = :group)");
            params.put("group", Ids.parse(groupId));
        }
        String orgId = blank(query.get("organization_id"));
        if (orgId != null) {
            where.append(" AND EXISTS (SELECT 1 FROM organization_members om WHERE om.user_id = u.id AND om.organization_id = :org)");
            params.put("org", Ids.parse(orgId));
        }
        String deptId = blank(query.get("department_id"));
        if (deptId != null) {
            where.append(" AND EXISTS (SELECT 1 FROM department_members dm WHERE dm.user_id = u.id AND dm.department_id = :dept)");
            params.put("dept", Ids.parse(deptId));
        }
        String attributeCode = blank(query.get("attribute_code"));
        String attributeValue = blank(query.get("attribute_value"));
        if (attributeCode != null && attributeValue != null) {
            where.append("""
                     AND EXISTS (SELECT 1 FROM user_attribute_values v
                                 JOIN user_attributes a ON a.id = v.attribute_id
                                 WHERE v.user_id = u.id AND a.code = :acode AND v.value = :aval)
                    """);
            params.put("acode", attributeCode);
            params.put("aval", Json.jsonb(Json.read(attributeValue)));
        }
        String from = blank(query.get("created_from"));
        if (from != null) {
            where.append(" AND u.created_at >= :from");
            params.put("from", Times.parse(from, "created_from"));
        }
        String to = blank(query.get("created_to"));
        if (to != null) {
            where.append(" AND u.created_at <= :to");
            params.put("to", Times.parse(to, "created_to"));
        }
        return new Filter(where.toString(), params);
    }

    public Map<String, Object> update(UUID tenantId, UUID userId, Body input, Integer expectedVersion,
                                      UUID actorId, RequestMeta meta) {
        Map<String, Object> current = activeUser(tenantId, userId);
        String displayName = input.has("display_name") ? input.trimmed("display_name") : str(current.get("display_name"));
        String avatarUrl = input.has("avatar_url") ? input.trimmed("avatar_url") : str(current.get("avatar_url"));
        String remark = input.has("remark") ? input.trimmed("remark") : str(current.get("remark"));
        StringBuilder sql = new StringBuilder("""
                UPDATE users SET display_name = :display, avatar_url = :avatar, remark = :remark,
                    updated_at = now(), version = version + 1
                WHERE tenant_id = :tenant AND id = :id AND deleted_at IS NULL
                """);
        Map<String, Object> params = Db.params("display", displayName, "avatar", avatarUrl, "remark", remark,
                "tenant", tenantId, "id", userId);
        if (expectedVersion != null) {
            sql.append(" AND version = :version");
            params.put("version", expectedVersion);
        }
        int rows = db.update(sql.toString(), params);
        if (rows == 0) {
            if (expectedVersion != null) {
                throw ApiException.conflict("版本冲突，数据已被修改");
            }
            throw ApiException.notFound("用户不存在");
        }
        audit.success(tenantId, actorId, "user.update", "user", userId.toString(), meta,
                Map.of("fields", input.map().keySet().stream().filter(k -> List.of("display_name", "avatar_url", "remark").contains(k)).toList()));
        outbox.publish("user.updated", "user", userId.toString(), Map.of(
                "identity_id", userId.toString(),
                "tenant_id", tenantId.toString(),
                "display_name", displayName == null ? "" : displayName,
                "avatar_url", avatarUrl == null ? "" : avatarUrl));
        syncProfileBestEffort(userId, Map.of("display_name", displayName == null ? "" : displayName,
                "avatar_url", avatarUrl == null ? "" : avatarUrl));
        return view(tenantId, userId);
    }

    public void delete(UUID tenantId, UUID userId, UUID actorId, RequestMeta meta) {
        Map<String, Object> current = activeUser(tenantId, userId);
        String from = String.valueOf(current.get("status"));
        StatusMachine.requireTransition(from, StatusMachine.DELETED);
        db.inTx(() -> {
            db.update("""
                    UPDATE users SET status = 'deleted', deleted_at = now(), updated_at = now(), version = version + 1
                    WHERE tenant_id = :tenant AND id = :id AND deleted_at IS NULL
                    """, Db.params("tenant", tenantId, "id", userId));
            audit.statusHistory(tenantId, userId, from, StatusMachine.DELETED, "soft delete", actorId);
        });
        audit.success(tenantId, actorId, "user.delete", "user", userId.toString(), meta, Map.of("from", from));
        outbox.publish("user.deleted", "user", userId.toString(), Map.of(
                "identity_id", userId.toString(), "tenant_id", tenantId.toString()));
        updateAuthStatusBestEffort(userId, StatusMachine.DELETED, "soft delete");
    }

    public Map<String, Object> restore(UUID tenantId, UUID userId, UUID actorId, RequestMeta meta) {
        Map<String, Object> current = db.one("""
                SELECT * FROM users WHERE tenant_id = :tenant AND id = :id AND deleted_at IS NOT NULL
                """, Db.params("tenant", tenantId, "id", userId));
        String from = String.valueOf(current.get("status"));
        db.inTx(() -> {
            db.update("""
                    UPDATE users SET status = 'active', deleted_at = NULL, updated_at = now(), version = version + 1
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("tenant", tenantId, "id", userId));
            audit.statusHistory(tenantId, userId, from, StatusMachine.ACTIVE, "restore", actorId);
        });
        audit.success(tenantId, actorId, "user.restore", "user", userId.toString(), meta, Map.of());
        outbox.publish("user.status_changed", "user", userId.toString(), Map.of(
                "identity_id", userId.toString(),
                "tenant_id", tenantId.toString(),
                "from", from,
                "to", StatusMachine.ACTIVE,
                "reason", "restore"));
        updateAuthStatusBestEffort(userId, StatusMachine.ACTIVE, "restore");
        return view(tenantId, userId);
    }

    public Map<String, Object> changeStatus(UUID tenantId, UUID userId, Body input, UUID actorId, RequestMeta meta) {
        String status = input.required("status", "状态");
        String reason = input.trimmed("reason");
        return applyStatus(tenantId, userId, status, reason, actorId, meta, true);
    }

    public Map<String, Object> applyStatus(UUID tenantId, UUID userId, String status, String reason,
                                            UUID actorId, RequestMeta meta, boolean syncAuth) {
        Map<String, Object> current = activeUser(tenantId, userId);
        String from = String.valueOf(current.get("status"));
        StatusMachine.requireTransition(from, status);
        if (from.equals(status)) {
            return view(tenantId, userId);
        }
        db.inTx(() -> {
            db.update("""
                    UPDATE users SET status = :status,
                        deleted_at = CASE WHEN :status = 'deleted' THEN now() ELSE deleted_at END,
                        updated_at = now(), version = version + 1
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("status", status, "tenant", tenantId, "id", userId));
            audit.statusHistory(tenantId, userId, from, status, reason, actorId);
        });
        audit.success(tenantId, actorId, "user.status_change", "user", userId.toString(), meta,
                Map.of("from", from, "to", status, "reason", reason == null ? "" : reason));
        outbox.publish("user.status_changed", "user", userId.toString(), Map.of(
                "identity_id", userId.toString(),
                "tenant_id", tenantId.toString(),
                "from", from,
                "to", status,
                "reason", reason == null ? "" : reason));
        if (syncAuth) {
            updateAuthStatusBestEffort(userId, status, reason);
        }
        return view(tenantId, userId);
    }

    public void applyExternalStatus(UUID tenantId, UUID userId, String status, String reason) {
        StatusMachine.validateTarget(status);
        Map<String, Object> current = db.find("""
                SELECT * FROM users WHERE tenant_id = :tenant AND id = :id
                """, Db.params("tenant", tenantId, "id", userId)).orElse(null);
        if (current == null) {
            return;
        }
        String from = String.valueOf(current.get("status"));
        if (from.equals(status)) {
            return;
        }
        db.inTx(() -> {
            db.update("""
                    UPDATE users SET status = :status,
                        deleted_at = CASE WHEN :status = 'deleted' THEN now() ELSE deleted_at END,
                        updated_at = now(), version = version + 1
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("status", status, "tenant", tenantId, "id", userId));
            audit.statusHistory(tenantId, userId, from, status, reason, null);
        });
        outbox.publish("user.status_changed", "user", userId.toString(), Map.of(
                "identity_id", userId.toString(),
                "tenant_id", tenantId.toString(),
                "from", from,
                "to", status,
                "reason", reason == null ? "auth sync" : reason,
                "source", "auth"));
    }

    public List<String> tags(UUID tenantId, UUID userId) {
        requireUserExists(tenantId, userId);
        return db.list("""
                SELECT tag FROM user_tags WHERE tenant_id = :tenant AND user_id = :user ORDER BY tag
                """, Db.params("tenant", tenantId, "user", userId))
                .stream().map(row -> String.valueOf(row.get("tag"))).toList();
    }

    public List<String> setTags(UUID tenantId, UUID userId, Body input, UUID actorId, RequestMeta meta) {
        requireActiveUser(tenantId, userId);
        List<String> tags = normalizeTags(input.strings("tags"));
        tx.executeWithoutResult(status -> {
            db.update("DELETE FROM user_tags WHERE tenant_id = :tenant AND user_id = :user",
                    Db.params("tenant", tenantId, "user", userId));
            for (String tag : tags) {
                db.update("""
                        INSERT INTO user_tags (id, tenant_id, user_id, tag)
                        VALUES (:id, :tenant, :user, :tag)
                        """, Db.params("id", Ids.uuidValue(), "tenant", tenantId, "user", userId, "tag", tag));
            }
        });
        audit.success(tenantId, actorId, "user.tags_update", "user", userId.toString(), meta, Map.of("tags", tags));
        outbox.publish("user.updated", "user", userId.toString(),
                Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "tags", tags));
        return tags(tenantId, userId);
    }

    public List<String> addTags(UUID tenantId, UUID userId, List<String> rawTags, UUID actorId, RequestMeta meta) {
        requireActiveUser(tenantId, userId);
        List<String> tags = normalizeTags(rawTags);
        for (String tag : tags) {
            db.update("""
                    INSERT INTO user_tags (id, tenant_id, user_id, tag)
                    VALUES (:id, :tenant, :user, :tag) ON CONFLICT DO NOTHING
                    """, Db.params("id", Ids.uuidValue(), "tenant", tenantId, "user", userId, "tag", tag));
        }
        audit.success(tenantId, actorId, "user.tags_update", "user", userId.toString(), meta, Map.of("added", tags));
        outbox.publish("user.updated", "user", userId.toString(),
                Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "tags", tags));
        return tags(tenantId, userId);
    }

    public Map<String, Object> statusHistory(UUID tenantId, UUID userId, Map<String, String> query) {
        requireUserExists(tenantId, userId);
        PageQuery page = PageQuery.parse(query.get("page"), query.get("page_size"));
        long total = db.count("""
                SELECT count(*) FROM user_status_history WHERE tenant_id = :tenant AND user_id = :user
                """, Db.params("tenant", tenantId, "user", userId));
        return Db.page(audit.statusHistory(tenantId, userId, page), total, page.page(), page.pageSize());
    }

    public List<Map<String, Object>> history(UUID tenantId, UUID userId) {
        requireUserExists(tenantId, userId);
        return audit.orgHistory(tenantId, userId);
    }

    public Map<String, Object> registration(UUID tenantId, UUID userId) {
        return db.find("""
                SELECT * FROM user_registration_records
                WHERE tenant_id = :tenant AND user_id = :user ORDER BY created_at DESC LIMIT 1
                """, Db.params("tenant", tenantId, "user", userId)).orElseGet(LinkedHashMap::new);
    }

    public List<Map<String, Object>> links(UUID tenantId, UUID userId) {
        requireUserExists(tenantId, userId);
        return db.list("""
                SELECT id, provider, provider_subject, linked_at, last_login_at
                FROM user_account_links WHERE tenant_id = :tenant AND user_id = :user
                ORDER BY linked_at DESC
                """, Db.params("tenant", tenantId, "user", userId));
    }

    public Map<String, Object> addLink(UUID tenantId, UUID userId, String provider, Body input,
                                        UUID actorId, RequestMeta meta) {
        requireActiveUser(tenantId, userId);
        String providerValue = normalizeProvider(provider != null ? provider : input.required("provider", "服务商"));
        String subject = input.required("provider_subject", "第三方标识");
        if (db.count("""
                SELECT count(*) FROM user_account_links
                WHERE provider = :provider AND provider_subject = :subject
                """, Db.params("provider", providerValue, "subject", subject)) > 0) {
            throw ApiException.conflict("该第三方账号已绑定");
        }
        UUID id = Ids.uuidValue();
        db.update("""
                INSERT INTO user_account_links (id, tenant_id, user_id, provider, provider_subject)
                VALUES (:id, :tenant, :user, :provider, :subject)
                """, Db.params("id", id, "tenant", tenantId, "user", userId, "provider", providerValue, "subject", subject));
        audit.success(tenantId, actorId, "user.link_add", "user", userId.toString(), meta, Map.of("provider", providerValue));
        outbox.publish("user.updated", "user", userId.toString(),
                Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "provider", providerValue));
        return db.one("SELECT * FROM user_account_links WHERE id = :id", Db.params("id", id));
    }

    public void removeLink(UUID tenantId, UUID userId, String provider, UUID actorId, RequestMeta meta) {
        requireUserExists(tenantId, userId);
        String providerValue = normalizeProvider(provider);
        int rows = db.update("""
                DELETE FROM user_account_links
                WHERE tenant_id = :tenant AND user_id = :user AND provider = :provider
                """, Db.params("tenant", tenantId, "user", userId, "provider", providerValue));
        if (rows == 0) {
            throw ApiException.notFound("未绑定该第三方账号");
        }
        audit.success(tenantId, actorId, "user.link_remove", "user", userId.toString(), meta, Map.of("provider", providerValue));
        outbox.publish("user.updated", "user", userId.toString(),
                Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "provider", providerValue));
    }

    // ───────────────────────── 批量/导入导出 ─────────────────────────

    public Map<String, Object> batchCreate(UUID tenantId, List<Object> items, UUID actorId, RequestMeta meta) {
        List<Map<String, Object>> errors = new ArrayList<>();
        List<String> created = new ArrayList<>();
        int success = 0;
        for (int i = 0; i < items.size(); i++) {
            try {
                Map<String, Object> user = create(tenantId, Body.of(items.get(i)), actorId, meta);
                success++;
                created.add(String.valueOf(user.get("id")));
            } catch (Exception e) {
                errors.add(error(i, e));
            }
        }
        return Map.of("success", success, "failed", errors.size(), "errors", errors, "created", created);
    }

    public Map<String, Object> batchUpdate(UUID tenantId, Object rawBody, UUID actorId, RequestMeta meta) {
        Body body = Body.of(rawBody);
        List<Map<String, Object>> errors = new ArrayList<>();
        List<Object> results = new ArrayList<>();
        int success = 0;
        List<Object> items = body.list("items");
        if (!items.isEmpty() || (!body.has("action") && !body.has("ids") && !body.has("user_ids"))) {
            for (int i = 0; i < items.size(); i++) {
                Map<String, Object> item = Json.readMap(items.get(i));
                try {
                    UUID id = Ids.parse(str(item.get("id")));
                    if (id == null) {
                        throw ApiException.validation("id", "ID 格式不合法");
                    }
                    Integer version = item.get("version") instanceof Number n ? n.intValue() : null;
                    Map<String, Object> user = update(tenantId, id, Body.of(item), version, actorId, meta);
                    success++;
                    results.add(Map.of("id", id.toString(), "status", user.get("status")));
                } catch (Exception e) {
                    errors.add(error(i, e));
                }
            }
        } else {
            String action = body.required("action", "操作");
            List<UUID> ids = body.uuids("ids");
            if (ids.isEmpty()) {
                ids = body.uuids("user_ids");
            }
            if (ids.isEmpty()) {
                throw ApiException.validation("ids", "至少需要一个用户");
            }
            List<String> tags = body.strings("tags");
            for (UUID id : ids) {
                try {
                    switch (action) {
                        case "enable", "activate" -> applyStatus(tenantId, id, StatusMachine.ACTIVE, body.trimmed("reason"),
                                actorId, meta, true);
                        case "disable" -> applyStatus(tenantId, id, StatusMachine.DISABLED, body.trimmed("reason"),
                                actorId, meta, true);
                        case "delete" -> delete(tenantId, id, actorId, meta);
                        case "restore" -> restore(tenantId, id, actorId, meta);
                        case "tag", "add_tags" -> addTags(tenantId, id, tags, actorId, meta);
                        case "set_tags" -> setTags(tenantId, id, Body.of(Map.of("tags", tags)), actorId, meta);
                        case "status" -> applyStatus(tenantId, id, body.required("status", "状态"),
                                body.trimmed("reason"), actorId, meta, true);
                        default -> throw ApiException.validation("action", "不支持的操作: " + action);
                    }
                    success++;
                    results.add(Map.of("id", id.toString(), "ok", true));
                } catch (Exception e) {
                    errors.add(error(id.toString(), e));
                }
            }
        }
        return Map.of("success", success, "failed", errors.size(), "errors", errors, "results", results);
    }

    public Map<String, Object> importUsers(UUID tenantId, Body input, UUID actorId, RequestMeta meta) {
        String content = input.required("content", "导入内容");
        String format = input.str("format", "auto").toLowerCase();
        List<Object> rows;
        if ("json".equals(format) || ("auto".equals(format) && content.trim().startsWith("["))) {
            rows = new ArrayList<>(Json.readList(content));
        } else if ("csv".equals(format) || "auto".equals(format) || "text".equals(format)) {
            rows = new ArrayList<>();
            for (Map<String, String> row : com.platform.user.common.Csv.parse(content)) {
                rows.add(new LinkedHashMap<>(row));
            }
        } else {
            throw ApiException.validation("format", "仅支持 json 或 csv");
        }
        List<Map<String, Object>> errors = new ArrayList<>();
        List<String> created = new ArrayList<>();
        int success = 0;
        Set<String> seenUsernames = new LinkedHashSet<>();
        Set<String> seenEmails = new LinkedHashSet<>();
        Set<String> seenPhones = new LinkedHashSet<>();
        for (int i = 0; i < rows.size(); i++) {
            Map<String, Object> row = Json.readMap(rows.get(i));
            try {
                String username = Text.normalizeUsername(str(row.get("username")));
                if (username == null) {
                    throw ApiException.validation("username", "用户名不能为空");
                }
                if (!seenUsernames.add(username)) {
                    throw ApiException.conflict("导入文件内用户名重复");
                }
                String email = Text.normalizeEmail(str(row.get("email")));
                if (email != null && !seenEmails.add(email)) {
                    throw ApiException.conflict("导入文件内邮箱重复");
                }
                String phone = Text.normalizePhone(str(row.get("phone")));
                if (phone != null && !seenPhones.add(phone)) {
                    throw ApiException.conflict("导入文件内手机号重复");
                }
                if (row.get("status") == null) {
                    row.put("status", "active");
                }
                if (row.get("source") == null) {
                    row.put("source", "import");
                }
                Map<String, Object> user = create(tenantId, Body.of(row), actorId, meta);
                success++;
                created.add(String.valueOf(user.get("id")));
            } catch (Exception e) {
                errors.add(error(i + 2, e));
            }
        }
        audit.success(tenantId, actorId, "user.import", "user", null, meta,
                Map.of("total", rows.size(), "success", success, "failed", errors.size()));
        return Map.of("total", rows.size(), "success", success, "failed", errors.size(),
                "errors", errors, "created", created);
    }

    public List<Map<String, Object>> exportUsers(UUID tenantId, Map<String, String> query) {
        Filter filter = filter(tenantId, query);
        Map<String, String> safe = new LinkedHashMap<>(query);
        safe.remove("page");
        safe.remove("page_size");
        String sort = SORTS.getOrDefault(blank(query.get("sort")), SORTS.get("created_at_desc"));
        List<Map<String, Object>> items = db.list("""
                SELECT u.*, p.gender, p.birthday, p.bio, p.region, p.timezone, p.locale, p.website,
                       p.company, p.job_title, p.completeness
                FROM users u LEFT JOIN user_profiles p ON p.user_id = u.id
                """ + filter.where + " ORDER BY " + sort + " LIMIT 10000", filter.params);
        attachTags(items);
        return items;
    }

    // ───────────────────────── 内部接口 ─────────────────────────

    public Map<String, Object> ensureInternal(UUID tenantId, Body input, RequestMeta meta) {
        UUID identityId = input.requiredUuid("identity_id", "identity_id");
        Map<String, Object> existing = db.find("SELECT * FROM users WHERE id = :id",
                Db.params("id", identityId)).orElse(null);
        if (existing != null) {
            String existingTenant = String.valueOf(existing.get("tenant_id"));
            if (!existingTenant.equals(tenantId.toString())) {
                throw ApiException.conflict("identity 已属于其他租户");
            }
            if (existing.get("deleted_at") != null) {
                db.update("""
                        UPDATE users SET deleted_at = NULL, status = 'active', updated_at = now()
                        WHERE id = :id
                        """, Db.params("id", identityId));
            }
            return view(tenantId, identityId);
        }
        Map<String, Object> row = new LinkedHashMap<>(input.map());
        row.put("id", identityId);
        row.put("tenant_id", tenantId);
        row.putIfAbsent("status", "active");
        row.putIfAbsent("source", "internal");
        if (row.get("username") == null || String.valueOf(row.get("username")).isBlank()) {
            row.put("username", "user_" + identityId.toString().replace("-", "").substring(0, 10));
        }
        createInternal(tenantId, Body.of(row), null, meta, null);
        return view(tenantId, identityId);
    }

    public Map<String, Object> internalUser(UUID tenantId, UUID userId) {
        return view(tenantId, userId);
    }

    public Map<String, Object> internalStatus(UUID tenantId, UUID userId, Body input, RequestMeta meta) {
        String status = input.required("status", "状态");
        return applyStatus(tenantId, userId, status, input.trimmed("reason"), null, meta, false);
    }

    // ───────────────────────── 工具 ─────────────────────────

    private Map<String, Object> activeUser(UUID tenantId, UUID userId) {
        return db.one("""
                SELECT * FROM users WHERE tenant_id = :tenant AND id = :id AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "id", userId));
    }

    private void requireActiveUser(UUID tenantId, UUID userId) {
        if (db.count("""
                SELECT count(*) FROM users WHERE tenant_id = :tenant AND id = :id AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "id", userId)) == 0) {
            throw ApiException.notFound("用户不存在");
        }
    }

    private void requireUserExists(UUID tenantId, UUID userId) {
        if (db.count("SELECT count(*) FROM users WHERE tenant_id = :tenant AND id = :id",
                Db.params("tenant", tenantId, "id", userId)) == 0) {
            throw ApiException.notFound("用户不存在");
        }
    }

    private void attachTags(List<Map<String, Object>> items) {
        if (items.isEmpty()) {
            return;
        }
        List<UUID> ids = new ArrayList<>();
        for (Map<String, Object> item : items) {
            UUID id = Ids.parse(str(item.get("id")));
            if (id != null) {
                ids.add(id);
            }
        }
        Map<String, List<String>> byUser = new LinkedHashMap<>();
        if (!ids.isEmpty()) {
            List<Map<String, Object>> rows = db.list("""
                    SELECT user_id, tag FROM user_tags WHERE user_id IN (:ids) ORDER BY tag
                    """, Db.params("ids", ids));
            for (Map<String, Object> row : rows) {
                byUser.computeIfAbsent(String.valueOf(row.get("user_id")), k -> new ArrayList<>())
                        .add(String.valueOf(row.get("tag")));
            }
        }
        for (Map<String, Object> item : items) {
            item.put("tags", byUser.getOrDefault(String.valueOf(item.get("id")), new ArrayList<>()));
        }
    }

    private List<String> normalizeTags(List<String> raw) {
        Set<String> out = new LinkedHashSet<>();
        if (raw != null) {
            for (String tag : raw) {
                String value = Text.blankToNull(tag);
                if (value == null) {
                    continue;
                }
                if (value.length() > 64) {
                    throw ApiException.validation("tags", "标签长度不能超过 64");
                }
                out.add(value);
            }
        }
        return new ArrayList<>(out);
    }

    private String normalizeProvider(String provider) {
        String value = Text.normalizeUsername(provider);
        if (value == null || !value.matches("^[a-z0-9_-]{1,32}$")) {
            throw ApiException.validation("provider", "服务商标识需为 1-32 位小写字母、数字、下划线或中划线");
        }
        return value;
    }

    private static LocalDate parseDate(String value, String field) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return LocalDate.parse(value.trim());
        } catch (Exception e) {
            throw ApiException.validation(field, "日期格式不合法，应为 YYYY-MM-DD");
        }
    }

    private static int completeness(String gender, LocalDate birthday, String bio, String region,
                                    String timezone, String locale, String website, String company, String jobTitle) {
        int filled = 0;
        if (gender != null) filled++;
        if (birthday != null) filled++;
        if (bio != null) filled++;
        if (region != null) filled++;
        if (timezone != null) filled++;
        if (locale != null) filled++;
        if (website != null) filled++;
        if (company != null) filled++;
        if (jobTitle != null) filled++;
        return Math.round(filled * 100f / 9f);
    }

    private void syncProfileBestEffort(UUID userId, Map<String, Object> profile) {
        try {
            auth.syncProfile(userId, profile);
        } catch (Exception e) {
            log.debug("同步用户资料到认证中心失败 {}: {}", userId, e.getMessage());
        }
    }

    private void updateAuthStatusBestEffort(UUID userId, String status, String reason) {
        try {
            auth.updateStatus(userId, status, reason);
        } catch (Exception e) {
            log.debug("同步用户状态到认证中心失败 {}: {}", userId, e.getMessage());
        }
    }

    private static Map<String, Object> error(int index, Exception e) {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("index", index);
        if (e instanceof ApiException api) {
            error.put("code", api.code());
            error.put("error", api.getMessage());
        } else {
            error.put("code", "error");
            error.put("error", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
        return error;
    }

    private static Map<String, Object> error(String id, Exception e) {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("id", id);
        if (e instanceof ApiException api) {
            error.put("code", api.code());
            error.put("error", api.getMessage());
        } else {
            error.put("code", "error");
            error.put("error", e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage());
        }
        return error;
    }

    private static String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private static String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private record Filter(String where, Map<String, Object> params) {
    }
}
