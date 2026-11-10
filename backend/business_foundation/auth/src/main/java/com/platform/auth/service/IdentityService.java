package com.platform.auth.service;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.AuditService;
import com.platform.auth.common.Db;
import com.platform.auth.common.Ids;
import com.platform.auth.common.Json;
import com.platform.auth.common.NotificationService;
import com.platform.auth.common.OutboxService;
import com.platform.auth.config.AppProps;
import com.platform.auth.security.PasswordService;
import com.platform.auth.security.JwtService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class IdentityService {
    public static final String DEFAULT_TENANT = "00000000-0000-0000-0000-000000000001";
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_.@-]{3,64}");
    private static final Pattern EMAIL = Pattern.compile("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$");
    private static final Pattern PHONE = Pattern.compile("^\\+?[0-9]{6,20}$");

    private final Db db;
    private final AppProps props;
    private final PasswordService passwords;
    private final NotificationService notifications;
    private final SessionService sessions;
    private final RbacService rbac;
    private final AuditService audit;
    private final OutboxService outbox;
    private final JwtService jwt;

    public IdentityService(Db db, AppProps props, PasswordService passwords, NotificationService notifications,
                           SessionService sessions, RbacService rbac, AuditService audit, OutboxService outbox,
                           JwtService jwt) {
        this.db = db;
        this.props = props;
        this.passwords = passwords;
        this.notifications = notifications;
        this.sessions = sessions;
        this.rbac = rbac;
        this.audit = audit;
        this.outbox = outbox;
        this.jwt = jwt;
    }

    public String tenantId(String code) {
        if (code == null || code.isBlank()) {
            return DEFAULT_TENANT;
        }
        return db.list("SELECT id FROM tenants WHERE lower(code) = lower(:code) AND deleted_at IS NULL",
                        Db.params("code", code)).stream().findFirst()
                .map(r -> String.valueOf(r.get("id")))
                .orElseThrow(() -> ApiException.notFound("租户不存在"));
    }

    public Map<String, Object> register(Map<String, Object> body, SessionService.LoginMeta meta) {
        if (!props.isRegistrationEnabled()) {
            throw ApiException.forbidden("当前未开放注册");
        }
        String tenant = tenantId(str(body.get("tenant")));
        Object status = props.isRequireEmailVerification() && body.get("email") != null ? "pending" : "active";
        Map<String, Object> identity = create(body, tenant, String.valueOf(status), meta, "registration");
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("identity", identity);
        return out;
    }

    public Map<String, Object> create(Map<String, Object> body, String tenantId, String status,
                                      SessionService.LoginMeta meta, String source) {
        String username = str(body.get("username"));
        String email = normalizeEmail(str(body.get("email")));
        String phone = normalizePhone(str(body.get("phone")));
        String password = str(body.get("password"));
        if (Ids.blank(username) || !USERNAME.matcher(username).matches()) {
            throw ApiException.badRequest("用户名格式不合法（3-64 位字母、数字、_ . @ -）");
        }
        if (email != null && !EMAIL.matcher(email).matches()) {
            throw ApiException.badRequest("邮箱格式不合法");
        }
        if (phone != null && !PHONE.matcher(phone).matches()) {
            throw ApiException.badRequest("手机号格式不合法");
        }
        if (password != null) {
            passwords.validateStrength(password);
        }
        if (email == null && phone == null && password == null) {
            throw ApiException.badRequest("缺少可用的登录凭证");
        }
        assertUnique(tenantId, username, email, phone, null);
        String id = Ids.uuidStr();
        String finalStatus = status == null ? "active" : status;
        db.inTx(() -> {
            db.update("""
                    INSERT INTO identities (id, tenant_id, username, email, phone, display_name, avatar_url, status,
                                            metadata, email_verified, phone_verified)
                    VALUES (:id, :tenant, :username, :email, :phone, :display, :avatar, :status, :metadata, FALSE, FALSE)
                    """, Db.params("id", id, "tenant", tenantId, "username", username, "email", email, "phone", phone,
                    "display", str(body.get("display_name")), "avatar", str(body.get("avatar_url")),
                    "status", finalStatus,
                    "metadata", Json.jsonb(Map.of("source", source == null ? "admin" : source))));
            insertIdentifier(id, tenantId, "username", username);
            if (email != null) {
                insertIdentifier(id, tenantId, "email", email);
            }
            if (phone != null) {
                insertIdentifier(id, tenantId, "phone", phone);
            }
            if (password != null) {
                db.update("""
                        INSERT INTO identity_credentials (identity_id, credential_type, secret_hash)
                        VALUES (:id, 'password', :hash)
                        """, Db.params("id", id, "hash", passwords.hash(password)));
            }
        });
        Map<String, Object> identity = get(id);
        audit.log(tenantId, id, "identity.created", "identity", id, "success",
                meta == null ? null : meta.ip(), meta == null ? null : meta.userAgent(),
                Map.of("source", source == null ? "admin" : source, "status", finalStatus));
        outbox.publish("identity.registered", "identity", id, Map.of(
                "identity_id", id, "tenant_id", tenantId, "username", username,
                "email", email == null ? "" : email, "phone", phone == null ? "" : phone,
                "display_name", str(body.get("display_name")) == null ? "" : str(body.get("display_name")),
                "status", finalStatus));
        return identity;
    }

    public Map<String, Object> login(Map<String, Object> body, SessionService.LoginMeta meta) {
        String tenant = tenantId(str(body.get("tenant")));
        String identifier = str(body.get("identifier"));
        String password = str(body.get("password"));
        if (Ids.blank(identifier) || password == null) {
            throw ApiException.badRequest("缺少账号或密码");
        }
        Map<String, Object> identity = findByLogin(tenant, identifier)
                .orElseThrow(() -> {
                    audit.log(tenant, null, "auth.login", "identity", null, "failure", meta.ip(), meta.userAgent(),
                            Map.of("identifier", identifier, "reason", "not_found"));
                    return ApiException.badRequest("账号或密码错误");
                });
        String id = String.valueOf(identity.get("id"));
        try {
            assertLoginable(identity);
            Map<String, Object> credential = db.list("""
                    SELECT secret_hash FROM identity_credentials WHERE identity_id = :id AND credential_type = 'password'
                    """, Db.params("id", id)).stream().findFirst().orElse(null);
            if (credential == null || !passwords.matches(password, String.valueOf(credential.get("secret_hash")))) {
                registerFailure(identity, meta);
                throw ApiException.badRequest("账号或密码错误");
            }
            return completeLogin(identity, List.of("pwd"), "urn:auth:acr:pwd", body, meta);
        } catch (ApiException e) {
            audit.log(tenant, id, "auth.login", "identity", id, "failure", meta.ip(), meta.userAgent(),
                    Map.of("reason", e.getMessage()));
            throw e;
        }
    }

    public Map<String, Object> loginOtp(Map<String, Object> body, SessionService.LoginMeta meta) {
        String tenant = tenantId(str(body.get("tenant")));
        String identifier = str(body.get("identifier"));
        String code = str(body.get("code"));
        if (Ids.blank(identifier) || Ids.blank(code)) {
            throw ApiException.badRequest("缺少账号或验证码");
        }
        String channel = str(body.get("channel"));
        if (channel == null) {
            channel = identifier.contains("@") ? "email" : "sms";
        }
        String target = identifier.contains("@") ? normalizeEmail(identifier) : normalizePhone(identifier);
        notifications.verify(tenant, "login", channel, target, code);
        Map<String, Object> identity = findByLogin(tenant, identifier)
                .orElseThrow(() -> ApiException.badRequest("账号不存在"));
        assertLoginable(identity);
        return completeLogin(identity, List.of("otp"), "urn:auth:acr:otp", body, meta);
    }

    public Map<String, Object> requestOtp(Map<String, Object> body, SessionService.LoginMeta meta) {
        String tenant = tenantId(str(body.get("tenant")));
        String identifier = str(body.get("identifier"));
        Map<String, Object> identity = findByLogin(tenant, identifier)
                .orElseThrow(() -> ApiException.badRequest("账号不存在"));
        String channel = str(body.get("channel"));
        if (channel == null) {
            channel = identity.get("email") != null ? "email" : "sms";
        }
        String target = "email".equals(channel) ? str(identity.get("email")) : str(identity.get("phone"));
        if (Ids.blank(target)) {
            throw ApiException.badRequest("账号没有对应的联系方式");
        }
        notifications.issue(tenant, String.valueOf(identity.get("id")), "login",
                "email".equals(channel) ? "email" : "sms", target);
        return Map.of("sent", true, "channel", channel);
    }

    private Map<String, Object> completeLogin(Map<String, Object> identity, List<String> amr, String acr,
                                              Map<String, Object> body, SessionService.LoginMeta meta) {
        String id = String.valueOf(identity.get("id"));
        String tenant = String.valueOf(identity.get("tenant_id"));
        db.update("""
                UPDATE identities SET failed_attempts = 0, locked_until = NULL, last_login_at = now(),
                last_login_ip = :ip, status = CASE WHEN status = 'pending' THEN 'active' ELSE status END
                WHERE id = :id
                """, Db.params("ip", meta.ip(), "id", id));
        if (!activeFactors(id).isEmpty()) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("mfa_required", true);
            out.put("mfa_token", jwt.signMfa(id, tenant));
            out.put("factors", activeFactors(id));
            out.put("expires_in", 300);
            return out;
        }
        String scope = str(body.get("scope")) == null ? "openid profile email offline_access" : str(body.get("scope"));
        Map<String, Object> tokens = sessions.issue(id, tenant, "auth-console", scope, amr, acr, meta, null);
        if (passwordExpired(identity)) {
            Map<String, Object> flagged = new LinkedHashMap<>(tokens);
            flagged.put("password_expired", true);
            tokens = flagged;
        }
        audit.log(tenant, id, "auth.login", "identity", id, "success", meta.ip(), meta.userAgent(),
                Map.of("amr", amr));
        return tokens;
    }

    private boolean passwordExpired(Map<String, Object> identity) {
        if (props.getPasswordMaxAgeDays() <= 0) {
            return false;
        }
        Object updated = identity.get("password_updated_at");
        if (updated == null) {
            return true;
        }
        try {
            return Instant.parse(String.valueOf(updated))
                    .plusSeconds(props.getPasswordMaxAgeDays() * 86400)
                    .isBefore(Instant.now());
        } catch (Exception e) {
            return false;
        }
    }

    public List<Map<String, Object>> activeFactors(String identityId) {
        return db.list("SELECT id, kind, name, verified_at FROM mfa_factors WHERE identity_id = :id AND status = 'active'",
                Db.params("id", identityId));
    }

    private void registerFailure(Map<String, Object> identity, SessionService.LoginMeta meta) {
        int attempts = ((Number) identity.getOrDefault("failed_attempts", 0)).intValue() + 1;
        boolean locked = attempts >= props.getLoginMaxAttempts();
        db.update("""
                UPDATE identities SET failed_attempts = :attempts,
                locked_until = CASE WHEN :lock THEN now() + (:secs || ' seconds')::interval ELSE locked_until END,
                status = CASE WHEN :lock AND status = 'active' THEN 'locked' ELSE status END
                WHERE id = :id
                """, Db.params("attempts", attempts, "lock", locked, "secs", String.valueOf(props.getLoginLockSeconds()),
                "id", identity.get("id")));
    }

    private void assertLoginable(Map<String, Object> identity) {
        String status = String.valueOf(identity.get("status"));
        Instant lockedUntil = identity.get("locked_until") == null ? null
                : Instant.parse(String.valueOf(identity.get("locked_until")));
        if (lockedUntil != null && lockedUntil.isAfter(Instant.now())) {
            throw new ApiException(423, "account_locked", "账户已被锁定，请稍后再试");
        }
        switch (status) {
            case "active", "pending" -> { }
            case "locked" -> throw new ApiException(423, "account_locked", "账户已被锁定");
            case "disabled" -> throw new ApiException(403, "account_disabled", "账户已被禁用");
            default -> throw new ApiException(403, "account_unavailable", "账户当前不可用");
        }
    }

    public Map<String, Object> me(String identityId) {
        Map<String, Object> identity = get(identityId);
        identity.remove("password_hash");
        Map<String, Object> out = new LinkedHashMap<>(identity);
        out.put("identifiers", db.list("""
                SELECT kind, value, verified_at, is_primary FROM identity_identifiers
                WHERE identity_id = :id ORDER BY kind, created_at
                """, Db.params("id", identityId)));
        out.put("roles", rbac.roleCodes(identityId, String.valueOf(identity.get("tenant_id"))));
        out.put("permissions", rbac.permissions(identityId, String.valueOf(identity.get("tenant_id"))));
        out.put("mfa_factors", activeFactors(identityId));
        return out;
    }

    public Map<String, Object> updateSelf(String identityId, Map<String, Object> body) {
        Map<String, Object> identity = get(identityId);
        String tenant = String.valueOf(identity.get("tenant_id"));
        String displayName = str(body.get("display_name"));
        String avatar = str(body.get("avatar_url"));
        if (displayName != null || avatar != null) {
            db.update("""
                    UPDATE identities SET display_name = COALESCE(:display, display_name),
                    avatar_url = COALESCE(:avatar, avatar_url), updated_at = now(), version = version + 1
                    WHERE id = :id
                    """, Db.params("display", displayName, "avatar", avatar, "id", identityId));
        }
        audit.log(tenant, identityId, "identity.updated", "identity", identityId, "success", null, null,
                Map.of("fields", body.keySet()));
        outbox.publish("identity.updated", "identity", identityId,
                Map.of("identity_id", identityId, "tenant_id", tenant, "display_name", displayName == null ? "" : displayName));
        return me(identityId);
    }

    public Map<String, Object> changePassword(String identityId, Map<String, Object> body, SessionService.LoginMeta meta) {
        Map<String, Object> identity = get(identityId);
        String tenant = String.valueOf(identity.get("tenant_id"));
        String current = str(body.get("current_password"));
        String next = str(body.get("new_password"));
        passwords.validateStrength(next);
        Map<String, Object> credential = db.list(
                "SELECT secret_hash FROM identity_credentials WHERE identity_id = :id AND credential_type = 'password'",
                Db.params("id", identityId)).stream().findFirst()
                .orElseThrow(() -> ApiException.badRequest("账户未设置密码"));
        if (!passwords.matches(current, String.valueOf(credential.get("secret_hash")))) {
            throw ApiException.badRequest("当前密码不正确");
        }
        if (passwords.matches(next, String.valueOf(credential.get("secret_hash")))) {
            throw ApiException.badRequest("新密码不能与当前密码相同");
        }
        List<Map<String, Object>> history = db.list("""
                SELECT password_hash FROM password_history WHERE identity_id = :id ORDER BY created_at DESC LIMIT 5
                """, Db.params("id", identityId));
        for (Map<String, Object> row : history) {
            if (passwords.matches(next, String.valueOf(row.get("password_hash")))) {
                throw ApiException.badRequest("新密码不能与最近使用的密码重复");
            }
        }
        String hash = passwords.hash(next);
        db.inTx(() -> {
            db.update("UPDATE identity_credentials SET secret_hash = :hash, updated_at = now() WHERE identity_id = :id AND credential_type = 'password'",
                    Db.params("hash", hash, "id", identityId));
            db.update("INSERT INTO password_history (identity_id, password_hash) VALUES (:id, :hash)",
                    Db.params("id", identityId, "hash", hash));
            db.update("UPDATE identities SET password_updated_at = now(), updated_at = now() WHERE id = :id",
                    Db.params("id", identityId));
        });
        audit.log(tenant, identityId, "identity.password_changed", "identity", identityId, "success",
                meta.ip(), meta.userAgent(), Map.of());
        outbox.publish("identity.password_changed", "identity", identityId,
                Map.of("identity_id", identityId, "tenant_id", tenant));
        return Map.of("changed", true);
    }

    public Map<String, Object> forgotPassword(Map<String, Object> body, SessionService.LoginMeta meta) {
        String tenant = tenantId(str(body.get("tenant")));
        String identifier = str(body.get("identifier"));
        Map<String, Object> identity = findByLogin(tenant, identifier).orElse(null);
        if (identity != null) {
            String channel = identity.get("email") != null ? "email" : "sms";
            String target = "email".equals(channel) ? str(identity.get("email")) : str(identity.get("phone"));
            if (target != null) {
                notifications.issue(tenant, String.valueOf(identity.get("id")), "reset_password",
                        "email".equals(channel) ? "email" : "sms", target);
            }
        }
        return Map.of("sent", true);
    }

    public Map<String, Object> resetPassword(Map<String, Object> body, SessionService.LoginMeta meta) {
        String tenant = tenantId(str(body.get("tenant")));
        String identifier = str(body.get("identifier"));
        String code = str(body.get("code"));
        String password = str(body.get("new_password"));
        passwords.validateStrength(password);
        Map<String, Object> identity = findByLogin(tenant, identifier)
                .orElseThrow(() -> ApiException.badRequest("验证码错误"));
        String channel = identity.get("email") != null ? "email" : "sms";
        String target = "email".equals(channel) ? str(identity.get("email")) : str(identity.get("phone"));
        notifications.verify(tenant, "reset_password", channel, target, code);
        String id = String.valueOf(identity.get("id"));
        String hash = passwords.hash(password);
        db.inTx(() -> {
            db.update("UPDATE identity_credentials SET secret_hash = :hash, updated_at = now() WHERE identity_id = :id AND credential_type = 'password'",
                    Db.params("hash", hash, "id", id));
            db.update("INSERT INTO password_history (identity_id, password_hash) VALUES (:id, :hash)",
                    Db.params("id", id, "hash", hash));
            db.update("UPDATE identities SET password_updated_at = now(), failed_attempts = 0, locked_until = NULL, status = 'active' WHERE id = :id",
                    Db.params("id", id));
        });
        sessions.logoutAll(id);
        audit.log(tenant, id, "identity.password_reset", "identity", id, "success", meta.ip(), meta.userAgent(), Map.of());
        return Map.of("reset", true);
    }

    public Map<String, Object> requestVerification(String identityId, String kind, SessionService.LoginMeta meta) {
        Map<String, Object> identity = get(identityId);
        String tenant = String.valueOf(identity.get("tenant_id"));
        String target = "email".equals(kind) ? str(identity.get("email")) : str(identity.get("phone"));
        if (target == null) {
            throw ApiException.badRequest("账户未设置" + ("email".equals(kind) ? "邮箱" : "手机号"));
        }
        notifications.issue(tenant, identityId, "email".equals(kind) ? "verify_email" : "verify_phone",
                "email".equals(kind) ? "email" : "sms", target);
        return Map.of("sent", true, "channel", kind);
    }

    public Map<String, Object> confirmVerification(String identityId, String kind, String code,
                                                   SessionService.LoginMeta meta) {
        Map<String, Object> identity = get(identityId);
        String tenant = String.valueOf(identity.get("tenant_id"));
        String target = "email".equals(kind) ? str(identity.get("email")) : str(identity.get("phone"));
        if (target == null) {
            throw ApiException.badRequest("账户未设置对应联系方式");
        }
        notifications.verify(tenant, "email".equals(kind) ? "verify_email" : "verify_phone",
                "email".equals(kind) ? "email" : "sms", target, code);
        db.update("UPDATE identities SET " + ("email".equals(kind) ? "email_verified" : "phone_verified")
                + " = TRUE, updated_at = now() WHERE id = :id", Db.params("id", identityId));
        audit.log(tenant, identityId, "identity.verified", "identity", identityId, "success",
                meta.ip(), meta.userAgent(), Map.of("kind", kind));
        publishContacts(tenant, identityId, "verified");
        return Map.of("verified", true);
    }

    private void publishContacts(String tenant, String identityId, String reason) {
        Map<String, Object> identity = get(identityId);
        List<Map<String, Object>> contacts = new ArrayList<>();
        if (identity.get("email") != null) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("kind", "email");
            item.put("value", identity.get("email"));
            item.put("verified", Boolean.TRUE.equals(identity.get("email_verified")));
            item.put("is_primary", true);
            contacts.add(item);
        }
        if (identity.get("phone") != null) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("kind", "phone");
            item.put("value", identity.get("phone"));
            item.put("verified", Boolean.TRUE.equals(identity.get("phone_verified")));
            item.put("is_primary", true);
            contacts.add(item);
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("identity_id", identityId);
        payload.put("tenant_id", tenant);
        payload.put("contacts", contacts);
        payload.put("reason", reason);
        outbox.publish("identity.contacts_changed", "identity", identityId, payload);
    }

    public Map<String, Object> requestContactChange(String identityId, Map<String, Object> body,
                                                    SessionService.LoginMeta meta) {
        Map<String, Object> identity = get(identityId);
        String tenant = String.valueOf(identity.get("tenant_id"));
        String kind = str(body.get("kind"));
        String value = "email".equals(kind) ? normalizeEmail(str(body.get("value"))) : normalizePhone(str(body.get("value")));
        if (value == null) {
            throw ApiException.badRequest("联系方式格式不合法");
        }
        assertUnique(tenant, null, "email".equals(kind) ? value : null, "phone".equals(kind) ? value : null, identityId);
        notifications.issue(tenant, identityId, "email".equals(kind) ? "change_email" : "change_phone",
                "email".equals(kind) ? "email" : "sms", value);
        return Map.of("sent", true, "kind", kind, "target", value);
    }

    public Map<String, Object> confirmContactChange(String identityId, Map<String, Object> body,
                                                    SessionService.LoginMeta meta) {
        Map<String, Object> identity = get(identityId);
        String tenant = String.valueOf(identity.get("tenant_id"));
        String kind = str(body.get("kind"));
        String value = "email".equals(kind) ? normalizeEmail(str(body.get("value"))) : normalizePhone(str(body.get("value")));
        notifications.verify(tenant, "email".equals(kind) ? "change_email" : "change_phone",
                "email".equals(kind) ? "email" : "sms", value, str(body.get("code")));
        String column = "email".equals(kind) ? "email" : "phone";
        String verifiedColumn = "email".equals(kind) ? "email_verified" : "phone_verified";
        db.inTx(() -> {
            db.update("UPDATE identities SET " + column + " = :value, " + verifiedColumn + " = TRUE, updated_at = now() WHERE id = :id",
                    Db.params("value", value, "id", identityId));
            db.update("DELETE FROM identity_identifiers WHERE identity_id = :id AND kind = :kind",
                    Db.params("id", identityId, "kind", kind));
            insertIdentifier(identityId, tenant, kind, value);
        });
        audit.log(tenant, identityId, "identity.contact_changed", "identity", identityId, "success",
                meta.ip(), meta.userAgent(), Map.of("kind", kind));
        publishContacts(tenant, identityId, "changed");
        return Map.of("changed", true);
    }

    public List<Map<String, Object>> consents(String identityId) {
        return db.list("""
                SELECT c.*, cl.name AS client_name FROM oauth_consents c
                LEFT JOIN oauth_clients cl ON cl.client_id = c.client_id
                WHERE c.identity_id = :id AND c.status = 'active' ORDER BY c.updated_at DESC
                """, Db.params("id", identityId));
    }

    public void revokeConsent(String identityId, String clientId) {
        int updated = db.update("""
                UPDATE oauth_consents SET status = 'revoked', revoked_at = now(), updated_at = now()
                WHERE identity_id = :id AND client_id = :client AND status = 'active'
                """, Db.params("id", identityId, "client", clientId));
        if (updated == 0) {
            throw ApiException.notFound("授权记录不存在");
        }
    }

    public Map<String, Object> get(String id) {
        return db.list("""
                SELECT * FROM identities WHERE id = :id AND deleted_at IS NULL
                """, Db.params("id", id)).stream().findFirst()
                .orElseThrow(() -> ApiException.notFound("身份不存在"));
    }

    public java.util.Optional<Map<String, Object>> findByLogin(String tenantId, String identifier) {
        String email = normalizeEmail(identifier);
        String phone = normalizePhone(identifier);
        return db.list("""
                SELECT * FROM identities WHERE tenant_id = :tenant AND deleted_at IS NULL AND (
                    lower(username) = lower(:value) OR lower(email) = lower(:value) OR phone = :phone)
                ORDER BY created_at LIMIT 1
                """, Db.params("tenant", tenantId, "value", identifier, "phone", phone == null ? identifier : phone))
                .stream().findFirst();
    }

    public Map<String, Object> adminList(int page, int size, String status, String keyword) {
        Map<String, Object> params = new LinkedHashMap<>();
        StringBuilder where = new StringBuilder(" WHERE deleted_at IS NULL");
        if (status != null && !status.isBlank()) {
            where.append(" AND status = :status");
            params.put("status", status);
        }
        if (keyword != null && !keyword.isBlank()) {
            where.append(" AND (lower(username) LIKE lower(:kw) OR lower(email) LIKE lower(:kw) OR phone LIKE :kw)");
            params.put("kw", "%" + keyword + "%");
        }
        long total = db.count("SELECT count(*) FROM identities" + where, params);
        params.put("limit", size);
        params.put("offset", (page - 1) * size);
        List<Map<String, Object>> items = db.list("""
                SELECT id, tenant_id, username, email, email_verified, phone, phone_verified, display_name,
                       avatar_url, status, status_reason, mfa_enforced, failed_attempts, locked_until,
                       last_login_at, last_login_ip, created_at, updated_at, version
                FROM identities""" + where + " ORDER BY created_at DESC LIMIT :limit OFFSET :offset", params);
        return Db.page(items, total, page, size);
    }

    public Map<String, Object> adminUpdate(String id, Map<String, Object> body, String actorId, SessionService.LoginMeta meta) {
        Map<String, Object> identity = get(id);
        String tenant = String.valueOf(identity.get("tenant_id"));
        db.inTx(() -> {
            if (body.get("display_name") != null) {
                db.update("UPDATE identities SET display_name = :v, updated_at = now(), version = version + 1 WHERE id = :id",
                        Db.params("v", str(body.get("display_name")), "id", id));
            }
            if (body.get("avatar_url") != null) {
                db.update("UPDATE identities SET avatar_url = :v, updated_at = now(), version = version + 1 WHERE id = :id",
                        Db.params("v", str(body.get("avatar_url")), "id", id));
            }
            if (body.get("mfa_enforced") != null) {
                db.update("UPDATE identities SET mfa_enforced = :v, updated_at = now() WHERE id = :id",
                        Db.params("v", Boolean.TRUE.equals(body.get("mfa_enforced")), "id", id));
            }
            if (body.get("email") != null) {
                String email = normalizeEmail(str(body.get("email")));
                assertUnique(tenant, null, email, null, id);
                db.update("UPDATE identities SET email = :v, email_verified = FALSE, updated_at = now() WHERE id = :id",
                        Db.params("v", email, "id", id));
                db.update("DELETE FROM identity_identifiers WHERE identity_id = :id AND kind = 'email'", Db.params("id", id));
                insertIdentifier(id, tenant, "email", email);
            }
            if (body.get("phone") != null) {
                String phone = normalizePhone(str(body.get("phone")));
                assertUnique(tenant, null, null, phone, id);
                db.update("UPDATE identities SET phone = :v, phone_verified = FALSE, updated_at = now() WHERE id = :id",
                        Db.params("v", phone, "id", id));
                db.update("DELETE FROM identity_identifiers WHERE identity_id = :id AND kind = 'phone'", Db.params("id", id));
                insertIdentifier(id, tenant, "phone", phone);
            }
            if (body.get("metadata") instanceof Map<?, ?> metadata) {
                db.update("UPDATE identities SET metadata = :v, updated_at = now() WHERE id = :id",
                        Db.params("v", Json.jsonb(metadata), "id", id));
            }
        });
        audit.log(tenant, actorId, "identity.updated", "identity", id, "success",
                meta.ip(), meta.userAgent(), Map.of("fields", body.keySet()));
        outbox.publish("identity.updated", "identity", id, Map.of("identity_id", id, "tenant_id", tenant));
        return get(id);
    }

    public Map<String, Object> setStatus(String id, Map<String, Object> body, String actorId,
                                         SessionService.LoginMeta meta) {
        Map<String, Object> identity = get(id);
        String tenant = String.valueOf(identity.get("tenant_id"));
        String status = str(body.get("status"));
        Set<String> allowed = Set.of("active", "pending", "disabled", "locked", "deleting", "deleted");
        if (status == null || !allowed.contains(status)) {
            throw ApiException.badRequest("非法的账户状态");
        }
        String reason = str(body.get("reason"));
        db.update("""
                UPDATE identities SET status = :status, status_reason = :reason, updated_at = now(), version = version + 1,
                failed_attempts = CASE WHEN :status = 'active' THEN 0 ELSE failed_attempts END,
                locked_until = CASE WHEN :status = 'active' THEN NULL ELSE locked_until END,
                deleted_at = CASE WHEN :status = 'deleted' THEN now() ELSE deleted_at END
                WHERE id = :id
                """, Db.params("status", status, "reason", reason, "id", id));
        if (!"active".equals(status)) {
            sessions.logoutAll(id);
        }
        audit.log(tenant, actorId, "identity.status_changed", "identity", id, "success",
                meta.ip(), meta.userAgent(), Map.of("status", status, "reason", reason == null ? "" : reason));
        Map<String, Object> statusEvent = new LinkedHashMap<>();
        statusEvent.put("identity_id", id);
        statusEvent.put("tenant_id", tenant);
        statusEvent.put("status", status);
        if (reason != null) {
            statusEvent.put("reason", reason);
        }
        outbox.publish("identity.status_changed", "identity", id, statusEvent);
        return get(id);
    }

    public List<Map<String, Object>> rolesOf(String identityId) {
        return db.list("""
                SELECT ur.id, ur.role_id, r.code, r.name, r.scope, ur.scope, ur.created_at, ur.valid_until
                FROM user_roles ur JOIN roles r ON r.id = ur.role_id
                WHERE ur.identity_id = :id AND ur.revoked_at IS NULL ORDER BY ur.created_at DESC
                """, Db.params("id", identityId));
    }

    public void revokeAllSessions(String identityId) {
        sessions.logoutAll(identityId);
    }

    public void assertUnique(String tenantId, String username, String email, String phone, String excludeId) {
        if (username != null) {
            Map<String, Object> params = new LinkedHashMap<>();
            params.put("t", tenantId);
            params.put("v", username);
            String sql = "SELECT id FROM identities WHERE tenant_id = :t AND lower(username) = lower(:v) AND deleted_at IS NULL";
            if (excludeId != null) {
                sql += " AND id <> :exclude";
                params.put("exclude", excludeId);
            }
            if (!db.list(sql, params).isEmpty()) {
                throw ApiException.conflict("用户名已被占用");
            }
        }
        if (email != null) {
            Map<String, Object> params = new LinkedHashMap<>();
            params.put("v", email);
            String sql = "SELECT id FROM identities WHERE lower(email) = lower(:v) AND deleted_at IS NULL";
            if (excludeId != null) {
                sql += " AND id <> :exclude";
                params.put("exclude", excludeId);
            }
            if (!db.list(sql, params).isEmpty()) {
                throw ApiException.conflict("邮箱已被使用");
            }
        }
        if (phone != null) {
            Map<String, Object> params = new LinkedHashMap<>();
            params.put("v", phone);
            String sql = "SELECT id FROM identities WHERE phone = :v AND deleted_at IS NULL";
            if (excludeId != null) {
                sql += " AND id <> :exclude";
                params.put("exclude", excludeId);
            }
            if (!db.list(sql, params).isEmpty()) {
                throw ApiException.conflict("手机号已被使用");
            }
        }
    }

    private void insertIdentifier(String identityId, String tenantId, String kind, String value) {
        String normalized = "email".equals(kind) ? normalizeEmail(value) : "phone".equals(kind) ? normalizePhone(value) : value;
        db.update("""
                INSERT INTO identity_identifiers (identity_id, tenant_id, kind, value, normalized_value, is_primary)
                VALUES (:id, :tenant, :kind, :value, :normalized, TRUE)
                ON CONFLICT (kind, normalized_value) DO NOTHING
                """, Db.params("id", identityId, "tenant", tenantId, "kind", kind, "value", value,
                "normalized", normalized == null ? value : normalized));
    }

    public static String normalizeEmail(String value) {
        return value == null || value.isBlank() ? null : value.trim().toLowerCase();
    }

    public static String normalizePhone(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String cleaned = value.trim().replaceAll("[\\s()-]", "");
        return cleaned.startsWith("00") ? "+" + cleaned.substring(2) : cleaned;
    }

    private static String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
