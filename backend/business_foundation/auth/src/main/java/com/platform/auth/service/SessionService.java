package com.platform.auth.service;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.AuthContext;
import com.platform.auth.common.Db;
import com.platform.auth.common.Ids;
import com.platform.auth.common.Json;
import com.platform.auth.config.AppProps;
import com.platform.auth.security.JwtService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Service
public class SessionService {
    private final Db db;
    private final AppProps props;
    private final JwtService jwt;
    private final RbacService rbac;

    public SessionService(Db db, AppProps props, JwtService jwt, RbacService rbac) {
        this.db = db;
        this.props = props;
        this.jwt = jwt;
        this.rbac = rbac;
    }

    public Map<String, Object> issue(String identityId, String tenantId, String clientId, String scope,
                                     List<String> amr, String acr, LoginMeta meta, Map<String, Object> idClaims) {
        String sessionId = Ids.uuidStr();
        db.update("""
                INSERT INTO auth_sessions
                (id, identity_id, tenant_id, client_id, ip, user_agent, device_id, device_name, amr, acr, expires_at)
                VALUES (:id, :identity, :tenant, :client, :ip, :ua, :device, :device_name,
                        CAST(:amr AS jsonb), :acr, now() + (:ttl || ' seconds')::interval)
                """, Db.params("id", sessionId, "identity", identityId, "tenant", tenantId, "client", clientId,
                "ip", meta.ip(), "ua", meta.userAgent(), "device", meta.deviceId(),
                "device_name", meta.deviceName(), "amr", Json.write(amr == null ? List.of("pwd") : amr),
                "acr", acr == null ? "urn:auth:acr:pwd" : acr, "ttl", String.valueOf(props.getSessionTtl())));
        return tokensFor(identityId, tenantId, sessionId, clientId, scope, amr, acr, idClaims, true);
    }

    public Map<String, Object> tokensFor(String identityId, String tenantId, String sessionId, String clientId,
                                         String scope, List<String> amr, String acr,
                                         Map<String, Object> idClaims, boolean withRefresh) {
        var roles = rbac.roleCodes(identityId, tenantId);
        var perms = rbac.permissions(identityId, tenantId);
        String access = jwt.signAccess(identityId, tenantId, sessionId, clientId,
                scope, amr, acr, props.getAccessTokenTtl(), List.copyOf(roles), List.copyOf(perms), null);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("access_token", access);
        out.put("token_type", "Bearer");
        out.put("expires_in", props.getAccessTokenTtl());
        out.put("scope", scope == null ? "" : scope);
        out.put("session_id", sessionId);
        if (withRefresh) {
            String raw = Ids.randomToken(48);
            String refreshId = Ids.uuidStr();
            db.update("""
                    INSERT INTO refresh_tokens
                    (id, session_id, identity_id, tenant_id, client_id, token_hash, family_id, scope, expires_at)
                    VALUES (:id, :session, :identity, :tenant, :client, :hash, :family, :scope,
                            now() + (:ttl || ' seconds')::interval)
                    """, Db.params("id", refreshId, "session", sessionId, "identity", identityId,
                    "tenant", tenantId, "client", clientId == null ? "auth-console" : clientId,
                    "hash", Ids.sha256(raw), "family", Ids.uuid(), "scope", scope == null ? "" : scope,
                    "ttl", String.valueOf(props.getRefreshTokenTtl())));
            out.put("refresh_token", raw);
            out.put("refresh_expires_in", props.getRefreshTokenTtl());
        }
        if (idClaims != null) {
            out.put("id_token", jwt.signIdToken(identityId, tenantId, sessionId, clientId,
                    idClaims.get("nonce") == null ? null : String.valueOf(idClaims.get("nonce")),
                    idClaims.get("auth_time") instanceof Number n ? n.longValue() : Instant.now().getEpochSecond(),
                    idClaims));
        }
        return out;
    }

    public Map<String, Object> refresh(String rawToken, String clientId, LoginMeta meta) {
        Map<String, Object> row = db.list("""
                SELECT * FROM refresh_tokens WHERE token_hash = :hash
                """, Db.params("hash", Ids.sha256(rawToken))).stream().findFirst()
                .orElseThrow(() -> ApiException.unauthorized("刷新令牌无效"));
        String status = String.valueOf(row.get("status"));
        if (!"active".equals(status)) {
            db.update("UPDATE auth_sessions SET status = 'revoked', revoked_at = now(), revoke_reason = 'refresh_token_reuse' "
                    + "WHERE id = :session", Db.params("session", row.get("session_id")));
            db.update("UPDATE refresh_tokens SET status = 'revoked', revoked_at = now() WHERE family_id = :family",
                    Db.params("family", row.get("family_id")));
            throw ApiException.unauthorized("刷新令牌已被使用，会话已终止");
        }
        if (Instant.parse(String.valueOf(row.get("expires_at"))).isBefore(Instant.now())) {
            db.update("UPDATE refresh_tokens SET status = 'expired' WHERE id = :id", Db.params("id", row.get("id")));
            throw ApiException.unauthorized("刷新令牌已过期");
        }
        if (clientId != null && !clientId.equals(String.valueOf(row.get("client_id")))) {
            throw ApiException.unauthorized("刷新令牌与客户端不匹配");
        }
        Map<String, Object> session = db.one("SELECT * FROM auth_sessions WHERE id = :id",
                Db.params("id", row.get("session_id")));
        if (!"active".equals(String.valueOf(session.get("status")))) {
            throw ApiException.unauthorized("会话已失效");
        }
        String newRaw = Ids.randomToken(48);
        String newId = Ids.uuidStr();
        db.inTx(() -> {
            db.update("UPDATE refresh_tokens SET status = 'rotated', rotated_at = now() WHERE id = :id",
                    Db.params("id", row.get("id")));
            db.update("""
                    INSERT INTO refresh_tokens
                    (id, session_id, identity_id, tenant_id, client_id, token_hash, family_id, previous_id, scope, expires_at)
                    VALUES (:id, :session, :identity, :tenant, :client, :hash, :family, :prev, :scope,
                            now() + (:ttl || ' seconds')::interval)
                    """, Db.params("id", newId, "session", row.get("session_id"), "identity", row.get("identity_id"),
                    "tenant", row.get("tenant_id"), "client", row.get("client_id"), "hash", Ids.sha256(newRaw),
                    "family", row.get("family_id"), "prev", row.get("id"), "scope", row.get("scope"),
                    "ttl", String.valueOf(props.getRefreshTokenTtl())));
            db.update("UPDATE auth_sessions SET last_seen_at = now(), ip = COALESCE(:ip, ip), user_agent = COALESCE(:ua, user_agent) WHERE id = :id",
                    Db.params("ip", meta.ip(), "ua", meta.userAgent(), "id", row.get("session_id")));
        });
        String tenantId = String.valueOf(row.get("tenant_id"));
        String identityId = String.valueOf(row.get("identity_id"));
        String sid = String.valueOf(row.get("session_id"));
        List<String> amr = Json.readMap(session.get("amr")) == null ? List.of("pwd") : stringList(session.get("amr"));
        Map<String, Object> out = tokensFor(identityId, tenantId, sid, String.valueOf(row.get("client_id")),
                String.valueOf(row.get("scope")), amr, String.valueOf(session.get("acr")), null, false);
        out.put("refresh_token", newRaw);
        out.put("refresh_expires_in", props.getRefreshTokenTtl());
        return out;
    }

    @SuppressWarnings("unchecked")
    private List<String> stringList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        return List.of("pwd");
    }

    public boolean active(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return false;
        }
        Map<String, Object> row = db.list("""
                SELECT status, expires_at FROM auth_sessions WHERE id = :id
                """, Db.params("id", sessionId)).stream().findFirst().orElse(null);
        return row != null && "active".equals(String.valueOf(row.get("status")))
                && Instant.parse(String.valueOf(row.get("expires_at"))).isAfter(Instant.now());
    }

    public void logoutAll(String identityId) {
        db.list("SELECT id FROM auth_sessions WHERE identity_id = :id AND status = 'active'",
                        Db.params("id", identityId))
                .forEach(s -> revokeSessionById(String.valueOf(s.get("id")), "admin_action"));
    }

    public void logout(AuthContext ctx, boolean allDevices, String deviceId) {
        Map<String, Object> params = new LinkedHashMap<>();
        StringBuilder where = new StringBuilder("identity_id = :identity AND status = 'active'");
        params.put("identity", ctx.identityId());
        if (deviceId != null) {
            where.append(" AND device_id = :device");
            params.put("device", deviceId);
        } else if (!allDevices) {
            where.append(" AND id = :sid");
            params.put("sid", ctx.sessionId());
        }
        List<Map<String, Object>> sessions = db.list("SELECT id FROM auth_sessions WHERE " + where, params);
        for (Map<String, Object> session : sessions) {
            revokeSessionById(String.valueOf(session.get("id")), "logout");
        }
    }

    public void revokeSessionById(String sessionId, String reason) {
        db.inTx(() -> {
            db.update("UPDATE auth_sessions SET status = 'revoked', revoked_at = now(), revoke_reason = :reason WHERE id = :id",
                    Db.params("id", sessionId, "reason", reason));
            db.update("UPDATE refresh_tokens SET status = 'revoked', revoked_at = now() WHERE session_id = :id AND status = 'active'",
                    Db.params("id", sessionId));
        });
    }

    public void revokeSession(String identityId, String sessionId) {
        Map<String, Object> row = db.list("SELECT id FROM auth_sessions WHERE id = :id AND identity_id = :identity",
                Db.params("id", sessionId, "identity", identityId)).stream().findFirst()
                .orElseThrow(() -> ApiException.notFound("会话不存在"));
        revokeSessionById(String.valueOf(row.get("id")), "user_revoked");
    }

    public void revokeDevice(String identityId, String deviceId) {
        db.list("SELECT id FROM auth_sessions WHERE identity_id = :identity AND device_id = :device AND status = 'active'",
                Db.params("identity", identityId, "device", deviceId))
                .forEach(s -> revokeSessionById(String.valueOf(s.get("id")), "device_revoked"));
    }

    public List<Map<String, Object>> list(String identityId) {
        return db.list("""
                SELECT id, client_id, status, ip, user_agent, device_id, device_name, amr, acr,
                       created_at, last_seen_at, expires_at, revoked_at, revoke_reason
                FROM auth_sessions WHERE identity_id = :id ORDER BY last_seen_at DESC
                """, Db.params("id", identityId));
    }

    public void renameDevice(String identityId, String sessionId, String deviceName) {
        int updated = db.update("UPDATE auth_sessions SET device_name = :name WHERE id = :id AND identity_id = :identity",
                Db.params("name", deviceName, "id", sessionId, "identity", identityId));
        if (updated == 0) {
            throw ApiException.notFound("会话不存在");
        }
    }

    public List<Map<String, Object>> history(String identityId) {
        return db.list("""
                SELECT id, client_id, status, ip, user_agent, device_name, created_at, last_seen_at, revoked_at
                FROM auth_sessions WHERE identity_id = :id ORDER BY created_at DESC LIMIT 200
                """, Db.params("id", identityId));
    }

    /**
     * 异常登录检测：近 90 天内首次出现的 IP + 设备组合视为异常登录。
     */
    public List<Map<String, Object>> anomalies(String identityId) {
        List<Map<String, Object>> history = db.list("""
                SELECT id, client_id, ip, user_agent, device_id, device_name, created_at
                FROM auth_sessions
                WHERE identity_id = :id AND created_at > now() - interval '90 days'
                ORDER BY created_at ASC LIMIT 500
                """, Db.params("id", identityId));
        java.util.Set<String> seen = new java.util.HashSet<>();
        List<Map<String, Object>> out = new java.util.ArrayList<>();
        for (Map<String, Object> row : history) {
            String key = row.get("ip") + "|" + row.get("device_id");
            if (!seen.isEmpty() && !seen.contains(key)) {
                Map<String, Object> item = new LinkedHashMap<>(row);
                item.put("reason", "new_device_or_ip");
                out.add(item);
            }
            seen.add(key);
        }
        java.util.Collections.reverse(out);
        return out;
    }

    public record LoginMeta(String ip, String userAgent, String deviceId, String deviceName, String traceId) {}
}
