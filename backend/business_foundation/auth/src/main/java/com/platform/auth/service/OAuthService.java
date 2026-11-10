package com.platform.auth.service;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.AuditService;
import com.platform.auth.common.AuthContext;
import com.platform.auth.common.Db;
import com.platform.auth.common.Ids;
import com.platform.auth.common.Json;
import com.platform.auth.config.AppProps;
import com.platform.auth.security.JwtService;
import com.platform.auth.security.KeyService;
import com.platform.auth.security.PasswordService;
import com.platform.auth.security.Pkce;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Service
public class OAuthService {
    private final Db db;
    private final AppProps props;
    private final PasswordService passwords;
    private final JwtService jwt;
    private final KeyService keys;
    private final SessionService sessions;
    private final IdentityService identities;
    private final AuditService audit;

    public OAuthService(Db db, AppProps props, PasswordService passwords, JwtService jwt, KeyService keys,
                        SessionService sessions, IdentityService identities, AuditService audit) {
        this.db = db;
        this.props = props;
        this.passwords = passwords;
        this.jwt = jwt;
        this.keys = keys;
        this.sessions = sessions;
        this.identities = identities;
        this.audit = audit;
    }

    public Map<String, Object> client(String clientId) {
        return db.list("SELECT * FROM oauth_clients WHERE client_id = :id", Db.params("id", clientId))
                .stream().findFirst().orElseThrow(() -> ApiException.badRequest("OAuth 客户端不存在"));
    }

    public Map<String, Object> authenticateClient(String clientId, String secret) {
        Map<String, Object> client = client(clientId);
        if (!"active".equals(String.valueOf(client.get("status")))) {
            throw ApiException.badRequest("客户端已被禁用");
        }
        if ("confidential".equals(String.valueOf(client.get("kind")))) {
            String hash = client.get("client_secret_hash") == null ? null : String.valueOf(client.get("client_secret_hash"));
            if (hash == null || !passwords.matches(secret, hash)) {
                throw ApiException.unauthorized("客户端认证失败");
            }
        }
        return client;
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> authorize(AuthContext ctx, Map<String, String> params) {
        String clientId = params.get("client_id");
        String redirectUri = params.get("redirect_uri");
        String responseType = params.get("response_type");
        String scope = params.getOrDefault("scope", "openid profile email");
        String state = params.get("state");
        String nonce = params.get("nonce");
        String prompt = params.get("prompt");
        if (clientId == null || redirectUri == null) {
            throw ApiException.badRequest("缺少 client_id 或 redirect_uri");
        }
        if (!"code".equals(responseType)) {
            throw ApiException.badRequest("仅支持 authorization_code 模式");
        }
        Map<String, Object> client = client(clientId);
        if (!"active".equals(String.valueOf(client.get("status")))) {
            throw ApiException.badRequest("客户端已被禁用");
        }
        List<String> redirectUris = stringList(client.get("redirect_uris"));
        if (!redirectUris.contains(redirectUri)) {
            throw ApiException.badRequest("redirect_uri 未注册");
        }
        Set<String> requested = parseScopes(scope);
        Set<String> allowed = new LinkedHashSet<>(stringList(client.get("scopes")));
        if (!allowed.containsAll(requested)) {
            throw ApiException.badRequest("请求的 scope 超出客户端权限");
        }
        boolean requirePkce = Boolean.TRUE.equals(client.get("require_pkce"))
                || "public".equals(String.valueOf(client.get("kind")));
        if (requirePkce && params.get("code_challenge") == null) {
            throw ApiException.badRequest("该客户端必须使用 PKCE");
        }
        Map<String, Object> consent = db.list("""
                SELECT * FROM oauth_consents WHERE identity_id = :identity AND client_id = :client AND status = 'active'
                """, Db.params("identity", ctx.identityId(), "client", clientId)).stream().findFirst().orElse(null);
        boolean consented = consent != null && new LinkedHashSet<>(stringList(consent.get("scopes"))).containsAll(requested);
        if (!consented && !"none".equals(prompt)) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("consent_required", true);
            out.put("client_id", clientId);
            out.put("client_name", client.get("name"));
            out.put("scopes", requested);
            out.put("redirect_uri", redirectUri);
            out.put("state", state);
            return out;
        }
        String code = issueCode(ctx, clientId, redirectUri, requested, nonce, state,
                params.get("code_challenge"), params.get("code_challenge_method"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("code", code);
        out.put("redirect_uri", redirectUri);
        out.put("state", state);
        return out;
    }

    public Map<String, Object> consent(AuthContext ctx, Map<String, Object> body) {
        String clientId = String.valueOf(body.get("client_id"));
        String redirectUri = String.valueOf(body.get("redirect_uri"));
        Set<String> scopes = parseScopes(body.get("scope") instanceof List<?> list
                ? String.join(" ", list.stream().map(String::valueOf).toList())
                : String.valueOf(body.getOrDefault("scope", "")));
        boolean approve = !Boolean.FALSE.equals(body.get("approve"));
        Map<String, Object> client = client(clientId);
        if (!stringList(client.get("redirect_uris")).contains(redirectUri)) {
            throw ApiException.badRequest("redirect_uri 未注册");
        }
        if (!approve) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("error", "access_denied");
            out.put("redirect_uri", redirectUri);
            out.put("state", body.get("state"));
            return out;
        }
        db.update("""
                INSERT INTO oauth_consents (identity_id, client_id, tenant_id, scopes, status)
                VALUES (:identity, :client, :tenant, :scopes, 'active')
                ON CONFLICT (identity_id, client_id) WHERE status = 'active'
                DO UPDATE SET scopes = EXCLUDED.scopes, updated_at = now()
                """, Db.params("identity", ctx.identityId(), "client", clientId, "tenant", ctx.tenantId(),
                "scopes", Json.jsonb(scopes)));
        String code = issueCode(ctx, clientId, redirectUri, scopes,
                body.get("nonce") == null ? null : String.valueOf(body.get("nonce")),
                body.get("state") == null ? null : String.valueOf(body.get("state")),
                body.get("code_challenge") == null ? null : String.valueOf(body.get("code_challenge")),
                body.get("code_challenge_method") == null ? null : String.valueOf(body.get("code_challenge_method")));
        audit.log(ctx.tenantId(), ctx.identityId(), "oauth.consent_granted", "oauth_client", clientId, "success",
                null, null, Map.of("scopes", scopes));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("code", code);
        out.put("redirect_uri", redirectUri);
        out.put("state", body.get("state"));
        return out;
    }

    private String issueCode(AuthContext ctx, String clientId, String redirectUri, Set<String> scopes,
                             String nonce, String state, String challenge, String method) {
        String code = Ids.randomToken(32);
        db.update("""
                INSERT INTO authorization_codes
                (code_hash, client_id, tenant_id, identity_id, session_id, redirect_uri, scope, nonce, state,
                 code_challenge, code_challenge_method, amr, acr, expires_at)
                VALUES (:hash, :client, :tenant, :identity, :session, :redirect, :scope, :nonce, :state,
                        :challenge, :method, :amr, :acr, now() + (:ttl || ' seconds')::interval)
                """, Db.params("hash", Ids.sha256(code), "client", clientId, "tenant", ctx.tenantId(),
                "identity", ctx.identityId(), "session", ctx.sessionId(), "redirect", redirectUri,
                "scope", String.join(" ", scopes), "nonce", nonce, "state", state,
                "challenge", challenge, "method", method == null ? "S256" : method,
                "amr", Json.write(List.copyOf(ctx.amr())), "acr", ctx.acr(),
                "ttl", String.valueOf(props.getCodeTtl())));
        return code;
    }

    public Map<String, Object> token(Map<String, String> form, SessionService.LoginMeta meta) {
        String grantType = form.get("grant_type");
        if (grantType == null) {
            throw ApiException.badRequest("缺少 grant_type");
        }
        Map<String, Object> client = authenticateClient(form.get("client_id"), form.get("client_secret"));
        String clientId = String.valueOf(client.get("client_id"));
        return switch (grantType) {
            case "authorization_code" -> authorizationCode(form, client, meta);
            case "refresh_token" -> {
                Map<String, Object> tokens = sessions.refresh(form.get("refresh_token"), clientId, meta);
                audit.log(null, null, "oauth.refresh", "oauth_client", clientId, "success",
                        meta.ip(), meta.userAgent(), Map.of());
                yield tokens;
            }
            case "client_credentials" -> clientCredentials(form, client);
            default -> throw ApiException.badRequest("不支持的 grant_type");
        };
    }

    private Map<String, Object> authorizationCode(Map<String, String> form, Map<String, Object> client,
                                                  SessionService.LoginMeta meta) {
        String code = form.get("code");
        if (code == null) {
            throw ApiException.badRequest("缺少授权码");
        }
        Map<String, Object> row = db.list("""
                SELECT * FROM authorization_codes WHERE code_hash = :hash
                """, Db.params("hash", Ids.sha256(code))).stream().findFirst()
                .orElseThrow(() -> ApiException.badRequest("授权码无效"));
        if (row.get("consumed_at") != null) {
            throw ApiException.badRequest("授权码已被使用");
        }
        if (Instant.parse(String.valueOf(row.get("expires_at"))).isBefore(Instant.now())) {
            throw ApiException.badRequest("授权码已过期");
        }
        if (!String.valueOf(client.get("client_id")).equals(String.valueOf(row.get("client_id")))) {
            throw ApiException.badRequest("授权码与客户端不匹配");
        }
        if (form.get("redirect_uri") != null && !form.get("redirect_uri").equals(String.valueOf(row.get("redirect_uri")))) {
            throw ApiException.badRequest("redirect_uri 不匹配");
        }
        Pkce.verify(str(row.get("code_challenge")), str(row.get("code_challenge_method")), form.get("code_verifier"));
        db.update("UPDATE authorization_codes SET consumed_at = now() WHERE id = :id", Db.params("id", row.get("id")));
        String identityId = String.valueOf(row.get("identity_id"));
        Map<String, Object> identity = identities.get(identityId);
        Map<String, Object> idClaims = new LinkedHashMap<>();
        idClaims.put("nonce", row.get("nonce"));
        idClaims.put("auth_time", Instant.now().getEpochSecond());
        idClaims.put("name", identity.get("display_name"));
        idClaims.put("preferred_username", identity.get("username"));
        idClaims.put("email", identity.get("email"));
        idClaims.put("email_verified", identity.get("email_verified"));
        Map<String, Object> tokens = sessions.tokensFor(identityId, String.valueOf(row.get("tenant_id")),
                String.valueOf(row.get("session_id")), String.valueOf(row.get("client_id")),
                String.valueOf(row.get("scope")), stringList(row.get("amr")), String.valueOf(row.get("acr")),
                idClaims, true);
        tokens.remove("session_id");
        audit.log(String.valueOf(row.get("tenant_id")), identityId, "oauth.token_issued", "oauth_client",
                String.valueOf(row.get("client_id")), "success", meta.ip(), meta.userAgent(), Map.of());
        return tokens;
    }

    private Map<String, Object> clientCredentials(Map<String, String> form, Map<String, Object> client) {
        String clientId = String.valueOf(client.get("client_id"));
        Set<String> requested = parseScopes(form.getOrDefault("scope", String.join(" ", stringList(client.get("scopes")))));
        Set<String> allowed = new LinkedHashSet<>(stringList(client.get("scopes")));
        if (!allowed.containsAll(requested)) {
            throw ApiException.badRequest("请求的 scope 超出客户端权限");
        }
        String tenant = String.valueOf(client.get("tenant_id"));
        String access = jwt.signAccess(clientId, tenant, null, clientId, String.join(" ", requested),
                List.of("client_credentials"), "urn:auth:acr:client", props.getAccessTokenTtl(),
                List.of(), List.of(), Map.of("client_credentials", true));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("access_token", access);
        out.put("token_type", "Bearer");
        out.put("expires_in", props.getAccessTokenTtl());
        out.put("scope", String.join(" ", requested));
        return out;
    }

    public Map<String, Object> userinfo(String bearer) {
        Map<String, Object> claims = jwt.verify(bearer, "access");
        String identityId = str(claims.get("sub"));
        Map<String, Object> identity = identities.get(identityId);
        Set<String> scopes = parseScopes(str(claims.get("scope")));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sub", identityId);
        if (scopes.contains("profile")) {
            out.put("name", identity.get("display_name"));
            out.put("preferred_username", identity.get("username"));
            out.put("picture", identity.get("avatar_url"));
        }
        if (scopes.contains("email")) {
            out.put("email", identity.get("email"));
            out.put("email_verified", identity.get("email_verified"));
        }
        if (scopes.contains("phone")) {
            out.put("phone_number", identity.get("phone"));
            out.put("phone_number_verified", identity.get("phone_verified"));
        }
        return out;
    }

    public Map<String, Object> introspect(String token) {
        Map<String, Object> out = new LinkedHashMap<>();
        try {
            Map<String, Object> claims = jwt.verify(token, "access");
            out.put("active", true);
            out.putAll(claims);
            return out;
        } catch (Exception ignored) {
        }
        Map<String, Object> refresh = db.list("SELECT * FROM refresh_tokens WHERE token_hash = :hash",
                        Db.params("hash", Ids.sha256(token))).stream().findFirst().orElse(null);
        if (refresh != null && "active".equals(String.valueOf(refresh.get("status")))
                && Instant.parse(String.valueOf(refresh.get("expires_at"))).isAfter(Instant.now())) {
            out.put("active", true);
            out.put("token_type", "refresh_token");
            out.put("client_id", refresh.get("client_id"));
            out.put("sub", refresh.get("identity_id"));
            out.put("scope", refresh.get("scope"));
            out.put("exp", Instant.parse(String.valueOf(refresh.get("expires_at"))).getEpochSecond());
            return out;
        }
        out.put("active", false);
        return out;
    }

    public void revoke(String token, String clientId) {
        Map<String, Object> refresh = db.list("SELECT * FROM refresh_tokens WHERE token_hash = :hash",
                Db.params("hash", Ids.sha256(token))).stream().findFirst().orElse(null);
        if (refresh != null) {
            db.update("UPDATE refresh_tokens SET status = 'revoked', revoked_at = now() WHERE family_id = :family",
                    Db.params("family", refresh.get("family_id")));
            return;
        }
        try {
            Map<String, Object> claims = jwt.verify(token, "access");
            String sid = str(claims.get("sid"));
            if (sid != null) {
                sessions.revokeSessionById(sid, "token_revoked");
            }
        } catch (Exception ignored) {
            // RFC 7009：无效令牌同样返回成功
        }
    }

    public Map<String, Object> endSession(Map<String, String> params) {
        String sessionId = null;
        if (params.get("id_token_hint") != null) {
            try {
                sessionId = str(jwt.verify(params.get("id_token_hint"), "id").get("sid"));
            } catch (Exception ignored) {
            }
        }
        if (sessionId == null && params.get("session_id") != null) {
            sessionId = params.get("session_id");
        }
        if (sessionId != null) {
            sessions.revokeSessionById(sessionId, "end_session");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        String redirect = params.get("post_logout_redirect_uri");
        if (redirect != null) {
            out.put("redirect_uri", redirect);
            if (params.get("state") != null) {
                out.put("state", params.get("state"));
            }
        }
        out.put("logged_out", true);
        return out;
    }

    public Map<String, Object> discovery() {
        Map<String, Object> out = new LinkedHashMap<>();
        String issuer = props.getIssuer();
        out.put("issuer", issuer);
        out.put("authorization_endpoint", issuer + "/oauth2/authorize");
        out.put("token_endpoint", issuer + "/oauth2/token");
        out.put("userinfo_endpoint", issuer + "/oauth2/userinfo");
        out.put("jwks_uri", issuer + "/oauth2/jwks");
        out.put("end_session_endpoint", issuer + "/oauth2/logout");
        out.put("introspection_endpoint", issuer + "/oauth2/introspect");
        out.put("revocation_endpoint", issuer + "/oauth2/revoke");
        out.put("response_types_supported", List.of("code"));
        out.put("grant_types_supported", List.of("authorization_code", "refresh_token", "client_credentials"));
        out.put("subject_types_supported", List.of("public"));
        out.put("id_token_signing_alg_values_supported", List.of("RS256"));
        out.put("scopes_supported", List.of("openid", "profile", "email", "phone", "offline_access", "internal"));
        out.put("token_endpoint_auth_methods_supported", List.of("client_secret_basic", "client_secret_post"));
        out.put("code_challenge_methods_supported", List.of("S256", "plain"));
        out.put("claims_supported", List.of("sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
                "name", "preferred_username", "email", "email_verified", "phone_number", "phone_number_verified"));
        return out;
    }

    public Map<String, Object> jwks() {
        return keys.jwks();
    }

    public Map<String, Object> listClients(int page, int size, String keyword) {
        Map<String, Object> params = new LinkedHashMap<>();
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        if (keyword != null && !keyword.isBlank()) {
            where.append(" AND (lower(client_id) LIKE lower(:kw) OR lower(name) LIKE lower(:kw))");
            params.put("kw", "%" + keyword + "%");
        }
        long total = db.count("SELECT count(*) FROM oauth_clients" + where, params);
        params.put("limit", size);
        params.put("offset", (page - 1) * size);
        List<Map<String, Object>> items = db.list("""
                SELECT id, tenant_id, client_id, name, description, kind, redirect_uris, post_logout_redirect_uris,
                       grant_types, scopes, status, require_pkce, access_token_ttl_secs, refresh_token_ttl_secs,
                       id_token_ttl_secs, metadata, created_at, updated_at
                FROM oauth_clients""" + where + " ORDER BY created_at DESC LIMIT :limit OFFSET :offset", params);
        return Db.page(items, total, page, size);
    }

    public Map<String, Object> createClient(Map<String, Object> body) {
        String clientId = body.get("client_id") == null ? "client-" + Ids.randomToken(12) : String.valueOf(body.get("client_id"));
        if (db.list("SELECT id FROM oauth_clients WHERE client_id = :id", Db.params("id", clientId)).size() > 0) {
            throw ApiException.conflict("client_id 已存在");
        }
        String secret = body.get("client_secret") == null ? Ids.randomToken(32) : String.valueOf(body.get("client_secret"));
        String kind = body.getOrDefault("kind", "confidential").toString();
        db.update("""
                INSERT INTO oauth_clients
                (tenant_id, client_id, client_secret_hash, name, description, kind, redirect_uris,
                 post_logout_redirect_uris, grant_types, scopes, require_pkce, access_token_ttl_secs,
                 refresh_token_ttl_secs, id_token_ttl_secs)
                VALUES (:tenant, :client, :hash, :name, :description, :kind, :redirect_uris, :logout_uris,
                        :grants, :scopes, :pkce, :access_ttl, :refresh_ttl, :id_ttl)
                """, Db.params("tenant", body.getOrDefault("tenant_id", IdentityService.DEFAULT_TENANT),
                "client", clientId, "hash", "confidential".equals(kind) ? passwords.hash(secret) : null,
                "name", body.getOrDefault("name", clientId), "description", body.get("description"),
                "kind", kind,
                "redirect_uris", Json.jsonb(body.getOrDefault("redirect_uris", List.of())),
                "logout_uris", Json.jsonb(body.getOrDefault("post_logout_redirect_uris", List.of())),
                "grants", Json.jsonb(body.getOrDefault("grant_types", List.of("authorization_code", "refresh_token"))),
                "scopes", Json.jsonb(body.getOrDefault("scopes", List.of("openid", "profile", "email"))),
                "pkce", body.get("require_pkce") == null || Boolean.TRUE.equals(body.get("require_pkce")),
                "access_ttl", body.get("access_token_ttl_secs"), "refresh_ttl", body.get("refresh_token_ttl_secs"),
                "id_ttl", body.get("id_token_ttl_secs")));
        Map<String, Object> out = new LinkedHashMap<>(client(clientId));
        out.remove("client_secret_hash");
        if ("confidential".equals(kind)) {
            out.put("client_secret", secret);
        }
        return out;
    }

    public Map<String, Object> updateClient(String clientId, Map<String, Object> body) {
        client(clientId);
        db.update("""
                UPDATE oauth_clients SET
                    name = COALESCE(:name, name), description = COALESCE(:description, description),
                    redirect_uris = COALESCE(:redirect_uris, redirect_uris),
                    post_logout_redirect_uris = COALESCE(:logout_uris, post_logout_redirect_uris),
                    grant_types = COALESCE(:grants, grant_types), scopes = COALESCE(:scopes, scopes),
                    require_pkce = COALESCE(:pkce, require_pkce), updated_at = now()
                WHERE client_id = :client
                """, Db.params("name", body.get("name"), "description", body.get("description"),
                "redirect_uris", body.get("redirect_uris") == null ? null : Json.jsonb(body.get("redirect_uris")),
                "logout_uris", body.get("post_logout_redirect_uris") == null ? null : Json.jsonb(body.get("post_logout_redirect_uris")),
                "grants", body.get("grant_types") == null ? null : Json.jsonb(body.get("grant_types")),
                "scopes", body.get("scopes") == null ? null : Json.jsonb(body.get("scopes")),
                "pkce", body.get("require_pkce"), "client", clientId));
        return client(clientId);
    }

    public Map<String, Object> rotateSecret(String clientId) {
        Map<String, Object> client = client(clientId);
        if (!"confidential".equals(String.valueOf(client.get("kind")))) {
            throw ApiException.badRequest("公共客户端没有密钥");
        }
        String secret = Ids.randomToken(32);
        db.update("UPDATE oauth_clients SET client_secret_hash = :hash, updated_at = now() WHERE client_id = :client",
                Db.params("hash", passwords.hash(secret), "client", clientId));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("client_id", clientId);
        out.put("client_secret", secret);
        return out;
    }

    public Map<String, Object> setClientStatus(String clientId, String status) {
        if (!Set.of("active", "disabled").contains(status)) {
            throw ApiException.badRequest("非法的客户端状态");
        }
        db.update("UPDATE oauth_clients SET status = :status, updated_at = now() WHERE client_id = :client",
                Db.params("status", status, "client", clientId));
        return client(clientId);
    }

    public List<Map<String, Object>> listScopes() {
        return db.list("SELECT * FROM oauth_scopes ORDER BY name");
    }

    public Map<String, Object> createScope(Map<String, Object> body) {
        String name = String.valueOf(body.get("name"));
        db.update("""
                INSERT INTO oauth_scopes (tenant_id, name, description, is_default)
                VALUES (:tenant, :name, :description, :default)
                ON CONFLICT (tenant_id, name) DO UPDATE SET description = EXCLUDED.description
                """, Db.params("tenant", body.getOrDefault("tenant_id", IdentityService.DEFAULT_TENANT),
                "name", name, "description", body.get("description"),
                "default", Boolean.TRUE.equals(body.get("is_default"))));
        return db.one("SELECT * FROM oauth_scopes WHERE name = :name AND tenant_id = :tenant",
                Db.params("name", name, "tenant", body.getOrDefault("tenant_id", IdentityService.DEFAULT_TENANT)));
    }

    public void deleteScope(String name) {
        db.update("DELETE FROM oauth_scopes WHERE name = :name", Db.params("name", name));
    }

    public static Set<String> parseScopes(String scope) {
        Set<String> out = new LinkedHashSet<>();
        if (scope != null) {
            for (String value : scope.trim().split("\\s+")) {
                if (!value.isBlank()) {
                    out.add(value);
                }
            }
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    public static List<String> stringList(Object value) {
        if (value instanceof List<?> list) {
            return list.stream().map(String::valueOf).toList();
        }
        if (value instanceof String text) {
            return new ArrayList<>(parseScopes(text));
        }
        return List.of();
    }

    private static String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }
}
