package com.platform.auth.service;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.AuditService;
import com.platform.auth.common.AuthContext;
import com.platform.auth.common.Db;
import com.platform.auth.common.Ids;
import com.platform.auth.common.Json;
import com.platform.auth.common.OutboxService;
import com.platform.auth.config.AppProps;
import com.platform.auth.security.CryptoBox;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class FederationService {
    private final Db db;
    private final AppProps props;
    private final CryptoBox crypto;
    private final IdentityService identities;
    private final SessionService sessions;
    private final AuditService audit;
    private final OutboxService outbox;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final Map<String, State> states = new ConcurrentHashMap<>();

    public FederationService(Db db, AppProps props, CryptoBox crypto, IdentityService identities,
                             SessionService sessions, AuditService audit, OutboxService outbox) {
        this.db = db;
        this.props = props;
        this.crypto = crypto;
        this.identities = identities;
        this.sessions = sessions;
        this.audit = audit;
        this.outbox = outbox;
    }

    public List<Map<String, Object>> providers() {
        return db.list("""
                SELECT id, code, name, kind, enabled, issuer, authorization_endpoint, token_endpoint,
                       userinfo_endpoint, jwks_uri, client_id, redirect_uri, scopes, attribute_mapping,
                       auto_register, link_by_verified_email, created_at, updated_at
                FROM identity_providers ORDER BY code
                """);
    }

    public Map<String, Object> provider(String code) {
        return db.list("SELECT * FROM identity_providers WHERE code = :code", Db.params("code", code))
                .stream().findFirst().orElseThrow(() -> ApiException.notFound("身份提供商不存在"));
    }

    public Map<String, Object> start(String providerCode, Map<String, Object> body) {
        Map<String, Object> provider = provider(providerCode);
        if (!Boolean.TRUE.equals(provider.get("enabled"))) {
            throw ApiException.badRequest("身份提供商已禁用");
        }
        String redirectUri = body.get("redirect_uri") == null
                ? props.getBaseUrl() + "/api/v1/auth/federated/" + providerCode + "/callback"
                : String.valueOf(body.get("redirect_uri"));
        String state = Ids.randomToken(32);
        String nonce = Ids.randomToken(16);
        states.put(state, new State(providerCode, redirectUri,
                body.get("final_redirect") == null ? null : String.valueOf(body.get("final_redirect")),
                nonce, Instant.now().plusSeconds(600)));
        String authorizeUrl = endpoint(provider, "authorization_endpoint", defaults(providerCode).authorize());
        String scopes = scopeString(provider.get("scopes"));
        StringBuilder url = new StringBuilder(authorizeUrl);
        url.append(authorizeUrl.contains("?") ? "&" : "?");
        append(url, "response_type", "code");
        append(url, "client_id", String.valueOf(provider.get("client_id")));
        append(url, "redirect_uri", redirectUri);
        append(url, "scope", scopes);
        append(url, "state", state);
        if ("oidc".equals(String.valueOf(provider.get("kind"))) || "apple".equals(providerCode)) {
            append(url, "nonce", nonce);
        }
        if ("apple".equals(providerCode)) {
            append(url, "response_mode", "form_post");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("authorization_url", url.toString());
        out.put("state", state);
        return out;
    }

    public Map<String, Object> callback(String providerCode, String code, String state,
                                        SessionService.LoginMeta meta) {
        State saved = states.remove(state);
        if (saved == null || saved.expiresAt.isBefore(Instant.now())) {
            throw ApiException.badRequest("授权状态无效或已过期");
        }
        Map<String, Object> provider = provider(providerCode);
        Map<String, Object> tokenResponse = exchange(provider, code, saved.redirectUri);
        String accessToken = str(tokenResponse.get("access_token"));
        Map<String, Object> profile = new LinkedHashMap<>();
        String idToken = str(tokenResponse.get("id_token"));
        if (idToken != null) {
            profile.putAll(parseIdToken(idToken));
        }
        String userinfoUrl = endpoint(provider, "userinfo_endpoint", defaults(providerCode).userinfo());
        if (accessToken != null && userinfoUrl != null) {
            Map<String, Object> userinfo = getJson(userinfoUrl, accessToken);
            userinfo.forEach(profile::putIfAbsent);
        }
        if ("github".equals(providerCode) && profile.get("email") == null && accessToken != null) {
            List<Map<String, Object>> emails = getJsonList("https://api.github.com/user/emails", accessToken);
            emails.stream().filter(e -> Boolean.TRUE.equals(e.get("primary"))).findFirst()
                    .ifPresent(e -> profile.put("email", e.get("email")));
        }
        String subject = first(profile, "sub", "id", "user_id", "login");
        if (subject == null) {
            throw ApiException.badRequest("身份提供商未返回可用 subject");
        }
        String email = str(profile.get("email"));
        String displayName = first(profile, "name", "display_name", "login");

        Map<String, Object> external = db.list("""
                SELECT * FROM external_identities WHERE provider_id = :provider AND subject = :subject
                """, Db.params("provider", provider.get("id"), "subject", subject)).stream().findFirst().orElse(null);
        String identityId;
        if (external != null) {
            identityId = String.valueOf(external.get("identity_id"));
            db.update("UPDATE external_identities SET last_login_at = now(), email = :email, display_name = :name, raw = :raw WHERE id = :id",
                    Db.params("email", email, "name", displayName, "raw", Json.jsonb(profile), "id", external.get("id")));
        } else {
            Map<String, Object> linked = null;
            boolean verifiedEmail = Boolean.TRUE.equals(profile.get("email_verified")) && email != null;
            if (Boolean.TRUE.equals(provider.get("link_by_verified_email")) && verifiedEmail) {
                linked = db.list("SELECT * FROM identities WHERE lower(email) = lower(:email) AND deleted_at IS NULL",
                        Db.params("email", email)).stream().findFirst().orElse(null);
            }
            if (linked != null) {
                identityId = String.valueOf(linked.get("id"));
            } else if (Boolean.TRUE.equals(provider.get("auto_register"))) {
                String username = usernameFrom(email, displayName, subject);
                Map<String, Object> body = new LinkedHashMap<>();
                body.put("username", username);
                if (email != null) {
                    body.put("email", email);
                }
                body.put("display_name", displayName == null ? username : displayName);
                body.put("avatar_url", first(profile, "picture", "avatar_url"));
                identityId = String.valueOf(identities.create(body, String.valueOf(provider.get("tenant_id")),
                        "active", meta, "federation:" + providerCode).get("id"));
                if (email != null && verifiedEmail) {
                    db.update("UPDATE identities SET email_verified = TRUE WHERE id = :id", Db.params("id", identityId));
                }
            } else {
                throw ApiException.forbidden("外部账号未绑定，请先登录后绑定");
            }
            db.update("""
                    INSERT INTO external_identities
                    (identity_id, provider_id, provider_code, subject, email, display_name, raw, last_login_at)
                    VALUES (:identity, :provider, :code, :subject, :email, :name, :raw, now())
                    ON CONFLICT (provider_id, subject) DO NOTHING
                    """, Db.params("identity", identityId, "provider", provider.get("id"), "code", providerCode,
                    "subject", subject, "email", email, "name", displayName, "raw", Json.jsonb(profile)));
        }
        Map<String, Object> identity = identities.get(identityId);
        String tenantId = String.valueOf(identity.get("tenant_id"));
        Map<String, Object> tokens = sessions.issue(identityId, tenantId, providerCode,
                "openid profile email offline_access", List.of("federated", "pwd"), "urn:auth:acr:federated", meta, null);
        audit.log(tenantId, identityId, "auth.federated_login", "identity_provider", providerCode, "success",
                meta.ip(), meta.userAgent(), Map.of("subject", subject));
        Map<String, Object> out = new LinkedHashMap<>(tokens);
        out.put("final_redirect", saved.finalRedirect);
        out.put("provider", providerCode);
        return out;
    }

    private Map<String, Object> exchange(Map<String, Object> provider, String code, String redirectUri) {
        String tokenUrl = endpoint(provider, "token_endpoint", defaults(str(provider.get("code"))).token());
        StringBuilder form = new StringBuilder();
        append(form, "grant_type", "authorization_code");
        append(form, "code", code);
        append(form, "redirect_uri", redirectUri);
        append(form, "client_id", String.valueOf(provider.get("client_id")));
        String secret = provider.get("client_secret_encrypted") == null ? null
                : crypto.decrypt(String.valueOf(provider.get("client_secret_encrypted")));
        if (secret != null) {
            append(form, "client_secret", secret);
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(tokenUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(8))
                    .POST(HttpRequest.BodyPublishers.ofString(form.toString()))
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw ApiException.badRequest("身份提供商令牌交换失败");
            }
            return Json.readMap(response.body());
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw ApiException.badRequest("身份提供商不可达: " + e.getMessage());
        }
    }

    private Map<String, Object> getJson(String url, String accessToken) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .header("User-Agent", "auth-center")
                    .timeout(Duration.ofSeconds(8))
                    .GET().build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw ApiException.badRequest("获取第三方用户信息失败");
            }
            return Json.readMap(response.body());
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw ApiException.badRequest("身份提供商不可达");
        }
    }

    private List<Map<String, Object>> getJsonList(String url, String accessToken) {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .header("User-Agent", "auth-center")
                    .timeout(Duration.ofSeconds(8))
                    .GET().build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            Object parsed = Json.read(response.body());
            if (parsed instanceof List<?> list) {
                List<Map<String, Object>> out = new ArrayList<>();
                list.forEach(item -> out.add(Json.readMap(item)));
                return out;
            }
            return List.of();
        } catch (Exception e) {
            return List.of();
        }
    }

    private Map<String, Object> parseIdToken(String idToken) {
        try {
            String payload = idToken.split("\\.")[1];
            byte[] decoded = Base64.getUrlDecoder().decode(payload + "=".repeat((4 - payload.length() % 4) % 4));
            return Json.readMap(new String(decoded, StandardCharsets.UTF_8));
        } catch (Exception e) {
            return Map.of();
        }
    }

    public List<Map<String, Object>> links(String identityId) {
        return db.list("""
                SELECT id, provider_code, subject, email, display_name, linked_at, last_login_at
                FROM external_identities WHERE identity_id = :id ORDER BY linked_at DESC
                """, Db.params("id", identityId));
    }

    public void unlink(String identityId, String providerCode) {
        int count = db.update("DELETE FROM external_identities WHERE identity_id = :id AND provider_code = :code",
                Db.params("id", identityId, "code", providerCode));
        if (count == 0) {
            throw ApiException.notFound("绑定关系不存在");
        }
        audit.log(null, identityId, "federation.unlinked", "identity_provider", providerCode, "success",
                null, null, Map.of());
    }

    public Map<String, Object> createProvider(Map<String, Object> body, String actorId) {
        String code = String.valueOf(body.get("code"));
        db.update("""
                INSERT INTO identity_providers
                (tenant_id, code, name, kind, enabled, issuer, authorization_endpoint, token_endpoint,
                 userinfo_endpoint, jwks_uri, client_id, client_secret_encrypted, redirect_uri, scopes,
                 attribute_mapping, auto_register, link_by_verified_email, config)
                VALUES (:tenant, :code, :name, :kind, :enabled, :issuer, :authorize, :token, :userinfo, :jwks,
                        :client, :secret, :redirect, :scopes, :mapping, :auto, :link, :config)
                """, Db.params("tenant", body.getOrDefault("tenant_id", IdentityService.DEFAULT_TENANT),
                "code", code, "name", body.getOrDefault("name", code), "kind", body.getOrDefault("kind", "oidc"),
                "enabled", body.get("enabled") == null || Boolean.TRUE.equals(body.get("enabled")),
                "issuer", body.get("issuer"), "authorize", body.get("authorization_endpoint"),
                "token", body.get("token_endpoint"), "userinfo", body.get("userinfo_endpoint"),
                "jwks", body.get("jwks_uri"), "client", body.get("client_id"),
                "secret", body.get("client_secret") == null ? null : crypto.encrypt(String.valueOf(body.get("client_secret"))),
                "redirect", body.get("redirect_uri"), "scopes", Json.jsonb(body.getOrDefault("scopes", List.of("openid", "email", "profile"))),
                "mapping", Json.jsonb(body.getOrDefault("attribute_mapping", Map.of())),
                "auto", Boolean.TRUE.equals(body.get("auto_register")),
                "link", Boolean.TRUE.equals(body.get("link_by_verified_email")),
                "config", Json.jsonb(body.getOrDefault("config", Map.of()))));
        audit.log(null, actorId, "idp.created", "identity_provider", code, "success", null, null, Map.of());
        return provider(code);
    }

    public Map<String, Object> updateProvider(String code, Map<String, Object> body, String actorId) {
        provider(code);
        db.update("""
                UPDATE identity_providers SET
                    name = COALESCE(:name, name), enabled = COALESCE(:enabled, enabled),
                    issuer = COALESCE(:issuer, issuer),
                    authorization_endpoint = COALESCE(:authorize, authorization_endpoint),
                    token_endpoint = COALESCE(:token, token_endpoint),
                    userinfo_endpoint = COALESCE(:userinfo, userinfo_endpoint),
                    jwks_uri = COALESCE(:jwks, jwks_uri), client_id = COALESCE(:client, client_id),
                    client_secret_encrypted = COALESCE(:secret, client_secret_encrypted),
                    redirect_uri = COALESCE(:redirect, redirect_uri),
                    scopes = COALESCE(:scopes, scopes),
                    attribute_mapping = COALESCE(:mapping, attribute_mapping),
                    auto_register = COALESCE(:auto, auto_register),
                    link_by_verified_email = COALESCE(:link, link_by_verified_email),
                    config = COALESCE(:config, config), updated_at = now()
                WHERE code = :code
                """, Db.params("name", body.get("name"), "enabled", body.get("enabled"),
                "issuer", body.get("issuer"), "authorize", body.get("authorization_endpoint"),
                "token", body.get("token_endpoint"), "userinfo", body.get("userinfo_endpoint"),
                "jwks", body.get("jwks_uri"), "client", body.get("client_id"),
                "secret", body.get("client_secret") == null ? null : crypto.encrypt(String.valueOf(body.get("client_secret"))),
                "redirect", body.get("redirect_uri"),
                "scopes", body.get("scopes") == null ? null : Json.jsonb(body.get("scopes")),
                "mapping", body.get("attribute_mapping") == null ? null : Json.jsonb(body.get("attribute_mapping")),
                "auto", body.get("auto_register"), "link", body.get("link_by_verified_email"),
                "config", body.get("config") == null ? null : Json.jsonb(body.get("config")), "code", code));
        audit.log(null, actorId, "idp.updated", "identity_provider", code, "success", null, null, Map.of());
        return provider(code);
    }

    private String endpoint(Map<String, Object> provider, String field, String fallback) {
        Object value = provider.get(field);
        return value == null || String.valueOf(value).isBlank() ? fallback : String.valueOf(value);
    }

    private String scopeString(Object value) {
        List<String> scopes = OAuthService.stringList(value);
        return scopes.isEmpty() ? "openid email profile" : String.join(" ", scopes);
    }

    private static void append(StringBuilder sb, String key, String value) {
        if (value == null) {
            return;
        }
        if (sb.charAt(sb.length() - 1) != '?' && sb.charAt(sb.length() - 1) != '&') {
            sb.append('&');
        }
        sb.append(URLEncoder.encode(key, StandardCharsets.UTF_8)).append('=')
                .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
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

    private static String usernameFrom(String email, String displayName, String subject) {
        String base = email != null ? email.split("@")[0] : displayName != null ? displayName : subject;
        base = base.replaceAll("[^A-Za-z0-9_.-]", "").toLowerCase();
        if (base.length() < 3) {
            base = "user" + base;
        }
        if (base.length() > 50) {
            base = base.substring(0, 50);
        }
        return base + "_" + Ids.randomDigits(4);
    }

    private static String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    private Defaults defaults(String code) {
        return switch (code == null ? "" : code) {
            case "google" -> new Defaults("https://accounts.google.com/o/oauth2/v2/auth",
                    "https://oauth2.googleapis.com/token", "https://openidconnect.googleapis.com/v1/userinfo");
            case "github" -> new Defaults("https://github.com/login/oauth/authorize",
                    "https://github.com/login/oauth/access_token", "https://api.github.com/user");
            case "microsoft" -> new Defaults("https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
                    "https://login.microsoftonline.com/common/oauth2/v2.0/token",
                    "https://graph.microsoft.com/oidc/userinfo");
            case "apple" -> new Defaults("https://appleid.apple.com/auth/authorize",
                    "https://appleid.apple.com/auth/token", null);
            default -> new Defaults(null, null, null);
        };
    }

    private record Defaults(String authorize, String token, String userinfo) {}
    private record State(String provider, String redirectUri, String finalRedirect, String nonce, Instant expiresAt) {}
}
