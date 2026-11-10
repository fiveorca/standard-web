package com.platform.user.bootstrap;

import com.platform.user.common.ApiException;
import com.platform.user.common.AuthContext;
import com.platform.user.common.Ids;
import com.platform.user.common.Json;
import com.platform.user.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 认证中心客户端：JWKS 缓存 + RS256 验签 + authz check + 内部身份/联系人同步。
 * 认证中心不可达时统一抛出 503，绝不放行。
 */
@Component
public class AuthClient {
    private static final Logger log = LoggerFactory.getLogger(AuthClient.class);
    private static final long CLOCK_LEEWAY_SECONDS = 30;

    private final AppProperties props;
    private final HttpClient http;
    private final Map<String, PublicKey> keys = new ConcurrentHashMap<>();
    private final Map<String, Decision> decisions = new ConcurrentHashMap<>();
    private volatile long keysExpiresAt = 0;

    public AuthClient(AppProperties props) {
        this.props = props;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(Math.max(1, props.getAuth().getTimeoutSeconds())))
                .build();
    }

    // ───────────────────────── 访问令牌验签 ─────────────────────────

    public AuthContext verifyAccessToken(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            throw ApiException.invalidToken("访问令牌格式不合法");
        }
        Map<String, Object> header;
        Map<String, Object> claims;
        byte[] signature;
        try {
            header = Json.readMap(new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8));
            claims = Json.readMap(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
            signature = Base64.getUrlDecoder().decode(parts[2]);
        } catch (Exception e) {
            throw ApiException.invalidToken("访问令牌格式不合法");
        }
        String alg = header.get("alg") == null ? "" : String.valueOf(header.get("alg"));
        if (!"RS256".equals(alg)) {
            throw ApiException.invalidToken("仅支持 RS256 访问令牌");
        }
        String kid = header.get("kid") == null ? "" : String.valueOf(header.get("kid"));
        PublicKey key = key(kid);
        try {
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(key);
            verifier.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
            if (!verifier.verify(signature)) {
                throw ApiException.invalidToken("访问令牌签名无效");
            }
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw ApiException.invalidToken("访问令牌签名无效");
        }

        checkTime(claims);
        checkIssuer(claims);
        checkAudience(claims);
        checkType(claims);

        String sub = claims.get("sub") == null ? null : String.valueOf(claims.get("sub"));
        UUID identityId = Ids.parse(sub);
        if (identityId == null) {
            throw ApiException.invalidToken("访问令牌缺少有效的 sub");
        }
        UUID tenantId = Ids.parse(firstString(claims, "tenant_id", "tenantId", "tid"));
        if (tenantId == null) {
            throw ApiException.invalidToken("访问令牌缺少 tenant_id");
        }
        Object scopeClaim = claims.get("scope") != null ? claims.get("scope") : claims.get("scp");
        return new AuthContext(
                identityId,
                tenantId,
                AuthContext.stringList(claims.get("roles")),
                AuthContext.stringList(claims.get("permissions")),
                AuthContext.stringList(scopeClaim),
                claims.get("client_id") == null ? null : String.valueOf(claims.get("client_id")),
                claims);
    }

    private static String firstString(Map<String, Object> claims, String... keys) {
        for (String key : keys) {
            Object value = claims.get(key);
            if (value != null && !String.valueOf(value).isBlank()) {
                return String.valueOf(value);
            }
        }
        return null;
    }

    private void checkTime(Map<String, Object> claims) {
        long now = Instant.now().getEpochSecond();
        Object exp = claims.get("exp");
        if (!(exp instanceof Number n)) {
            throw ApiException.invalidToken("访问令牌缺少 exp");
        }
        if (now - CLOCK_LEEWAY_SECONDS > n.longValue()) {
            throw ApiException.invalidToken("访问令牌已过期");
        }
        if (claims.get("nbf") instanceof Number nbf && now + CLOCK_LEEWAY_SECONDS < nbf.longValue()) {
            throw ApiException.invalidToken("访问令牌尚未生效");
        }
    }

    private void checkIssuer(Map<String, Object> claims) {
        String expected = props.getAuth().getIssuer();
        if (expected == null || expected.isBlank()) {
            return;
        }
        Object actual = claims.get("iss");
        if (actual == null || !expected.equals(String.valueOf(actual))) {
            throw ApiException.invalidToken("访问令牌签发方不匹配");
        }
    }

    private void checkAudience(Map<String, Object> claims) {
        String expected = props.getAuth().getAudience();
        if (expected == null || expected.isBlank()) {
            return;
        }
        Object aud = claims.get("aud");
        if (aud instanceof List<?> list) {
            if (list.stream().anyMatch(v -> expected.equals(String.valueOf(v)))) {
                return;
            }
        } else if (aud != null && expected.equals(String.valueOf(aud))) {
            return;
        }
        throw ApiException.invalidToken("访问令牌受众不匹配");
    }

    private void checkType(Map<String, Object> claims) {
        Object type = claims.get("type");
        if (type == null) {
            return;
        }
        String value = String.valueOf(type);
        if (!"access".equals(value) && !"at+jwt".equals(value)) {
            throw ApiException.invalidToken("令牌类型不匹配");
        }
    }

    private PublicKey key(String kid) {
        if (keys.isEmpty() || System.currentTimeMillis() > keysExpiresAt) {
            refreshKeys();
        }
        PublicKey key = kid.isBlank() ? keys.values().stream().findFirst().orElse(null) : keys.get(kid);
        if (key == null && !kid.isBlank()) {
            refreshKeys();
            key = keys.get(kid);
        }
        if (key == null) {
            throw ApiException.invalidToken("未找到匹配的签名密钥");
        }
        return key;
    }

    private synchronized void refreshKeys() {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(props.getAuth().getJwksUrl()))
                    .timeout(Duration.ofSeconds(Math.max(1, props.getAuth().getTimeoutSeconds())))
                    .header("Accept", "application/json")
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw ApiException.unavailable("认证中心 JWKS 不可用: HTTP " + response.statusCode());
            }
            Map<String, Object> root = Json.readMap(response.body());
            Object rawKeys = root.get("keys");
            if (!(rawKeys instanceof List<?> list) || list.isEmpty()) {
                throw ApiException.unavailable("认证中心 JWKS 未返回签名密钥");
            }
            Map<String, PublicKey> loaded = new LinkedHashMap<>();
            for (Object item : list) {
                if (!(item instanceof Map<?, ?>)) {
                    continue;
                }
                Map<String, Object> jwk = Json.readMap(item);
                if (!"RSA".equals(String.valueOf(jwk.get("kty")))) {
                    continue;
                }
                String kid = jwk.get("kid") == null ? "" : String.valueOf(jwk.get("kid"));
                String n = jwk.get("n") == null ? null : String.valueOf(jwk.get("n"));
                String e = jwk.get("e") == null ? null : String.valueOf(jwk.get("e"));
                if (n == null || e == null) {
                    continue;
                }
                BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(n));
                BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(e));
                PublicKey publicKey = KeyFactory.getInstance("RSA")
                        .generatePublic(new RSAPublicKeySpec(modulus, exponent));
                loaded.put(kid, publicKey);
                if (kid.isEmpty()) {
                    loaded.put("", publicKey);
                }
            }
            if (loaded.isEmpty()) {
                throw ApiException.unavailable("认证中心 JWKS 中没有可用的 RSA 密钥");
            }
            keys.clear();
            keys.putAll(loaded);
            keysExpiresAt = System.currentTimeMillis() + Math.max(30, props.getAuth().getJwksCacheSeconds()) * 1000L;
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw ApiException.unavailable("无法获取认证中心 JWKS: " + e.getMessage());
        }
    }

    // ───────────────────────── 权限校验 ─────────────────────────

    public void requirePermission(AuthContext ctx, String permission) {
        if (ctx == null) {
            throw ApiException.unauthorized("缺少身份");
        }
        if (ctx.hasScope("internal")) {
            return;
        }
        if (!authorize(ctx, permission)) {
            throw ApiException.forbidden("缺少权限: " + permission);
        }
    }

    public boolean authorize(AuthContext ctx, String permission) {
        String cacheKey = ctx.identityId() + ":" + ctx.tenantId() + ":" + permission;
        Decision cached = decisions.get(cacheKey);
        if (cached != null && cached.expiresAt > System.currentTimeMillis()) {
            return cached.allowed;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("identity_id", ctx.identityId().toString());
        body.put("tenant_id", ctx.tenantId().toString());
        body.put("permission", permission);
        Map<String, Object> data = call("POST", "/api/v1/internal/authz/check", body, true);
        Object allowed = data.get("allowed");
        boolean ok = Boolean.TRUE.equals(allowed) || "true".equalsIgnoreCase(String.valueOf(allowed))
                || "allow".equalsIgnoreCase(String.valueOf(data.get("decision")));
        if (ok) {
            decisions.put(cacheKey, new Decision(true, System.currentTimeMillis() + 30_000));
        }
        if (decisions.size() > 20_000) {
            decisions.clear();
        }
        return ok;
    }

    // ───────────────────────── 内部身份/联系人调用 ─────────────────────────

    public Map<String, Object> getIdentity(String identityId) {
        Map<String, Object> data = call("GET", "/api/v1/internal/identities/" + identityId, null, true);
        Object identity = data.get("identity");
        if (identity instanceof Map<?, ?>) {
            return Json.readMap(identity);
        }
        return data;
    }

    public void requestContactChange(UUID identityId, String channel, String value, UUID tenantId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("channel", channel);
        body.put("value", value);
        body.put("tenant_id", tenantId.toString());
        call("POST", "/api/v1/internal/identities/" + identityId + "/contacts/request", body, true);
    }

    public void confirmContactChange(UUID identityId, String channel, String value, String code, UUID tenantId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("channel", channel);
        body.put("value", value);
        body.put("code", code);
        body.put("tenant_id", tenantId.toString());
        call("POST", "/api/v1/internal/identities/" + identityId + "/contacts/confirm", body, true);
    }

    public void clearContact(UUID identityId, String channel, UUID tenantId) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("channel", channel);
        body.put("tenant_id", tenantId.toString());
        call("POST", "/api/v1/internal/identities/" + identityId + "/contacts/clear", body, true);
    }

    public void updateStatus(UUID identityId, String status, String reason) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status);
        if (reason != null) {
            body.put("reason", reason);
        }
        call("PUT", "/api/v1/internal/identities/" + identityId + "/status", body, true);
    }

    public void syncProfile(UUID identityId, Map<String, Object> profile) {
        call("PUT", "/api/v1/internal/identities/" + identityId + "/profile", profile, true);
    }

    public Map<String, Object> ensureIdentity(Map<String, Object> identity) {
        return call("POST", "/api/v1/internal/identities", identity, true);
    }

    public boolean health() {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(base() + "/health"))
                    .timeout(Duration.ofSeconds(2))
                    .GET()
                    .build();
            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            return response.statusCode() / 100 == 2;
        } catch (Exception e) {
            return false;
        }
    }

    private String base() {
        String base = props.getAuth().getBaseUrl();
        if (base == null || base.isBlank()) {
            throw ApiException.unavailable("未配置认证中心地址");
        }
        return base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
    }

    private Map<String, Object> call(String method, String path, Map<String, Object> body, boolean internal) {
        if (internal && (props.getInternalToken() == null || props.getInternalToken().isBlank())) {
            throw ApiException.unavailable("未配置 USER_INTERNAL_TOKEN，无法调用认证中心内部接口");
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(base() + path))
                .timeout(Duration.ofSeconds(Math.max(1, props.getAuth().getTimeoutSeconds())))
                .header("Accept", "application/json");
        if (internal) {
            builder.header("x-internal-token", props.getInternalToken());
        }
        if (body != null) {
            builder.header("Content-Type", "application/json");
            builder.method(method, HttpRequest.BodyPublishers.ofString(Json.write(body), StandardCharsets.UTF_8));
        } else {
            builder.method(method, HttpRequest.BodyPublishers.noBody());
        }
        HttpResponse<String> response;
        try {
            response = http.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            log.warn("auth call {} {} failed: {}", method, path, e.getMessage());
            throw ApiException.unavailable("认证中心不可用: " + e.getMessage());
        }
        int status = response.statusCode();
        Map<String, Object> parsed = Json.readMap(response.body());
        if (status / 100 == 2) {
            String code = parsed.get("code") == null ? "ok" : String.valueOf(parsed.get("code"));
            if ("ok".equals(code)) {
                Object data = parsed.get("data");
                return data instanceof Map<?, ?> ? Json.readMap(data) : new LinkedHashMap<>();
            }
            throw ApiException.unavailable("认证中心返回错误: " + parsed.getOrDefault("message", code));
        }
        if (status >= 500) {
            throw ApiException.unavailable("认证中心不可用: HTTP " + status);
        }
        if (status == 401 || status == 403) {
            throw ApiException.unavailable("认证中心拒绝内部调用: HTTP " + status);
        }
        String message = parsed.get("message") == null ? "认证中心请求失败" : String.valueOf(parsed.get("message"));
        if (status == 404) {
            throw ApiException.notFound(message);
        }
        throw new ApiException(status, parsed.get("code") == null ? "auth_error" : String.valueOf(parsed.get("code")), message);
    }

    private record Decision(boolean allowed, long expiresAt) {
    }
}
