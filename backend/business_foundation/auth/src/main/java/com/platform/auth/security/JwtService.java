package com.platform.auth.security;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.Json;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
public class JwtService {
    private final KeyService keys;

    public JwtService(KeyService keys) {
        this.keys = keys;
    }

    public String signAccess(String subject, String tenantId, String sessionId, String clientId,
                             String scope, List<String> amr, String acr, long ttl,
                             List<String> roles, List<String> permissions, Map<String, Object> extra) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("roles", roles == null ? List.of() : roles);
        claims.put("permissions", permissions == null ? List.of() : permissions);
        if (extra != null) {
            claims.putAll(extra);
        }
        return keys.sign(keys.claims(subject, tenantId, sessionId, clientId, scope, amr, acr, ttl, "access", claims));
    }

    public String signIdToken(String subject, String tenantId, String sessionId, String clientId,
                              String nonce, long authTime, Map<String, Object> extra) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("auth_time", authTime);
        if (nonce != null) {
            claims.put("nonce", nonce);
        }
        if (extra != null) {
            claims.putAll(extra);
        }
        return keys.sign(keys.claims(subject, tenantId, sessionId, clientId, "openid", List.of("pwd"),
                "urn:auth:acr:pwd", keys.idTokenTtl(), "id", claims));
    }

    public String signMfa(String subject, String tenantId) {
        return keys.sign(keys.claims(subject, tenantId, null, null, "mfa", List.of("pwd"),
                "urn:auth:acr:pwd", 300, "mfa", Map.of("purpose", "mfa")));
    }

    public Map<String, Object> verify(String token, String expectedType) {
        JWTClaimsSet claims = keys.verify(token);
        String type = String.valueOf(claims.getClaim("type"));
        if (expectedType != null && !expectedType.equals(type)) {
            throw ApiException.unauthorized("令牌类型不匹配");
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sub", claims.getSubject());
        out.put("iss", claims.getIssuer());
        claims.getClaims().forEach(out::put);
        return out;
    }

    public Instant expiresAt(Map<String, Object> claims) {
        Object exp = claims.get("exp");
        if (exp instanceof Number n) {
            return Instant.ofEpochSecond(n.longValue());
        }
        if (exp instanceof Date d) {
            return d.toInstant();
        }
        return Instant.EPOCH;
    }

    public Map<String, Object> jwks() {
        return keys.jwks();
    }

    public String json(Map<String, Object> value) {
        return Json.write(value);
    }
}
