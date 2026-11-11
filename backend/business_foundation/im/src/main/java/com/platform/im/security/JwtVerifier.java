package com.platform.im.security;

import com.platform.im.config.AppProperties;
import com.platform.im.shared.ApiException;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/**
 * 统一 JWT 校验：支持平台 auth 服务 JWKS（RS/ES）或本地 HS256 密钥。
 */
@Component
public class JwtVerifier {
    private final AppProperties props;
    private final JwtDecoder decoder;

    public JwtVerifier(AppProperties props) {
        this.props = props;
        this.decoder = buildDecoder(props);
    }

    public AuthPrincipal verify(String token) {
        if (token == null || token.isBlank()) {
            throw ApiException.unauthorized("缺少访问令牌");
        }
        if (decoder == null) {
            throw ApiException.unavailable("JWT 校验未配置，请设置 im.security.jwt.jwks-url 或 hmac-secret");
        }
        try {
            Jwt jwt = decoder.decode(token);
            String audience = props.security.jwt.audience;
            if (audience != null && !audience.isBlank() && !jwt.getAudience().contains(audience)) {
                throw ApiException.unauthorized("访问令牌 audience 不匹配");
            }
            Set<String> roles = roles(jwt);
            UUID tenantId = tenant(jwt);
            String subject = subject(jwt);
            AuthPrincipal.PrincipalType type = roles.contains(props.security.adminRole)
                    || roles.contains("IM_ADMIN") || roles.contains("ADMIN")
                    ? AuthPrincipal.PrincipalType.ADMIN : AuthPrincipal.PrincipalType.SERVICE;
            String deviceId = firstString(jwt.getClaims().get("device_id"));
            return new AuthPrincipal(subject, tenantId, roles, type, deviceId);
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw ApiException.unauthorized("访问令牌无效或已过期");
        }
    }

    private static JwtDecoder buildDecoder(AppProperties props) {
        AppProperties.Jwt cfg = props.security.jwt;
        NimbusJwtDecoder built = null;
        if (cfg.jwksUrl != null && !cfg.jwksUrl.isBlank()) {
            built = NimbusJwtDecoder.withJwkSetUri(cfg.jwksUrl.trim()).build();
        } else if (cfg.hmacSecret != null && !cfg.hmacSecret.isBlank()) {
            byte[] secret = cfg.hmacSecret.getBytes(StandardCharsets.UTF_8);
            built = NimbusJwtDecoder.withSecretKey(new SecretKeySpec(secret, "HmacSHA256"))
                    .macAlgorithm(MacAlgorithm.HS256)
                    .build();
        }
        if (built != null && cfg.issuer != null && !cfg.issuer.isBlank()) {
            var validator = JwtValidators.createDefaultWithIssuer(cfg.issuer.trim());
            built.setJwtValidator(new DelegatingOAuth2TokenValidator<>(validator));
        }
        return built;
    }

    private Set<String> roles(Jwt jwt) {
        Set<String> out = new LinkedHashSet<>();
        Object claim = jwt.getClaims().get(props.security.jwt.rolesClaim);
        collectStrings(claim, out);
        Object scope = jwt.getClaims().get("scope");
        if (scope instanceof String text) {
            for (String value : text.split("\\s+")) {
                if (!value.isBlank()) {
                    out.add(value.trim());
                }
            }
        }
        Object authorities = jwt.getClaims().get("authorities");
        collectStrings(authorities, out);
        return out;
    }

    @SuppressWarnings("unchecked")
    private static void collectStrings(Object value, Set<String> out) {
        if (value == null) {
            return;
        }
        if (value instanceof String text) {
            for (String part : text.split("[,\\s]+")) {
                if (!part.isBlank()) {
                    out.add(part.trim());
                }
            }
            return;
        }
        if (value instanceof Collection<?> list) {
            for (Object item : list) {
                if (item != null) {
                    out.add(String.valueOf(item).trim());
                }
            }
            return;
        }
        if (value instanceof Object[] array) {
            for (Object item : array) {
                if (item != null) {
                    out.add(String.valueOf(item).trim());
                }
            }
        }
    }

    private UUID tenant(Jwt jwt) {
        Object claim = jwt.getClaims().get(props.security.jwt.tenantClaim);
        String text = firstString(claim);
        if (text == null || text.isBlank() || "null".equalsIgnoreCase(text)) {
            return null;
        }
        try {
            return UUID.fromString(text);
        } catch (IllegalArgumentException e) {
            throw ApiException.unauthorized("访问令牌中的租户标识不合法");
        }
    }

    private static String subject(Jwt jwt) {
        String subject = jwt.getSubject();
        if (subject != null && !subject.isBlank()) {
            return subject;
        }
        for (String key : List.of("username", "client_id", "user_name", "sub")) {
            String value = firstString(jwt.getClaims().get(key));
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return "unknown";
    }

    private static String firstString(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Collection<?> list && !list.isEmpty()) {
            Object first = list.iterator().next();
            return first == null ? null : String.valueOf(first);
        }
        return String.valueOf(value);
    }
}
