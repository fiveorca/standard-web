package com.platform.auth.common;

import com.platform.auth.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class AuthContextResolver implements HandlerMethodArgumentResolver {
    private final JwtService jwt;
    private final Db db;

    public AuthContextResolver(JwtService jwt, Db db) {
        this.jwt = jwt;
        this.db = db;
    }

    @Override
    public boolean supportsParameter(MethodParameter parameter) {
        return AuthContext.class.equals(parameter.getParameterType());
    }

    @Override
    public Object resolveArgument(MethodParameter parameter, ModelAndViewContainer mavContainer,
                                  NativeWebRequest webRequest, WebDataBinderFactory binderFactory) {
        HttpServletRequest request = webRequest.getNativeRequest(HttpServletRequest.class);
        return authenticate(request);
    }

    public AuthContext authenticate(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            String cookieToken = Cookies.read(request, "access_token");
            if (cookieToken == null) {
                throw ApiException.unauthorized("缺少访问令牌");
            }
            header = "Bearer " + cookieToken;
        }
        Map<String, Object> claims = jwt.verify(header.substring(7), "access");
        String sessionId = str(claims.get("sid"));
        if (sessionId != null) {
            Map<String, Object> session = db.list(
                    "SELECT status, expires_at FROM auth_sessions WHERE id = :id",
                    Db.params("id", sessionId)).stream().findFirst().orElse(null);
            if (session == null || !"active".equals(String.valueOf(session.get("status")))
                    || Instant.parse(String.valueOf(session.get("expires_at"))).isBefore(Instant.now())) {
                throw ApiException.unauthorized("会话已失效");
            }
        }
        return new AuthContext(
                str(claims.get("sub")),
                str(claims.get("tenant_id")),
                str(claims.get("sid")),
                str(claims.get("client_id")),
                str(claims.get("jti")),
                stringSet(claims.get("roles")),
                stringSet(claims.get("permissions")),
                stringSet(claims.get("amr")),
                str(claims.get("acr")),
                str(claims.get("scope")),
                jwt.expiresAt(claims),
                claims
        );
    }

    private static String str(Object value) {
        return value == null ? null : String.valueOf(value);
    }

    @SuppressWarnings("unchecked")
    private static Set<String> stringSet(Object value) {
        if (value instanceof List<?> list) {
            Set<String> out = new LinkedHashSet<>();
            list.forEach(v -> out.add(String.valueOf(v)));
            return out;
        }
        if (value instanceof String s && !s.isBlank()) {
            return new LinkedHashSet<>(List.of(s.split("\\s+")));
        }
        return new LinkedHashSet<>();
    }
}
