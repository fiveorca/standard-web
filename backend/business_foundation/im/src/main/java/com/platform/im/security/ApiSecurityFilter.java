package com.platform.im.security;

import com.platform.im.config.AppProperties;
import com.platform.im.shared.Json;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * /api/v1/admin/**、/api/v1/internal/** 以及其他管理 API 的认证入口。
 * 设备接口由 {@link DeviceAuthFilter} 单独处理。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class ApiSecurityFilter extends OncePerRequestFilter {
    private static final Set<String> PUBLIC_PREFIXES = Set.of(
            "/docs", "/swagger-ui", "/v3/api-docs", "/openapi.json", "/actuator/health", "/actuator/info");

    private final AppProperties props;
    private final JwtVerifier jwtVerifier;

    public ApiSecurityFilter(AppProperties props, JwtVerifier jwtVerifier) {
        this.props = props;
        this.jwtVerifier = jwtVerifier;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        for (String prefix : PUBLIC_PREFIXES) {
            if (uri.equals(prefix) || uri.startsWith(prefix)) {
                return true;
            }
        }
        if (!uri.startsWith("/api/v1/")) {
            return true;
        }
        return uri.startsWith("/api/v1/device/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String uri = request.getRequestURI();
        boolean adminPath = uri.startsWith("/api/v1/admin/");
        boolean internalPath = uri.startsWith("/api/v1/internal/");

        if (!props.security.enabled) {
            AuthPrincipal principal = AuthPrincipal.system("security-disabled");
            attach(request, principal);
            chain.doFilter(request, response);
            return;
        }

        AuthPrincipal principal;
        try {
            if (internalPath) {
                principal = authenticateInternal(request);
            } else {
                principal = authenticateAdminOrService(request);
                if (adminPath && !principal.isAdmin(props)) {
                    throw com.platform.im.shared.ApiException.forbidden("需要管理权限");
                }
            }
        } catch (com.platform.im.shared.ApiException ex) {
            unauthorized(response, ex.status(), ex.getMessage());
            return;
        }

        attach(request, principal);
        chain.doFilter(request, response);
    }

    private AuthPrincipal authenticateInternal(HttpServletRequest request) {
        String provided = request.getHeader("X-Internal-Token");
        String expected = props.security.internalToken;
        if (expected == null || expected.isBlank() || provided == null
                || !MessageDigest.isEqual(provided.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8))) {
            throw com.platform.im.shared.ApiException.unauthorized("内部令牌无效");
        }
        return AuthPrincipal.internal();
    }

    private AuthPrincipal authenticateAdminOrService(HttpServletRequest request) {
        String apiKey = request.getHeader("X-API-Key");
        String expected = props.security.adminApiKey;
        if (expected != null && !expected.isBlank() && apiKey != null
                && MessageDigest.isEqual(apiKey.getBytes(StandardCharsets.UTF_8),
                expected.getBytes(StandardCharsets.UTF_8))) {
            return AuthPrincipal.system("admin-api-key");
        }
        String header = request.getHeader("Authorization");
        if (header == null || header.isBlank()) {
            throw com.platform.im.shared.ApiException.unauthorized("缺少访问令牌");
        }
        if (!header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw com.platform.im.shared.ApiException.unauthorized("访问令牌格式应为 Bearer");
        }
        return jwtVerifier.verify(header.substring(7).trim());
    }

    private void attach(HttpServletRequest request, AuthPrincipal principal) {
        request.setAttribute(RequestContext.PRINCIPAL_ATTRIBUTE, principal);
        if (principal.tenantId() != null) {
            request.setAttribute("im.tenantId", principal.tenantId());
            MDC.put("tenantId", principal.tenantId().toString());
        }
        MDC.put("actor", principal.subject());
    }

    private void unauthorized(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", status == 403 ? 40301 : 40101);
        body.put("error", status == 403 ? "forbidden" : "unauthorized");
        body.put("message", message);
        body.put("timestamp", java.time.Instant.now().toString());
        response.getWriter().write(Json.write(body));
    }
}
