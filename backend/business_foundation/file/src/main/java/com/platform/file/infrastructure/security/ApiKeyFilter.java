package com.platform.file.infrastructure.security;

import com.platform.file.config.AppProperties;
import com.platform.file.shared.Json;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
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
 * 服务间 API Key 认证。未配置 Key 时仅用于本地开发。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class ApiKeyFilter extends OncePerRequestFilter {
    private static final Set<String> PUBLIC_PREFIXES = Set.of(
            "/health", "/live", "/ready", "/readyz", "/docs", "/swagger-ui", "/v3/api-docs",
            "/openapi.json", "/actuator/health", "/actuator/info", "/api/v1/public/");

    private final AppProperties props;

    public ApiKeyFilter(AppProperties props) {
        this.props = props;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        for (String prefix : PUBLIC_PREFIXES) {
            if (uri.equals(prefix) || uri.startsWith(prefix)) {
                return true;
            }
        }
        return props.security.apiKey == null || props.security.apiKey.isBlank();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String provided = request.getHeader("X-API-Key");
        if (provided == null || provided.isBlank()) {
            provided = request.getHeader("X-Internal-Token");
        }
        if (provided == null || !MessageDigest.isEqual(
                provided.getBytes(StandardCharsets.UTF_8),
                props.security.apiKey.getBytes(StandardCharsets.UTF_8))) {
            response.setStatus(401);
            response.setContentType("application/json;charset=UTF-8");
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("code", "unauthorized");
            body.put("message", "缺少或无效的 API Key");
            response.getWriter().write(Json.write(body));
            return;
        }
        chain.doFilter(request, response);
    }
}
