package com.platform.im.security;

import com.platform.im.config.AppProperties;
import com.platform.im.shared.ApiException;
import com.platform.im.shared.Ids;
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
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * 设备身份认证：支持设备凭证（X-Device-Id + X-Device-Token）或平台 JWT（device_id claim）。
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class DeviceAuthFilter extends OncePerRequestFilter {
    private final AppProperties props;
    private final DeviceAuthenticator deviceAuthenticator;
    private final JwtVerifier jwtVerifier;

    public DeviceAuthFilter(AppProperties props, DeviceAuthenticator deviceAuthenticator, JwtVerifier jwtVerifier) {
        this.props = props;
        this.deviceAuthenticator = deviceAuthenticator;
        this.jwtVerifier = jwtVerifier;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/v1/device/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            AuthPrincipal principal = authenticate(request);
            request.setAttribute(RequestContext.PRINCIPAL_ATTRIBUTE, principal);
            if (principal.deviceId() != null) {
                request.setAttribute("im.deviceId", principal.deviceId());
                MDC.put("actor", principal.deviceId());
            }
            if (principal.tenantId() != null) {
                request.setAttribute("im.tenantId", principal.tenantId());
                MDC.put("tenantId", principal.tenantId().toString());
            }
            chain.doFilter(request, response);
        } catch (ApiException ex) {
            response.setStatus(ex.status());
            response.setContentType("application/json;charset=UTF-8");
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("code", ex.code());
            body.put("error", ex.error());
            body.put("message", ex.getMessage());
            body.put("timestamp", java.time.Instant.now().toString());
            response.getWriter().write(Json.write(body));
        }
    }

    private AuthPrincipal authenticate(HttpServletRequest request) {
        String deviceId = header(request, "X-Device-Id");
        UUID tenantId = parseTenant(header(request, "X-Tenant-Id"));

        if (!props.security.enabled) {
            if (deviceId == null || deviceId.isBlank()) {
                throw ApiException.unauthorized("缺少 X-Device-Id");
            }
            return AuthPrincipal.device(deviceId, tenantId);
        }

        String deviceToken = header(request, "X-Device-Token");
        if (deviceToken != null && !deviceToken.isBlank()) {
            if (deviceId == null || deviceId.isBlank()) {
                throw ApiException.unauthorized("缺少 X-Device-Id");
            }
            return deviceAuthenticator.authenticate(deviceId, deviceToken, tenantId);
        }

        String authorization = request.getHeader("Authorization");
        if (authorization != null && authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            AuthPrincipal jwt = jwtVerifier.verify(authorization.substring(7).trim());
            String jwtDeviceId = jwt.deviceId() != null ? jwt.deviceId() : deviceId;
            if (jwtDeviceId == null || jwtDeviceId.isBlank()) {
                throw ApiException.unauthorized("访问令牌缺少 device_id");
            }
            UUID resolvedTenant = tenantId != null ? tenantId : jwt.tenantId();
            return deviceAuthenticator.resolve(jwtDeviceId, resolvedTenant);
        }
        throw ApiException.unauthorized("缺少设备凭证");
    }

    private static String header(HttpServletRequest request, String name) {
        String value = request.getHeader(name);
        return value == null ? null : value.trim();
    }

    private static UUID parseTenant(String value) {
        return Ids.parseUuid(value, "tenant_id");
    }
}
