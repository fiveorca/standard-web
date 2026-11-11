package com.platform.im.security;

import com.platform.im.shared.ApiException;
import jakarta.servlet.http.HttpServletRequest;

import java.util.UUID;

public final class RequestContext {
    public static final String PRINCIPAL_ATTRIBUTE = AuthPrincipal.class.getName();

    private RequestContext() {
    }

    public static AuthPrincipal principal(HttpServletRequest request) {
        Object value = request.getAttribute(PRINCIPAL_ATTRIBUTE);
        if (value instanceof AuthPrincipal principal) {
            return principal;
        }
        throw ApiException.unauthorized("未认证的请求");
    }

    public static AuthPrincipal principalOrSystem(HttpServletRequest request) {
        Object value = request.getAttribute(PRINCIPAL_ATTRIBUTE);
        return value instanceof AuthPrincipal principal ? principal : AuthPrincipal.system("anonymous");
    }

    public static UUID tenantId(HttpServletRequest request) {
        Object value = request.getAttribute("im.tenantId");
        if (value instanceof UUID tenantId) {
            return tenantId;
        }
        return principalOrSystem(request).tenantId();
    }

    public static String deviceId(HttpServletRequest request) {
        Object value = request.getAttribute("im.deviceId");
        if (value instanceof String deviceId && !deviceId.isBlank()) {
            return deviceId;
        }
        AuthPrincipal principal = principalOrSystem(request);
        if (principal.deviceId() == null || principal.deviceId().isBlank()) {
            throw ApiException.unauthorized("缺少设备身份");
        }
        return principal.deviceId();
    }

    public static String actor(HttpServletRequest request) {
        return principalOrSystem(request).subject();
    }
}
