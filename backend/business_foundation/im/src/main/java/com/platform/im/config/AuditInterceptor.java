package com.platform.im.config;

import com.platform.im.application.AuditService;
import com.platform.im.security.AuthPrincipal;
import com.platform.im.security.RequestContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class AuditInterceptor implements HandlerInterceptor {
    private static final Logger log = LoggerFactory.getLogger(AuditInterceptor.class);
    private static final String START_ATTRIBUTE = "im.audit.start";

    private final AuditService auditService;

    public AuditInterceptor(AuditService auditService) {
        this.auditService = auditService;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        request.setAttribute(START_ATTRIBUTE, System.nanoTime());
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response,
                                Object handler, Exception ex) {
        try {
            Object start = request.getAttribute(START_ATTRIBUTE);
            long durationMs = start instanceof Long value ? (System.nanoTime() - value) / 1_000_000 : 0;
            AuthPrincipal principal = RequestContext.principalOrSystem(request);
            String path = request.getRequestURI();
            String resourceType = "HTTP";
            String resourceId = null;
            String[] parts = path.split("/");
            if (parts.length > 5) {
                resourceType = parts[4];
                if (parts.length > 6) {
                    resourceId = parts[6];
                }
            }
            auditService.record(new AuditService.AuditEntry(
                    principal.tenantId(),
                    principal.subject(),
                    principal.type().name(),
                    request.getMethod() + " " + path,
                    resourceType,
                    resourceId,
                    request.getMethod(),
                    path,
                    response.getStatus(),
                    clientIp(request),
                    truncate(request.getHeader("User-Agent"), 512),
                    MDC.get("traceId"),
                    durationMs,
                    ex == null ? null : truncate(ex.getClass().getSimpleName() + ": " + ex.getMessage(), 1024)
            ));
        } catch (Exception e) {
            log.warn("failed to write audit log for {} {}", request.getMethod(), request.getRequestURI(), e);
        }
    }

    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
