package com.platform.im.config;

import com.platform.im.infrastructure.ratelimit.RequestRateLimiter;
import com.platform.im.security.RequestContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * HTTP 入口限流：优先按认证主体，其次按来源 IP。
 */
public class RateLimitInterceptor implements HandlerInterceptor {
    private final RequestRateLimiter limiter;

    public RateLimitInterceptor(RequestRateLimiter limiter) {
        this.limiter = limiter;
    }

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        var principal = RequestContext.principalOrSystem(request);
        String key = principal.subject();
        if (key == null || key.isBlank() || "anonymous".equals(key)) {
            key = clientIp(request);
        }
        limiter.checkHttp(key);
        return true;
    }

    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
