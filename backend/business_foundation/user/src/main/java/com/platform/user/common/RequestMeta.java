package com.platform.user.common;

import jakarta.servlet.http.HttpServletRequest;

public record RequestMeta(String ip, String userAgent, String traceId) {

    public static RequestMeta from(HttpServletRequest request, boolean trustProxy) {
        String ip = null;
        if (trustProxy) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                ip = forwarded.split(",")[0].trim();
            }
            if (ip == null || ip.isBlank()) {
                ip = request.getHeader("X-Real-IP");
            }
        }
        if (ip == null || ip.isBlank()) {
            ip = request.getRemoteAddr();
        }
        Object trace = request.getAttribute("traceId");
        String traceId = trace == null ? request.getHeader("X-Request-Id") : String.valueOf(trace);
        return new RequestMeta(ip, request.getHeader("User-Agent"), traceId);
    }
}
