package com.platform.im.shared;

import java.util.LinkedHashMap;
import java.util.Map;

public class ApiException extends RuntimeException {
    private final int status;
    private final int code;
    private final String error;
    private final Map<String, Object> details;

    public ApiException(int status, int code, String error, String message) {
        this(status, code, error, message, null);
    }

    public ApiException(int status, int code, String error, String message, Map<String, Object> details) {
        super(message);
        this.status = status;
        this.code = code;
        this.error = error;
        this.details = details == null ? Map.of() : details;
    }

    public int status() {
        return status;
    }

    public int code() {
        return code;
    }

    public String error() {
        return error;
    }

    public Map<String, Object> details() {
        return details;
    }

    public static ApiException badRequest(String message) {
        return new ApiException(400, 40001, "invalid_request", message);
    }

    public static ApiException unauthorized(String message) {
        return new ApiException(401, 40101, "unauthorized", message);
    }

    public static ApiException forbidden(String message) {
        return new ApiException(403, 40301, "forbidden", message);
    }

    public static ApiException notFound(String message) {
        return new ApiException(404, 40401, "not_found", message);
    }

    public static ApiException conflict(String message) {
        return new ApiException(409, 40901, "conflict", message);
    }

    public static ApiException payloadTooLarge(String message) {
        return new ApiException(413, 41301, "payload_too_large", message);
    }

    public static ApiException validation(String field, String message) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put(field, message);
        return new ApiException(422, 42201, "validation_failed", "参数校验失败", details);
    }

    public static ApiException rateLimited(String message) {
        return new ApiException(429, 42901, "rate_limited", message);
    }

    public static ApiException provider(String message) {
        return new ApiException(502, 50201, "provider_error", message);
    }

    public static ApiException unavailable(String message) {
        return new ApiException(503, 50301, "unavailable", message);
    }

    public static ApiException internal(String message) {
        return new ApiException(500, 50001, "internal_error", message);
    }
}
