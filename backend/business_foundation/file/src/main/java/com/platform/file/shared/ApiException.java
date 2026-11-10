package com.platform.file.shared;

import java.util.LinkedHashMap;
import java.util.Map;

public class ApiException extends RuntimeException {
    private final int status;
    private final String code;
    private final Map<String, Object> details;

    public ApiException(int status, String code, String message) {
        this(status, code, message, null);
    }

    public ApiException(int status, String code, String message, Map<String, Object> details) {
        super(message);
        this.status = status;
        this.code = code;
        this.details = details == null ? Map.of() : details;
    }

    public int status() {
        return status;
    }

    public String code() {
        return code;
    }

    public Map<String, Object> details() {
        return details;
    }

    public static ApiException badRequest(String message) {
        return new ApiException(400, "invalid_request", message);
    }

    public static ApiException unauthorized(String message) {
        return new ApiException(401, "unauthorized", message);
    }

    public static ApiException forbidden(String message) {
        return new ApiException(403, "forbidden", message);
    }

    public static ApiException notFound(String message) {
        return new ApiException(404, "not_found", message);
    }

    public static ApiException conflict(String message) {
        return new ApiException(409, "conflict", message);
    }

    public static ApiException payloadTooLarge(String message) {
        return new ApiException(413, "payload_too_large", message);
    }

    public static ApiException unsupportedMedia(String message) {
        return new ApiException(415, "unsupported_media_type", message);
    }

    public static ApiException validation(String field, String message) {
        Map<String, Object> details = new LinkedHashMap<>();
        details.put(field, message);
        return new ApiException(422, "validation_failed", "参数校验失败", details);
    }

    public static ApiException expired(String message) {
        return new ApiException(410, "expired", message);
    }

    public static ApiException storage(String message) {
        return new ApiException(502, "storage_error", message);
    }

    public static ApiException unavailable(String message) {
        return new ApiException(503, "unavailable", message);
    }
}
