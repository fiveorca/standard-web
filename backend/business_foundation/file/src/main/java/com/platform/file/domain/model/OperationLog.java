package com.platform.file.domain.model;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record OperationLog(
        UUID id,
        String operation,
        String status,
        UUID storageProviderId,
        UUID fileObjectId,
        UUID fileId,
        UUID uploadId,
        String objectKey,
        Long bytes,
        Long durationMs,
        String traceId,
        Map<String, Object> detail,
        String errorMessage,
        Instant createdAt) {
}
