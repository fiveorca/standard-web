package com.platform.file.domain.model;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record UploadSession(
        UUID id,
        UUID fileId,
        UUID fileObjectId,
        UUID storageProviderId,
        String mode,
        String status,
        String objectKey,
        String tempKey,
        String multipartId,
        Long expectedSize,
        long receivedSize,
        String sha256,
        Integer partsTotal,
        int partsCompleted,
        String idempotencyKey,
        Instant expiresAt,
        Instant confirmedAt,
        Instant cancelledAt,
        String errorMessage,
        Map<String, Object> metadata,
        Instant createdAt,
        Instant updatedAt) {
}
