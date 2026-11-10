package com.platform.file.domain.model;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record FileRecord(
        UUID id,
        UUID fileObjectId,
        UUID storageProviderId,
        String originalFilename,
        String displayName,
        long fileSize,
        String mimeType,
        String extension,
        String sourceType,
        String sourceId,
        String businessId,
        String creator,
        UUID tenantId,
        String status,
        String sha256,
        Map<String, Object> metadata,
        Instant createdAt,
        Instant updatedAt,
        Instant deletedAt) {
}
