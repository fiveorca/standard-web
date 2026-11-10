package com.platform.file.domain.model;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record FileObject(
        UUID id,
        UUID storageProviderId,
        String objectKey,
        String tempKey,
        String sha256,
        long fileSize,
        String mimeType,
        String extension,
        String etag,
        String status,
        Instant deleteAfter,
        int deleteAttempts,
        String lastError,
        Instant verifiedAt,
        Map<String, Object> metadata,
        Instant createdAt,
        Instant updatedAt,
        Instant deletedAt) {
}
