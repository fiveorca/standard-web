package com.platform.file.application.command;

import java.util.Map;
import java.util.UUID;

public record CreateUploadCommand(
        UUID storageProviderId,
        String filename,
        String displayName,
        String contentType,
        Long size,
        String sourceType,
        String sourceId,
        String businessId,
        String creator,
        UUID tenantId,
        Map<String, Object> metadata,
        String idempotencyKey,
        Long partSize) {
}
