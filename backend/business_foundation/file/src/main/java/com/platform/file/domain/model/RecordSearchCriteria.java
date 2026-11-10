package com.platform.file.domain.model;

import java.time.Instant;
import java.util.UUID;

public record RecordSearchCriteria(
        String status,
        String sourceType,
        String sourceId,
        String businessId,
        UUID storageProviderId,
        String creator,
        UUID tenantId,
        String mimeType,
        String filename,
        Instant createdFrom,
        Instant createdTo,
        String sort) {
}
