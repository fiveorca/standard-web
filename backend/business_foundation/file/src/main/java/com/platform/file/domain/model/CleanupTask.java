package com.platform.file.domain.model;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record CleanupTask(
        UUID id,
        String type,
        String status,
        boolean dryRun,
        UUID storageProviderId,
        int scanned,
        int deleted,
        int repaired,
        int failed,
        Map<String, Object> details,
        String errorMessage,
        Instant startedAt,
        Instant finishedAt,
        Instant createdAt) {
}
