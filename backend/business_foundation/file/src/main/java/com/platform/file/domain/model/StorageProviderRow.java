package com.platform.file.domain.model;

import com.platform.file.domain.storage.StorageType;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record StorageProviderRow(
        UUID id,
        String code,
        String name,
        StorageType type,
        String endpoint,
        String region,
        String bucket,
        String rootPath,
        String accessKeyCipher,
        String secretKeyCipher,
        String accessKeyEnv,
        String secretKeyEnv,
        boolean enabled,
        boolean defaultProvider,
        boolean allowUpload,
        boolean allowDownload,
        boolean allowDelete,
        Map<String, Object> options,
        String lastHealthStatus,
        String lastHealthMessage,
        Instant lastCheckedAt,
        int version,
        Instant createdAt,
        Instant updatedAt) {
}
