package com.platform.file.domain.model;

import com.platform.file.domain.storage.StorageType;

import java.util.Map;
import java.util.UUID;

public record StorageProviderConfig(
        UUID id,
        String code,
        String name,
        StorageType type,
        String endpoint,
        String region,
        String bucket,
        String rootPath,
        String accessKey,
        String secretKey,
        boolean enabled,
        boolean defaultProvider,
        boolean allowUpload,
        boolean allowDownload,
        boolean allowDelete,
        Map<String, Object> options,
        int version) {
}
