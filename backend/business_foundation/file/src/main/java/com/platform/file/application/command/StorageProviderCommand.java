package com.platform.file.application.command;

import com.platform.file.domain.storage.StorageType;

import java.util.Map;

public record StorageProviderCommand(
        String code,
        String name,
        StorageType type,
        String endpoint,
        String region,
        String bucket,
        String rootPath,
        String accessKey,
        String secretKey,
        String accessKeyEnv,
        String secretKeyEnv,
        Boolean enabled,
        Boolean defaultProvider,
        Boolean allowUpload,
        Boolean allowDownload,
        Boolean allowDelete,
        Map<String, Object> options) {
}
