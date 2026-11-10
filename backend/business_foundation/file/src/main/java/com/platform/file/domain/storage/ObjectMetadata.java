package com.platform.file.domain.storage;

import java.time.Instant;
import java.util.Map;

public record ObjectMetadata(
        String key,
        long size,
        String contentType,
        String etag,
        Instant lastModified,
        Map<String, String> metadata) {
}
