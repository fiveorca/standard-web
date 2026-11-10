package com.platform.file.domain.storage;

import java.time.Instant;
import java.util.Map;

public record PartAuthorization(String url, String method, Map<String, String> headers, Instant expiresAt) {
}
