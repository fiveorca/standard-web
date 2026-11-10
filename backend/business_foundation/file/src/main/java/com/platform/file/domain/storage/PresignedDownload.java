package com.platform.file.domain.storage;

import java.time.Instant;

public record PresignedDownload(String url, Instant expiresAt) {
}
