package com.platform.file.domain.model;

import java.time.Instant;
import java.util.UUID;

public record FileSource(
        UUID id,
        String code,
        String name,
        String description,
        boolean enabled,
        Instant createdAt,
        Instant updatedAt) {
}
