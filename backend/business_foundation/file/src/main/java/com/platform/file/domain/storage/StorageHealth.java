package com.platform.file.domain.storage;

import java.time.Instant;

public record StorageHealth(boolean ok, String message, Instant checkedAt) {
    public static StorageHealth ok(String message) {
        return new StorageHealth(true, message, Instant.now());
    }

    public static StorageHealth fail(String message) {
        return new StorageHealth(false, message, Instant.now());
    }
}
