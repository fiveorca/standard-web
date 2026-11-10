package com.platform.file.domain.storage;

public record StorageCapabilities(
        boolean serverUpload,
        boolean presignUpload,
        boolean presignDownload,
        boolean multipart,
        boolean listing) {
}
