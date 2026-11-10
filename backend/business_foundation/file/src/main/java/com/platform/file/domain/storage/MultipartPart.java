package com.platform.file.domain.storage;

public record MultipartPart(int partNumber, String etag, long size) {
}
