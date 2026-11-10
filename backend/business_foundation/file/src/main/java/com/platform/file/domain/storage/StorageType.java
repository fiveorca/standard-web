package com.platform.file.domain.storage;

import com.platform.file.shared.ApiException;

import java.util.Locale;

public enum StorageType {
    LOCAL,
    S3,
    OSS;

    public static StorageType parse(String value) {
        if (value == null || value.isBlank()) {
            throw ApiException.validation("type", "存储类型不能为空");
        }
        try {
            return StorageType.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw ApiException.validation("type", "不支持的存储类型: " + value);
        }
    }
}
