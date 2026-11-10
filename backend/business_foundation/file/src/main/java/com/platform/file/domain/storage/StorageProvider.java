package com.platform.file.domain.storage;

import java.io.InputStream;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/**
 * 统一存储抽象。业务层只依赖该接口，不依赖任何云厂商 SDK。
 */
public interface StorageProvider extends AutoCloseable {
    String type();

    StorageCapabilities capabilities();

    ObjectMetadata put(String key, InputStream content, long size, String contentType, Map<String, String> metadata);

    InputStream open(String key);

    void copy(String sourceKey, String targetKey);

    void delete(String key);

    boolean exists(String key);

    ObjectMetadata stat(String key);

    ObjectPage list(String prefix, String cursor, int limit);

    PresignedUpload presignUpload(String key, String contentType, long maxSize, Duration ttl);

    PresignedDownload presignDownload(String key, String filename, Duration ttl);

    MultipartHandle createMultipart(String key, String contentType, Map<String, String> metadata);

    MultipartPart uploadPart(String key, String uploadId, int partNumber, InputStream content, long size);

    PartAuthorization presignPart(String key, String uploadId, int partNumber, Duration ttl);

    MultipartPart completeMultipart(String key, String uploadId, List<MultipartPart> parts);

    void abortMultipart(String key, String uploadId);

    StorageHealth health();

    @Override
    default void close() {
    }
}
