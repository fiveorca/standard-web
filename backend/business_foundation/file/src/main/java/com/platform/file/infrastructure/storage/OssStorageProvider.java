package com.platform.file.infrastructure.storage;

import com.aliyun.oss.HttpMethod;
import com.aliyun.oss.OSS;
import com.aliyun.oss.OSSClientBuilder;
import com.aliyun.oss.model.AbortMultipartUploadRequest;
import com.aliyun.oss.model.CompleteMultipartUploadRequest;
import com.aliyun.oss.model.GeneratePresignedUrlRequest;
import com.aliyun.oss.model.InitiateMultipartUploadRequest;
import com.aliyun.oss.model.InitiateMultipartUploadResult;
import com.aliyun.oss.model.ListObjectsRequest;
import com.aliyun.oss.model.ObjectListing;
import com.aliyun.oss.model.ObjectMetadata;
import com.aliyun.oss.model.OSSObject;
import com.aliyun.oss.model.OSSObjectSummary;
import com.aliyun.oss.model.PartETag;
import com.aliyun.oss.model.ResponseHeaderOverrides;
import com.aliyun.oss.model.UploadPartRequest;
import com.platform.file.domain.model.StorageProviderConfig;
import com.platform.file.domain.storage.MultipartHandle;
import com.platform.file.domain.storage.MultipartPart;
import com.platform.file.domain.storage.ObjectPage;
import com.platform.file.domain.storage.PartAuthorization;
import com.platform.file.domain.storage.PresignedDownload;
import com.platform.file.domain.storage.PresignedUpload;
import com.platform.file.domain.storage.StorageCapabilities;
import com.platform.file.domain.storage.StorageException;
import com.platform.file.domain.storage.StorageHealth;
import com.platform.file.domain.storage.StorageProvider;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * 阿里云 OSS 适配器。直传授权使用 OSS 预签名 URL（可选 STS 由网关层扩展）。
 */
public class OssStorageProvider implements StorageProvider {
    private final StorageProviderConfig config;
    private final OSS client;
    private final String bucket;
    private final String rootPrefix;

    public OssStorageProvider(StorageProviderConfig config) {
        this.config = config;
        if (config.bucket() == null || config.bucket().isBlank()) {
            throw new StorageException("OSS 存储必须配置 bucket");
        }
        if (config.endpoint() == null || config.endpoint().isBlank()) {
            throw new StorageException("OSS 存储必须配置 endpoint");
        }
        if (config.accessKey() == null || config.secretKey() == null) {
            throw new StorageException("OSS 存储缺少访问凭据");
        }
        this.bucket = config.bucket();
        this.rootPrefix = normalizePrefix(config.rootPath());
        String endpoint = config.endpoint().trim();
        if (!endpoint.startsWith("http://") && !endpoint.startsWith("https://")) {
            endpoint = "https://" + endpoint;
        }
        this.client = new OSSClientBuilder().build(endpoint, config.accessKey(), config.secretKey());
    }

    @Override
    public String type() {
        return "OSS";
    }

    @Override
    public StorageCapabilities capabilities() {
        return new StorageCapabilities(true, true, true, true, true);
    }

    @Override
    public com.platform.file.domain.storage.ObjectMetadata put(String key, InputStream content, long size,
                                                               String contentType, Map<String, String> metadata) {
        try {
            ObjectMetadata objectMetadata = new ObjectMetadata();
            if (size >= 0) {
                objectMetadata.setContentLength(size);
            }
            if (contentType != null) {
                objectMetadata.setContentType(contentType);
            }
            if (metadata != null && !metadata.isEmpty()) {
                objectMetadata.setUserMetadata(metadata);
            }
            client.putObject(bucket, fullKey(key), content, objectMetadata);
            com.aliyun.oss.model.ObjectMetadata stored = client.getObjectMetadata(bucket, fullKey(key));
            return map(key, stored);
        } catch (Exception e) {
            throw wrap("OSS 上传失败", e);
        }
    }

    @Override
    public InputStream open(String key) {
        try {
            OSSObject object = client.getObject(bucket, fullKey(key));
            return new FilterInputStream(object.getObjectContent()) {
                @Override
                public void close() throws IOException {
                    try {
                        super.close();
                    } finally {
                        object.close();
                    }
                }
            };
        } catch (Exception e) {
            throw wrap("OSS 下载失败", e);
        }
    }

    @Override
    public void copy(String sourceKey, String targetKey) {
        try {
            client.copyObject(bucket, fullKey(sourceKey), bucket, fullKey(targetKey));
        } catch (Exception e) {
            throw wrap("OSS 复制失败", e);
        }
    }

    @Override
    public void delete(String key) {
        try {
            client.deleteObject(bucket, fullKey(key));
        } catch (Exception e) {
            throw wrap("OSS 删除失败", e);
        }
    }

    @Override
    public boolean exists(String key) {
        try {
            return client.doesObjectExist(bucket, fullKey(key));
        } catch (Exception e) {
            throw wrap("OSS 对象检查失败", e);
        }
    }

    @Override
    public com.platform.file.domain.storage.ObjectMetadata stat(String key) {
        try {
            return map(key, client.getObjectMetadata(bucket, fullKey(key)));
        } catch (Exception e) {
            throw wrap("OSS 元数据读取失败", e);
        }
    }

    @Override
    public ObjectPage list(String prefix, String cursor, int limit) {
        try {
            ListObjectsRequest request = new ListObjectsRequest(bucket);
            request.setPrefix(fullKey(prefix == null ? "" : prefix));
            request.setMaxKeys(limit);
            if (cursor != null && !cursor.isBlank()) {
                request.setMarker(fullKey(cursor));
            }
            ObjectListing listing = client.listObjects(request);
            List<com.platform.file.domain.storage.ObjectMetadata> items = new ArrayList<>();
            for (OSSObjectSummary summary : listing.getObjectSummaries()) {
                items.add(new com.platform.file.domain.storage.ObjectMetadata(
                        logicalKey(summary.getKey()), summary.getSize(), null,
                        summary.getETag(), summary.getLastModified().toInstant(), Map.of()));
            }
            String next = listing.isTruncated() && !items.isEmpty() ? items.getLast().key() : null;
            return new ObjectPage(items, next);
        } catch (Exception e) {
            throw wrap("OSS 对象遍历失败", e);
        }
    }

    @Override
    public PresignedUpload presignUpload(String key, String contentType, long maxSize, Duration ttl) {
        try {
            Instant expiresAt = Instant.now().plus(ttl);
            GeneratePresignedUrlRequest request = new GeneratePresignedUrlRequest(
                    bucket, fullKey(key), HttpMethod.PUT);
            request.setExpiration(Date.from(expiresAt));
            if (contentType != null) {
                request.setContentType(contentType);
            }
            URL url = client.generatePresignedUrl(request);
            return new PresignedUpload(url.toString(), "PUT",
                    contentType == null ? Map.of() : Map.of("Content-Type", contentType),
                    expiresAt, Map.of("max_size", maxSize));
        } catch (Exception e) {
            throw wrap("OSS 上传授权生成失败", e);
        }
    }

    @Override
    public PresignedDownload presignDownload(String key, String filename, Duration ttl) {
        try {
            Instant expiresAt = Instant.now().plus(ttl);
            GeneratePresignedUrlRequest request = new GeneratePresignedUrlRequest(
                    bucket, fullKey(key), HttpMethod.GET);
            request.setExpiration(Date.from(expiresAt));
            ResponseHeaderOverrides headers = new ResponseHeaderOverrides();
            headers.setContentDisposition("attachment; filename=\"" + safeFilename(filename) + "\"");
            request.setResponseHeaders(headers);
            URL url = client.generatePresignedUrl(request);
            return new PresignedDownload(url.toString(), expiresAt);
        } catch (Exception e) {
            throw wrap("OSS 下载授权生成失败", e);
        }
    }

    @Override
    public MultipartHandle createMultipart(String key, String contentType, Map<String, String> metadata) {
        try {
            ObjectMetadata objectMetadata = new ObjectMetadata();
            if (contentType != null) {
                objectMetadata.setContentType(contentType);
            }
            if (metadata != null && !metadata.isEmpty()) {
                objectMetadata.setUserMetadata(metadata);
            }
            InitiateMultipartUploadRequest request = new InitiateMultipartUploadRequest(
                    bucket, fullKey(key), objectMetadata);
            InitiateMultipartUploadResult result = client.initiateMultipartUpload(request);
            return new MultipartHandle(result.getUploadId(), key);
        } catch (Exception e) {
            throw wrap("OSS 分片上传初始化失败", e);
        }
    }

    @Override
    public MultipartPart uploadPart(String key, String uploadId, int partNumber, InputStream content, long size) {
        try {
            UploadPartRequest request = new UploadPartRequest();
            request.setBucketName(bucket);
            request.setKey(fullKey(key));
            request.setUploadId(uploadId);
            request.setPartNumber(partNumber);
            request.setInputStream(content);
            request.setPartSize(size);
            var result = client.uploadPart(request);
            return new MultipartPart(partNumber, result.getPartETag().getETag(), size);
        } catch (Exception e) {
            throw wrap("OSS 分片上传失败", e);
        }
    }

    @Override
    public PartAuthorization presignPart(String key, String uploadId, int partNumber, Duration ttl) {
        try {
            Instant expiresAt = Instant.now().plus(ttl);
            GeneratePresignedUrlRequest request = new GeneratePresignedUrlRequest(
                    bucket, fullKey(key), HttpMethod.PUT);
            request.setExpiration(Date.from(expiresAt));
            request.addQueryParameter("uploadId", uploadId);
            request.addQueryParameter("partNumber", String.valueOf(partNumber));
            URL url = client.generatePresignedUrl(request);
            return new PartAuthorization(url.toString(), "PUT", Map.of(), expiresAt);
        } catch (Exception e) {
            throw wrap("OSS 分片授权生成失败", e);
        }
    }

    @Override
    public MultipartPart completeMultipart(String key, String uploadId, List<MultipartPart> parts) {
        try {
            List<PartETag> partETags = parts.stream()
                    .sorted(Comparator.comparingInt(MultipartPart::partNumber))
                    .map(part -> new PartETag(part.partNumber(), part.etag()))
                    .toList();
            CompleteMultipartUploadRequest request = new CompleteMultipartUploadRequest(
                    bucket, fullKey(key), uploadId, partETags);
            client.completeMultipartUpload(request);
            ObjectMetadata metadata = client.getObjectMetadata(bucket, fullKey(key));
            return new MultipartPart(parts.size(), metadata.getETag(), metadata.getContentLength());
        } catch (Exception e) {
            throw wrap("OSS 分片合并失败", e);
        }
    }

    @Override
    public void abortMultipart(String key, String uploadId) {
        try {
            client.abortMultipartUpload(new AbortMultipartUploadRequest(bucket, fullKey(key), uploadId));
        } catch (Exception e) {
            throw wrap("OSS 分片上传取消失败", e);
        }
    }

    @Override
    public StorageHealth health() {
        try {
            client.getBucketInfo(bucket);
            return StorageHealth.ok("OSS 存储连接正常");
        } catch (Exception e) {
            return StorageHealth.fail("OSS 存储连接失败: " + rootMessage(e));
        }
    }

    @Override
    public void close() {
        try {
            client.shutdown();
        } catch (Exception ignored) {
            // 关闭客户端异常不影响业务结果。
        }
    }

    private com.platform.file.domain.storage.ObjectMetadata map(String key, ObjectMetadata metadata) {
        return new com.platform.file.domain.storage.ObjectMetadata(
                key,
                metadata.getContentLength(),
                metadata.getContentType(),
                metadata.getETag(),
                metadata.getLastModified() == null ? null : metadata.getLastModified().toInstant(),
                metadata.getUserMetadata() == null ? Map.of() : metadata.getUserMetadata());
    }

    private String fullKey(String key) {
        String normalized = key == null ? "" : key;
        return rootPrefix.isEmpty() ? normalized : rootPrefix + "/" + normalized;
    }

    private String logicalKey(String fullKey) {
        if (rootPrefix.isEmpty()) {
            return fullKey;
        }
        String prefix = rootPrefix + "/";
        return fullKey.startsWith(prefix) ? fullKey.substring(prefix.length()) : fullKey;
    }

    private static String normalizePrefix(String value) {
        if (value == null) {
            return "";
        }
        String prefix = value.replace('\\', '/').trim();
        while (prefix.startsWith("/")) {
            prefix = prefix.substring(1);
        }
        while (prefix.endsWith("/")) {
            prefix = prefix.substring(0, prefix.length() - 1);
        }
        return prefix;
    }

    private StorageException wrap(String message, Exception e) {
        return new StorageException(message + ": " + rootMessage(e), e);
    }

    private static String rootMessage(Exception e) {
        Throwable cause = e;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        String text = cause.getMessage();
        if (text == null) {
            text = cause.getClass().getSimpleName();
        }
        return text.length() > 300 ? text.substring(0, 300) : text;
    }

    private static String safeFilename(String filename) {
        return filename == null ? "download" : filename.replace("\"", "");
    }
}
