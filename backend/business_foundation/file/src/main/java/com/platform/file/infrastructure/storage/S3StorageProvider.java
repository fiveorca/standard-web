package com.platform.file.infrastructure.storage;

import com.platform.file.domain.model.StorageProviderConfig;
import com.platform.file.domain.storage.MultipartHandle;
import com.platform.file.domain.storage.MultipartPart;
import com.platform.file.domain.storage.ObjectMetadata;
import com.platform.file.domain.storage.ObjectPage;
import com.platform.file.domain.storage.PartAuthorization;
import com.platform.file.domain.storage.PresignedDownload;
import com.platform.file.domain.storage.PresignedUpload;
import com.platform.file.domain.storage.StorageCapabilities;
import com.platform.file.domain.storage.StorageException;
import com.platform.file.domain.storage.StorageHealth;
import com.platform.file.domain.storage.StorageProvider;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.AbortMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CopyObjectRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectResponse;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.S3Object;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedUploadPartRequest;
import software.amazon.awssdk.services.s3.presigner.model.PutObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.UploadPartPresignRequest;

import java.io.InputStream;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class S3StorageProvider implements StorageProvider {
    private final StorageProviderConfig config;
    private final S3Client client;
    private final S3Presigner presigner;
    private final String bucket;
    private final String rootPrefix;

    public S3StorageProvider(StorageProviderConfig config) {
        this.config = config;
        if (config.bucket() == null || config.bucket().isBlank()) {
            throw new StorageException("S3 存储必须配置 bucket");
        }
        if (config.accessKey() == null || config.secretKey() == null) {
            throw new StorageException("S3 存储缺少访问凭据");
        }
        this.bucket = config.bucket();
        this.rootPrefix = normalizePrefix(config.rootPath());
        Region region = Region.of(config.region() == null || config.region().isBlank() ? "us-east-1" : config.region());
        StaticCredentialsProvider credentials = StaticCredentialsProvider.create(
                AwsBasicCredentials.create(config.accessKey(), config.secretKey()));
        S3ClientBuilder clientBuilder = S3Client.builder()
                .region(region)
                .credentialsProvider(credentials);
        S3Presigner.Builder presignerBuilder = S3Presigner.builder()
                .region(region)
                .credentialsProvider(credentials);
        if (config.endpoint() != null && !config.endpoint().isBlank()) {
            URI endpoint = URI.create(config.endpoint());
            boolean pathStyle = optionBool("path_style_access", true);
            clientBuilder.endpointOverride(endpoint)
                    .serviceConfiguration(S3Configuration.builder()
                            .pathStyleAccessEnabled(pathStyle)
                            .build());
            presignerBuilder.endpointOverride(endpoint)
                    .serviceConfiguration(S3Configuration.builder()
                            .pathStyleAccessEnabled(pathStyle)
                            .build());
        }
        this.client = clientBuilder.build();
        this.presigner = presignerBuilder.build();
    }

    @Override
    public String type() {
        return "S3";
    }

    @Override
    public StorageCapabilities capabilities() {
        return new StorageCapabilities(true, true, true, true, true);
    }

    @Override
    public ObjectMetadata put(String key, InputStream content, long size, String contentType,
                              Map<String, String> metadata) {
        try {
            String full = fullKey(key);
            PutObjectRequest.Builder request = PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(full)
                    .contentType(contentType)
                    .metadata(metadata == null ? Map.of() : metadata);
            RequestBody body = size >= 0
                    ? RequestBody.fromInputStream(content, size)
                    : RequestBody.fromBytes(content.readAllBytes());
            var response = client.putObject(request.build(), body);
            return new ObjectMetadata(key, size >= 0 ? size : stat(key).size(), contentType,
                    response.eTag(), Instant.now(), metadata == null ? Map.of() : metadata);
        } catch (Exception e) {
            throw wrap("S3 上传失败", e);
        }
    }

    @Override
    public InputStream open(String key) {
        try {
            ResponseInputStream<GetObjectResponse> stream = client.getObject(
                    GetObjectRequest.builder().bucket(bucket).key(fullKey(key)).build());
            return stream;
        } catch (Exception e) {
            throw wrap("S3 下载失败", e);
        }
    }

    @Override
    public void copy(String sourceKey, String targetKey) {
        try {
            client.copyObject(CopyObjectRequest.builder()
                    .sourceBucket(bucket)
                    .sourceKey(fullKey(sourceKey))
                    .destinationBucket(bucket)
                    .destinationKey(fullKey(targetKey))
                    .build());
        } catch (Exception e) {
            throw wrap("S3 复制失败", e);
        }
    }

    @Override
    public void delete(String key) {
        try {
            client.deleteObject(DeleteObjectRequest.builder().bucket(bucket).key(fullKey(key)).build());
        } catch (Exception e) {
            throw wrap("S3 删除失败", e);
        }
    }

    @Override
    public boolean exists(String key) {
        try {
            client.headObject(HeadObjectRequest.builder().bucket(bucket).key(fullKey(key)).build());
            return true;
        } catch (S3Exception e) {
            if (e.statusCode() == 404) {
                return false;
            }
            throw wrap("S3 对象检查失败", e);
        } catch (Exception e) {
            throw wrap("S3 对象检查失败", e);
        }
    }

    @Override
    public ObjectMetadata stat(String key) {
        try {
            HeadObjectResponse response = client.headObject(
                    HeadObjectRequest.builder().bucket(bucket).key(fullKey(key)).build());
            return new ObjectMetadata(key, response.contentLength(), response.contentType(),
                    response.eTag(), response.lastModified(), response.metadata());
        } catch (Exception e) {
            throw wrap("S3 元数据读取失败", e);
        }
    }

    @Override
    public ObjectPage list(String prefix, String cursor, int limit) {
        try {
            String fullPrefix = fullKey(prefix == null ? "" : prefix);
            ListObjectsV2Request.Builder request = ListObjectsV2Request.builder()
                    .bucket(bucket)
                    .prefix(fullPrefix)
                    .maxKeys(limit);
            if (cursor != null && !cursor.isBlank()) {
                request.startAfter(fullKey(cursor));
            }
            ListObjectsV2Response response = client.listObjectsV2(request.build());
            List<ObjectMetadata> items = new ArrayList<>();
            for (S3Object object : response.contents()) {
                items.add(new ObjectMetadata(logicalKey(object.key()), object.size(), null,
                        object.eTag(), object.lastModified(), Map.of()));
            }
            String next = Boolean.TRUE.equals(response.isTruncated()) && !items.isEmpty()
                    ? items.getLast().key() : null;
            return new ObjectPage(items, next);
        } catch (Exception e) {
            throw wrap("S3 对象遍历失败", e);
        }
    }

    @Override
    public PresignedUpload presignUpload(String key, String contentType, long maxSize, Duration ttl) {
        try {
            PutObjectRequest put = PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(fullKey(key))
                    .contentType(contentType)
                    .build();
            PresignedPutObjectRequest presigned = presigner.presignPutObject(
                    PutObjectPresignRequest.builder()
                            .signatureDuration(ttl)
                            .putObjectRequest(put)
                            .build());
            Map<String, String> headers = contentType == null || contentType.isBlank()
                    ? Map.of() : Map.of("Content-Type", contentType);
            return new PresignedUpload(presigned.url().toString(), "PUT", headers,
                    Instant.now().plus(ttl), Map.of("max_size", maxSize));
        } catch (Exception e) {
            throw wrap("S3 上传授权生成失败", e);
        }
    }

    @Override
    public PresignedDownload presignDownload(String key, String filename, Duration ttl) {
        try {
            GetObjectRequest get = GetObjectRequest.builder()
                    .bucket(bucket)
                    .key(fullKey(key))
                    .responseContentDisposition("attachment; filename=\"" + safeFilename(filename) + "\"")
                    .build();
            PresignedGetObjectRequest presigned = presigner.presignGetObject(
                    GetObjectPresignRequest.builder()
                            .signatureDuration(ttl)
                            .getObjectRequest(get)
                            .build());
            return new PresignedDownload(presigned.url().toString(), Instant.now().plus(ttl));
        } catch (Exception e) {
            throw wrap("S3 下载授权生成失败", e);
        }
    }

    @Override
    public MultipartHandle createMultipart(String key, String contentType, Map<String, String> metadata) {
        try {
            var response = client.createMultipartUpload(CreateMultipartUploadRequest.builder()
                    .bucket(bucket)
                    .key(fullKey(key))
                    .contentType(contentType)
                    .metadata(metadata == null ? Map.of() : metadata)
                    .build());
            return new MultipartHandle(response.uploadId(), key);
        } catch (Exception e) {
            throw wrap("S3 分片上传初始化失败", e);
        }
    }

    @Override
    public MultipartPart uploadPart(String key, String uploadId, int partNumber, InputStream content, long size) {
        try {
            var response = client.uploadPart(UploadPartRequest.builder()
                    .bucket(bucket)
                    .key(fullKey(key))
                    .uploadId(uploadId)
                    .partNumber(partNumber)
                    .contentLength(size)
                    .build(), RequestBody.fromInputStream(content, size));
            return new MultipartPart(partNumber, response.eTag(), size);
        } catch (Exception e) {
            throw wrap("S3 分片上传失败", e);
        }
    }

    @Override
    public PartAuthorization presignPart(String key, String uploadId, int partNumber, Duration ttl) {
        try {
            UploadPartRequest part = UploadPartRequest.builder()
                    .bucket(bucket)
                    .key(fullKey(key))
                    .uploadId(uploadId)
                    .partNumber(partNumber)
                    .build();
            PresignedUploadPartRequest presigned = presigner.presignUploadPart(
                    UploadPartPresignRequest.builder()
                            .signatureDuration(ttl)
                            .uploadPartRequest(part)
                            .build());
            return new PartAuthorization(presigned.url().toString(), "PUT", Map.of(),
                    Instant.now().plus(ttl));
        } catch (Exception e) {
            throw wrap("S3 分片授权生成失败", e);
        }
    }

    @Override
    public MultipartPart completeMultipart(String key, String uploadId, List<MultipartPart> parts) {
        try {
            List<CompletedPart> completed = parts.stream()
                    .sorted(java.util.Comparator.comparingInt(MultipartPart::partNumber))
                    .map(part -> CompletedPart.builder().partNumber(part.partNumber()).eTag(part.etag()).build())
                    .toList();
            client.completeMultipartUpload(CompleteMultipartUploadRequest.builder()
                    .bucket(bucket)
                    .key(fullKey(key))
                    .uploadId(uploadId)
                    .multipartUpload(CompletedMultipartUpload.builder().parts(completed).build())
                    .build());
            ObjectMetadata metadata = stat(key);
            return new MultipartPart(parts.size(), metadata.etag(), metadata.size());
        } catch (Exception e) {
            throw wrap("S3 分片合并失败", e);
        }
    }

    @Override
    public void abortMultipart(String key, String uploadId) {
        try {
            client.abortMultipartUpload(AbortMultipartUploadRequest.builder()
                    .bucket(bucket)
                    .key(fullKey(key))
                    .uploadId(uploadId)
                    .build());
        } catch (Exception e) {
            throw wrap("S3 分片上传取消失败", e);
        }
    }

    @Override
    public StorageHealth health() {
        try {
            client.headBucket(HeadBucketRequest.builder().bucket(bucket).build());
            return StorageHealth.ok("S3 存储连接正常");
        } catch (Exception e) {
            return StorageHealth.fail("S3 存储连接失败: " + rootMessage(e));
        }
    }

    @Override
    public void close() {
        try {
            client.close();
        } catch (Exception ignored) {
            // 关闭客户端时的异常不影响业务结果。
        }
        try {
            presigner.close();
        } catch (Exception ignored) {
            // 同上。
        }
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

    private boolean optionBool(String name, boolean fallback) {
        Object value = config.options() == null ? null : config.options().get(name);
        if (value == null) {
            return fallback;
        }
        return value instanceof Boolean b ? b : Boolean.parseBoolean(String.valueOf(value));
    }

    private static String safeFilename(String filename) {
        return filename == null ? "download" : filename.replace("\"", "");
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
}
