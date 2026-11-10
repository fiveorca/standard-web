package com.platform.file.infrastructure.storage;

import com.platform.file.domain.model.StorageProviderConfig;
import com.platform.file.domain.storage.PartAuthorization;
import com.platform.file.domain.storage.PresignedDownload;
import com.platform.file.domain.storage.PresignedUpload;
import com.platform.file.domain.storage.StorageType;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 预签名在本地完成签名，不需要访问真实云服务即可验证 URL 与签名参数。
 */
class PresignProvidersTest {

    @Test
    void s3GeneratesPresignedUploadAndDownload() {
        S3StorageProvider provider = new S3StorageProvider(config(StorageType.S3,
                "https://s3.us-east-1.amazonaws.com", "us-east-1", "demo-bucket"));
        try {
            PresignedUpload upload = provider.presignUpload("temporary/u1/file.txt",
                    "text/plain", 1024, Duration.ofMinutes(5));
            assertTrue(upload.url().contains("X-Amz-Signature="));
            assertTrue(upload.url().contains("temporary/u1/file.txt"));
            assertEquals("text/plain", upload.headers().get("Content-Type"));

            PartAuthorization part = provider.presignPart("temporary/u1/file.txt",
                    "multipart-id", 1, Duration.ofMinutes(5));
            assertTrue(part.url().contains("partNumber=1"));

            PresignedDownload download = provider.presignDownload("permanent/2026/01/a.txt",
                    "a.txt", Duration.ofMinutes(5));
            assertTrue(download.url().contains("X-Amz-Signature="));
            assertTrue(download.expiresAt().isAfter(java.time.Instant.now()));
            assertEquals("S3", provider.type());
        } finally {
            provider.close();
        }
    }

    @Test
    void ossGeneratesPresignedUploadAndDownload() {
        OssStorageProvider provider = new OssStorageProvider(config(StorageType.OSS,
                "https://oss-cn-hangzhou.aliyuncs.com", "oss-cn-hangzhou", "demo-bucket"));
        try {
            PresignedUpload upload = provider.presignUpload("temporary/u1/file.txt",
                    "text/plain", 1024, Duration.ofMinutes(5));
            assertTrue(upload.url().startsWith("https://demo-bucket.oss-cn-hangzhou.aliyuncs.com/"));
            assertTrue(upload.url().contains("Signature="));

            PartAuthorization part = provider.presignPart("temporary/u1/file.txt",
                    "oss-multipart-id", 2, Duration.ofMinutes(5));
            assertTrue(part.url().contains("partNumber=2"));
            assertTrue(part.url().contains("uploadId=oss-multipart-id"));

            PresignedDownload download = provider.presignDownload("permanent/a.txt",
                    "a.txt", Duration.ofMinutes(5));
            assertNotNull(download.url());
            assertEquals("OSS", provider.type());
        } finally {
            provider.close();
        }
    }

    private static StorageProviderConfig config(StorageType type, String endpoint, String region,
                                                String bucket) {
        return new StorageProviderConfig(UUID.randomUUID(), "test-" + type.name().toLowerCase(),
                "测试存储", type, endpoint, region, bucket, null,
                "test-access-key", "test-secret-key", true, false, true, true, true,
                Map.of("path_style_access", false), 1);
    }
}
