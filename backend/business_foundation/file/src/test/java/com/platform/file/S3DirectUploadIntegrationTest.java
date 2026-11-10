package com.platform.file;

import com.platform.file.application.FileService;
import com.platform.file.application.FileSourceService;
import com.platform.file.application.StorageProviderService;
import com.platform.file.application.UploadService;
import com.platform.file.application.command.CreateUploadCommand;
import com.platform.file.application.command.FileSourceCommand;
import com.platform.file.application.command.StorageProviderCommand;
import com.platform.file.domain.storage.MultipartPart;
import com.platform.file.domain.storage.StorageType;
import com.platform.file.shared.Hash;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 使用 MinIO（S3 兼容）验证客户端直传链路：预签名 PUT、分片授权、服务端校验、确认迁移与预签名下载。
 */
@Tag("docker")
@SpringBootTest(classes = FileApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK,
        properties = "it.suite=s3")
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class S3DirectUploadIntegrationTest {

    private static final String BUCKET = "file-it";
    private static final String ACCESS_KEY = "minioadmin";
    private static final String SECRET_KEY = "minioadmin";
    private static final Path ROOT = createRoot();

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("file_service")
            .withUsername("file_service")
            .withPassword("file_service");

    static final GenericContainer<?> MINIO = new GenericContainer<>(
            DockerImageName.parse(System.getProperty("file.it.minio-image", "minio/minio:latest")))
            .withExposedPorts(9000)
            .withEnv("MINIO_ROOT_USER", ACCESS_KEY)
            .withEnv("MINIO_ROOT_PASSWORD", SECRET_KEY)
            .withCommand("server", "/data");

    static {
        System.setProperty("file.storage.local-root", ROOT.toString());
        System.setProperty("file.storage.upload-work-dir", ROOT.resolve("work").toString());
        System.setProperty("file.security.max-file-size", String.valueOf(64L * 1024 * 1024));
        System.setProperty("file.upload.min-part-size", "1024");
        System.setProperty("file.upload.max-part-size", String.valueOf(16L * 1024 * 1024));
        System.setProperty("file.cleanup.enabled", "false");
        System.setProperty("file.seed.enabled", "true");
        POSTGRES.start();
        try {
            MINIO.start();
            minioAvailable = true;
        } catch (Throwable e) {
            // 本地 Docker 无法拉取 MinIO 镜像时跳过该组用例，不影响其它集成测试。
            minioAvailable = false;
        }
        System.setProperty("spring.datasource.url", POSTGRES.getJdbcUrl());
        System.setProperty("spring.datasource.username", POSTGRES.getUsername());
        System.setProperty("spring.datasource.password", POSTGRES.getPassword());
        System.setProperty("logging.level.root", "WARN");
    }

    private static boolean minioAvailable;

    @Autowired
    private StorageProviderService providerService;
    @Autowired
    private UploadService uploads;
    @Autowired
    private FileService files;
    @Autowired
    private FileSourceService fileSources;

    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10)).build();

    private UUID providerId;

    @BeforeAll
    void setUpProvider() {
        org.junit.jupiter.api.Assumptions.assumeTrue(minioAvailable, "MinIO 镜像不可用，跳过 S3 直传集成测试");
        fileSources.create(new FileSourceCommand("S3TEST", "对象存储集成测试", "MinIO 直传测试", true));
        Map<String, Object> provider = providerService.create(new StorageProviderCommand(
                "it-s3", "MinIO 测试存储", StorageType.S3, endpoint(), "us-east-1", BUCKET,
                "it-root", ACCESS_KEY, SECRET_KEY, null, null,
                true, false, true, true, true, Map.of("path_style_access", true)));
        providerId = UUID.fromString(String.valueOf(provider.get("id")));
        createBucket();
    }

    @Test
    void directUploadConfirmsAndDownloads() throws Exception {
        byte[] payload = "direct upload to minio".getBytes(StandardCharsets.UTF_8);
        String sha = sha(payload);
        Map<String, Object> created = uploads.createDirectUpload(command("direct.txt", payload.length), false);
        UUID uploadId = uuid(created, "upload_id");

        @SuppressWarnings("unchecked")
        Map<String, Object> authorization = (Map<String, Object>) created.get("authorization");
        assertEquals("PRE_SIGNED_PUT", authorization.get("type"));
        HttpResponse<String> put = put((String) authorization.get("url"),
                headers(authorization), payload);
        assertEquals(200, put.statusCode(), "预签名上传失败: " + put.body());

        Map<String, Object> completed = uploads.completeDirect(uploadId, null, sha);
        assertEquals("UPLOADED", completed.get("status"));

        Map<String, Object> confirmed = uploads.confirm(uploadId, sha);
        assertEquals("CONFIRMED", confirmed.get("status"));
        assertEquals(sha, file(confirmed).get("sha256"));

        UUID fileId = uuid(confirmed, "file_id");
        Map<String, Object> download = files.downloadUrl(fileId, 120L);
        assertEquals("PRE_SIGNED_URL", download.get("type"));
        byte[] downloaded = get(String.valueOf(download.get("url")), headers(download));
        assertArrayEquals(payload, downloaded);
    }

    @Test
    void directMultipartUploadConfirmsAndDownloads() throws Exception {
        int partSize = 5 * 1024 * 1024;
        byte[] payload = new byte[partSize + 4096];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) ('a' + i % 26);
        }
        String sha = sha(payload);
        Map<String, Object> created = uploads.createDirectUpload(
                command("multipart-direct.bin", payload.length, (long) partSize), true);
        UUID uploadId = uuid(created, "upload_id");
        assertEquals(2, ((Number) created.get("parts_total")).intValue());

        Map<String, Object> authorized = uploads.authorizeParts(uploadId, List.of(1, 2));
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> parts = (List<Map<String, Object>>) authorized.get("parts");
        assertEquals(2, parts.size());

        List<MultipartPart> uploaded = new ArrayList<>();
        for (Map<String, Object> part : parts) {
            int number = ((Number) part.get("part_number")).intValue();
            int from = (number - 1) * partSize;
            int to = Math.min(payload.length, from + partSize);
            byte[] chunk = Arrays.copyOfRange(payload, from, to);
            HttpResponse<String> response = put(String.valueOf(part.get("url")), headers(part), chunk);
            assertEquals(200, response.statusCode(), "分片 " + number + " 上传失败: " + response.body());
            String etag = response.headers().firstValue("ETag")
                    .orElseThrow(() -> new IllegalStateException("MinIO 未返回 ETag"));
            uploaded.add(new MultipartPart(number, etag, chunk.length));
        }

        Map<String, Object> completed = uploads.completeDirect(uploadId, uploaded, sha);
        assertEquals("UPLOADED", completed.get("status"));
        Map<String, Object> confirmed = uploads.confirm(uploadId, sha);
        assertEquals("CONFIRMED", confirmed.get("status"));

        UUID fileId = uuid(confirmed, "file_id");
        Map<String, Object> download = files.downloadUrl(fileId, 120L);
        byte[] downloaded = get(String.valueOf(download.get("url")), headers(download));
        assertArrayEquals(payload, downloaded);
    }

    @Test
    void rejectsDirectCompletionWhenObjectMissing() {
        Map<String, Object> created = uploads.createDirectUpload(command("missing.txt", 8), false);
        UUID uploadId = uuid(created, "upload_id");
        com.platform.file.shared.ApiException error = org.junit.jupiter.api.Assertions.assertThrows(
                com.platform.file.shared.ApiException.class,
                () -> uploads.completeDirect(uploadId, null, null));
        assertEquals(409, error.status());
        assertTrue(error.getMessage().contains("尚未检测到上传对象"));
    }

    private CreateUploadCommand command(String filename, long size) {
        return command(filename, size, null);
    }

    private CreateUploadCommand command(String filename, long size, Long partSize) {
        return new CreateUploadCommand(providerId, filename, filename, "text/plain", size,
                "S3TEST", "source-" + filename, null, "tester", null, Map.of(), null, partSize);
    }

    private void createBucket() {
        try (S3Client client = S3Client.builder()
                .endpointOverride(URI.create(endpoint()))
                .region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(
                        AwsBasicCredentials.create(ACCESS_KEY, SECRET_KEY)))
                .serviceConfiguration(S3Configuration.builder().pathStyleAccessEnabled(true).build())
                .build()) {
            client.createBucket(CreateBucketRequest.builder().bucket(BUCKET).build());
        }
    }

    private static String endpoint() {
        return "http://" + MINIO.getHost() + ":" + MINIO.getMappedPort(9000);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> headers(Map<String, Object> authorization) {
        Object raw = authorization.get("headers");
        return raw == null ? Map.of() : (Map<String, String>) raw;
    }

    private HttpResponse<String> put(String url, Map<String, String> headers, byte[] body) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(30))
                .PUT(HttpRequest.BodyPublishers.ofByteArray(body));
        headers.forEach(request::header);
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private byte[] get(String url, Map<String, String> headers) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url))
                .timeout(Duration.ofSeconds(30)).GET();
        headers.forEach(request::header);
        HttpResponse<byte[]> response = http.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
        assertEquals(200, response.statusCode(), "预签名下载失败");
        return response.body();
    }

    private static String sha(byte[] payload) {
        return Hash.sha256(new java.io.ByteArrayInputStream(payload));
    }

    private static UUID uuid(Map<String, Object> view, String key) {
        Object value = view.get(key);
        assertNotNull(value, "缺少字段 " + key);
        return UUID.fromString(String.valueOf(value));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> file(Map<String, Object> view) {
        return (Map<String, Object>) view.get("file");
    }

    private static Path createRoot() {
        try {
            return Files.createTempDirectory("file-service-s3-it-");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
