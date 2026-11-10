package com.platform.file;

import com.platform.file.application.CleanupService;
import com.platform.file.application.FileService;
import com.platform.file.application.FileSourceService;
import com.platform.file.application.StorageProviderRegistry;
import com.platform.file.application.StorageProviderService;
import com.platform.file.application.UploadService;
import com.platform.file.application.command.CreateUploadCommand;
import com.platform.file.application.command.FileSourceCommand;
import com.platform.file.application.command.StorageProviderCommand;
import com.platform.file.domain.model.FileObject;
import com.platform.file.domain.model.StorageProviderRow;
import com.platform.file.domain.repository.FileObjectRepository;
import com.platform.file.domain.repository.StorageProviderRepository;
import com.platform.file.domain.storage.StorageProvider;
import com.platform.file.domain.storage.StorageType;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.Db;
import com.platform.file.shared.Hash;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.testcontainers.containers.PostgreSQLContainer;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("docker")
@SpringBootTest(classes = FileApplication.class, webEnvironment = SpringBootTest.WebEnvironment.MOCK,
        properties = "it.suite=local")
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class FileServiceIntegrationTest {

    private static final Path ROOT = createRoot();

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("file_service")
            .withUsername("file_service")
            .withPassword("file_service");

    static {
        // 该版本 Spring 的 @DynamicPropertySource 不会参与 @ConfigurationProperties 绑定，
        // 因此 file.* 配置通过系统属性注入（系统属性优先于 application.yml）。
        System.setProperty("file.storage.local-root", ROOT.toString());
        System.setProperty("file.storage.upload-work-dir", ROOT.resolve("work").toString());
        System.setProperty("file.security.max-file-size", String.valueOf(32L * 1024 * 1024));
        System.setProperty("file.upload.min-part-size", "1024");
        System.setProperty("file.upload.max-part-size", String.valueOf(1024L * 1024));
        System.setProperty("file.cleanup.enabled", "false");
        System.setProperty("file.cleanup.orphan-safety-minutes", "1");
        System.setProperty("file.cleanup.max-per-run", "500");
        System.setProperty("file.seed.enabled", "true");
        POSTGRES.start();
        System.setProperty("spring.datasource.url", POSTGRES.getJdbcUrl());
        System.setProperty("spring.datasource.username", POSTGRES.getUsername());
        System.setProperty("spring.datasource.password", POSTGRES.getPassword());
        System.setProperty("logging.level.root", "WARN");
    }

    @Autowired
    private StorageProviderService providerService;
    @Autowired
    private StorageProviderRepository providerRepository;
    @Autowired
    private StorageProviderRegistry registry;
    @Autowired
    private UploadService uploads;
    @Autowired
    private FileService files;
    @Autowired
    private FileSourceService fileSources;
    @Autowired
    private CleanupService cleanup;
    @Autowired
    private FileObjectRepository objects;
    @Autowired
    private Db db;

    private UUID providerId;

    @BeforeAll
    void setUpProvider() {
        fileSources.create(new FileSourceCommand("TEST", "集成测试", "测试来源", true));
        Map<String, Object> provider = providerService.create(new StorageProviderCommand(
                "it-local", "集成测试本地存储", StorageType.LOCAL, null, null, null,
                ROOT.toString(), null, null, null, null, true, true, true, true, true, Map.of()));
        providerId = UUID.fromString(String.valueOf(provider.get("id")));
    }

    @Test
    void serverUploadConfirmDownloadAndDeduplicate() throws Exception {
        byte[] payload = payload("server upload content");
        String sha = sha(payload);
        Map<String, Object> created = uploads.createServerUpload(command("hello.txt", payload.length));
        UUID uploadId = uuid(created, "upload_id");
        assertEquals("CREATED", created.get("status"));

        Map<String, Object> uploaded = uploads.uploadContent(uploadId,
                new ByteArrayInputStream(payload), payload.length, "text/plain");
        assertEquals("UPLOADED", uploaded.get("status"));

        Map<String, Object> confirmed = uploads.confirm(uploadId, sha);
        assertEquals("CONFIRMED", confirmed.get("status"));
        assertEquals("ACTIVE", file(confirmed).get("status"));
        assertEquals(sha, file(confirmed).get("sha256"));
        assertEquals((long) payload.length, ((Number) file(confirmed).get("file_size")).longValue());

        UUID fileId = uuid(confirmed, "file_id");
        Map<String, Object> download = files.downloadUrl(fileId, 120L);
        assertEquals("TOKEN", download.get("type"));
        String token = String.valueOf(download.get("token"));
        try (InputStream in = files.openContent(fileId, token).stream()) {
            assertEquals("server upload content", new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }

        Map<String, Object> duplicate = uploads.createServerUpload(command("copy.txt", payload.length));
        UUID duplicateUploadId = uuid(duplicate, "upload_id");
        uploads.uploadContent(duplicateUploadId, new ByteArrayInputStream(payload), payload.length, "text/plain");
        Map<String, Object> duplicateConfirmed = uploads.confirm(duplicateUploadId, sha);
        assertEquals(file(confirmed).get("file_object_id"), file(duplicateConfirmed).get("file_object_id"),
                "相同内容应复用同一个物理对象");
        assertEquals("ACTIVE", file(duplicateConfirmed).get("status"));
    }

    @Test
    void multipartUploadMergesAndConfirms() throws Exception {
        byte[] payload = new byte[3000];
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) (i % 97 + 32);
        }
        String sha = sha(payload);
        Map<String, Object> created = uploads.createMultipartUpload(
                command("multipart.txt", payload.length, 1024L));
        UUID uploadId = uuid(created, "upload_id");
        assertEquals(3, ((Number) created.get("parts_total")).intValue());

        uploads.uploadPart(uploadId, 1, new ByteArrayInputStream(Arrays.copyOfRange(payload, 0, 1024)), 1024);
        uploads.uploadPart(uploadId, 2, new ByteArrayInputStream(Arrays.copyOfRange(payload, 1024, 2048)), 1024);
        Map<String, Object> afterParts = uploads.uploadPart(uploadId, 3,
                new ByteArrayInputStream(Arrays.copyOfRange(payload, 2048, 3000)), 952);
        assertEquals(3, ((Number) afterParts.get("parts_completed")).intValue());

        Map<String, Object> completed = uploads.completeMultipart(uploadId);
        assertEquals("UPLOADED", completed.get("status"));

        Map<String, Object> confirmed = uploads.confirm(uploadId, sha);
        assertEquals("ACTIVE", file(confirmed).get("status"));
        UUID fileId = uuid(confirmed, "file_id");
        String token = String.valueOf(files.downloadUrl(fileId, 60L).get("token"));
        try (InputStream in = files.openContent(fileId, token).stream()) {
            assertTrue(Arrays.equals(payload, in.readAllBytes()));
        }
    }

    @Test
    void deleteKeepsObjectUntilLastReferenceThenReclaims() throws Exception {
        byte[] payload = payload("shared content for reference counting");
        String sha = sha(payload);
        UUID firstUpload = uuid(uploads.createServerUpload(command("ref-1.txt", payload.length)), "upload_id");
        uploads.uploadContent(firstUpload, new ByteArrayInputStream(payload), payload.length, "text/plain");
        Map<String, Object> first = uploads.confirm(firstUpload, sha);
        UUID secondUpload = uuid(uploads.createServerUpload(command("ref-2.txt", payload.length)), "upload_id");
        uploads.uploadContent(secondUpload, new ByteArrayInputStream(payload), payload.length, "text/plain");
        Map<String, Object> second = uploads.confirm(secondUpload, sha);

        UUID firstFileId = uuid(first, "file_id");
        UUID secondFileId = uuid(second, "file_id");
        UUID objectId = UUID.fromString(String.valueOf(file(first).get("file_object_id")));
        FileObject object = objects.findById(objectId).orElseThrow();
        String objectKey = object.objectKey();

        Map<String, Object> firstDelete = files.delete(firstFileId, "tester");
        assertEquals(1L, ((Number) firstDelete.get("references")).longValue());
        assertFalse(Boolean.TRUE.equals(firstDelete.get("physical_delete_scheduled")));

        Map<String, Object> secondDelete = files.delete(secondFileId, "tester");
        assertEquals(0L, ((Number) secondDelete.get("references")).longValue());
        assertTrue(Boolean.TRUE.equals(secondDelete.get("physical_delete_scheduled")));
        assertEquals("PENDING_DELETE", objects.findById(objectId).orElseThrow().status());

        objects.markPendingDelete(objectId, Instant.now().minusSeconds(5));
        Map<String, Object> task = cleanup.physicalDelete(false);
        assertEquals("SUCCESS", task.get("status"));
        assertTrue(((Number) task.get("deleted")).intValue() >= 1);

        StorageProviderRow row = providerRepository.findById(providerId).orElseThrow();
        StorageProvider provider = registry.get(row);
        assertFalse(provider.exists(objectKey), "引用计数归零后物理文件应被回收");
        assertEquals("DELETED", objects.findById(objectId).orElseThrow().status());
        assertEquals(404, assertThrows(ApiException.class,
                () -> files.downloadUrl(firstFileId, 60L)).status());
    }

    @Test
    void cancelAndExpireRejectConfirmation() {
        Map<String, Object> created = uploads.createServerUpload(command("cancel.txt", 4));
        UUID uploadId = uuid(created, "upload_id");
        Map<String, Object> cancelled = uploads.cancel(uploadId);
        assertEquals("CANCELLED", cancelled.get("status"));
        ApiException error = assertThrows(ApiException.class, () -> uploads.confirm(uploadId, null));
        assertEquals(410, error.status());

        Map<String, Object> expiring = uploads.createServerUpload(command("expire.txt", 4));
        UUID expiringId = uuid(expiring, "upload_id");
        db.update("UPDATE upload_session SET expires_at = now() - interval '5 minutes' WHERE id = :id",
                Db.params("id", expiringId));
        assertEquals(1, uploads.expireDueSessions(10));
        assertEquals("EXPIRED", uploads.detail(expiringId).get("status"));
    }

    @Test
    void rejectsDirectUploadForLocalProvider() {
        ApiException error = assertThrows(ApiException.class,
                () -> uploads.createDirectUpload(command("direct.txt", 10), false));
        assertEquals(422, error.status());
        assertTrue(String.valueOf(error.details().get("mode")).contains("直传"));
    }

    @Test
    void orphanScanSupportsDryRunAndDeletesRealOrphans() throws Exception {
        Path orphan = ROOT.resolve("permanent/orphan/manual.txt");
        Files.createDirectories(orphan.getParent());
        Files.writeString(orphan, "orphan");
        Files.setLastModifiedTime(orphan, FileTime.from(Instant.now().minusSeconds(300)));

        Map<String, Object> dryRun = cleanup.scanOrphans(providerId, true);
        assertEquals("SUCCESS", dryRun.get("status"));
        assertTrue(((Number) dryRun.get("deleted")).intValue() >= 1);
        assertTrue(Files.exists(orphan), "Dry Run 不应删除真实文件");

        Map<String, Object> real = cleanup.scanOrphans(providerId, false);
        assertEquals("SUCCESS", real.get("status"));
        assertTrue(((Number) real.get("deleted")).intValue() >= 1);
        assertFalse(Files.exists(orphan));
    }

    @Test
    void consistencyCheckQuarantinesMissingPhysicalFile() throws Exception {
        byte[] payload = payload("file will disappear from storage");
        String sha = sha(payload);
        UUID uploadId = uuid(uploads.createServerUpload(command("vanish.txt", payload.length)), "upload_id");
        uploads.uploadContent(uploadId, new ByteArrayInputStream(payload), payload.length, "text/plain");
        Map<String, Object> confirmed = uploads.confirm(uploadId, sha);
        UUID fileId = uuid(confirmed, "file_id");
        UUID objectId = UUID.fromString(String.valueOf(file(confirmed).get("file_object_id")));
        String objectKey = objects.findById(objectId).orElseThrow().objectKey();

        Files.delete(ROOT.resolve(objectKey));
        Map<String, Object> task = cleanup.consistencyCheck(false);
        assertEquals("SUCCESS", task.get("status"));
        assertTrue(((Number) task.get("repaired")).intValue() >= 1);
        assertEquals("QUARANTINED", objects.findById(objectId).orElseThrow().status());
        assertEquals("QUARANTINED", file(files.detail(fileId)).get("status"));
    }

    @Test
    void concurrentUploadsOfSameContentReuseOneObject() throws Exception {
        byte[] payload = payload("concurrent upload same content");
        String sha = sha(payload);
        int concurrency = 6;
        List<UUID> fileIds = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        List<UUID> objectIds = java.util.Collections.synchronizedList(new java.util.ArrayList<>());
        List<Throwable> failures = java.util.Collections.synchronizedList(new java.util.ArrayList<>());

        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(concurrency);
        try {
            List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < concurrency; i++) {
                int index = i;
                futures.add(pool.submit(() -> {
                    try {
                        UUID uploadId = uuid(uploads.createServerUpload(
                                command("concurrent-" + index + ".txt", payload.length)), "upload_id");
                        uploads.uploadContent(uploadId, new ByteArrayInputStream(payload), payload.length, "text/plain");
                        Map<String, Object> confirmed = confirmWithRetry(uploadId, sha);
                        fileIds.add(uuid(confirmed, "file_id"));
                        objectIds.add(UUID.fromString(String.valueOf(file(confirmed).get("file_object_id"))));
                    } catch (Throwable e) {
                        failures.add(e);
                    }
                }));
            }
            for (java.util.concurrent.Future<?> future : futures) {
                future.get(60, java.util.concurrent.TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }

        assertTrue(failures.isEmpty(), "并发确认失败: " + failures);
        assertEquals(concurrency, fileIds.size());
        assertEquals(1, objectIds.stream().distinct().count(), "并发上传相同内容必须复用同一物理对象");
        long activeObjects = db.count("""
                SELECT count(*) FROM file_object
                WHERE storage_provider_id = :provider AND sha256 = :sha AND status = 'ACTIVE'
                """, Db.params("provider", providerId, "sha", sha));
        assertEquals(1L, activeObjects, "同一内容只能存在一个 ACTIVE 物理对象");
        long activeRecords = db.count("""
                SELECT count(*) FROM file_record
                WHERE file_object_id = :object AND status = 'ACTIVE' AND deleted_at IS NULL
                """, Db.params("object", objectIds.getFirst()));
        assertEquals((long) concurrency, activeRecords);
    }

    @Test
    void consistencyCheckFailsStaleMigratingUpload() throws Exception {
        byte[] payload = payload("stale migrating content");
        UUID uploadId = uuid(uploads.createServerUpload(command("migrating.txt", payload.length)), "upload_id");
        uploads.uploadContent(uploadId, new ByteArrayInputStream(payload), payload.length, "text/plain");
        Map<String, Object> session = uploads.detail(uploadId);
        UUID fileId = UUID.fromString(String.valueOf(session.get("file_id")));
        UUID objectId = UUID.fromString(String.valueOf(session.get("file_object_id")));

        db.update("UPDATE upload_session SET status = 'CONFIRMING', updated_at = now() - interval '2 hours' "
                + "WHERE id = :id", Db.params("id", uploadId));
        db.update("UPDATE file_object SET status = 'MIGRATING', updated_at = now() - interval '2 hours' "
                + "WHERE id = :id", Db.params("id", objectId));
        db.update("UPDATE file_record SET status = 'PENDING_UPLOAD' WHERE id = :id", Db.params("id", fileId));

        Map<String, Object> task = cleanup.consistencyCheck(false);
        assertEquals("SUCCESS", task.get("status"));
        assertEquals("FAILED", uploads.detail(uploadId).get("status"));
        assertEquals("FAILED", objects.findById(objectId).orElseThrow().status());
    }

    @Test
    void listsCleanupTasksAndSourceStats() {
        cleanup.uploadExpiry();
        Map<String, Object> tasks = cleanup.tasks(null, null,
                com.platform.file.shared.PageQuery.of(Map.of("page", "1", "page_size", "5")));
        assertNotNull(tasks.get("items"));
        assertTrue(((Number) tasks.get("total")).intValue() >= 1);
        assertNotNull(files.sourceStats());
        assertNotNull(files.stats());
    }

    private Map<String, Object> confirmWithRetry(UUID uploadId, String sha) throws Exception {
        ApiException last = null;
        for (int attempt = 0; attempt < 10; attempt++) {
            try {
                return uploads.confirm(uploadId, sha);
            } catch (ApiException e) {
                // 并发去重时另一个任务可能正在处理相同内容，按设计文档要求进行有限重试。
                if (e.status() != 409) {
                    throw e;
                }
                last = e;
                Thread.sleep(100);
            }
        }
        throw last == null ? new IllegalStateException("确认失败") : last;
    }

    private CreateUploadCommand command(String filename, long size) {
        return command(filename, size, null);
    }

    private CreateUploadCommand command(String filename, long size, Long partSize) {
        return new CreateUploadCommand(providerId, filename, filename, "text/plain", size,
                "TEST", "source-" + filename, null, "tester", null, Map.of(),
                null, partSize);
    }

    private static byte[] payload(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static String sha(byte[] payload) {
        return Hash.sha256(new ByteArrayInputStream(payload));
    }

    private static UUID uuid(Map<String, Object> view, String key) {
        return UUID.fromString(String.valueOf(view.get(key)));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> file(Map<String, Object> view) {
        return (Map<String, Object>) view.get("file");
    }

    private static Path createRoot() {
        try {
            return Files.createTempDirectory("file-service-it-");
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}
