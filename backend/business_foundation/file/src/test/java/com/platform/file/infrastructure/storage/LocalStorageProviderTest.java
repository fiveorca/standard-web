package com.platform.file.infrastructure.storage;

import com.platform.file.domain.model.StorageProviderConfig;
import com.platform.file.domain.storage.MultipartHandle;
import com.platform.file.domain.storage.MultipartPart;
import com.platform.file.domain.storage.ObjectMetadata;
import com.platform.file.domain.storage.ObjectPage;
import com.platform.file.domain.storage.StorageException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LocalStorageProviderTest {

    @TempDir
    Path tempDir;

    private LocalStorageProvider provider;

    @BeforeEach
    void setUp() {
        provider = new LocalStorageProvider(config(tempDir.toString()));
    }

    @AfterEach
    void tearDown() {
        provider.close();
    }

    @Test
    void writesReadsCopiesAndDeletesObject() throws Exception {
        byte[] payload = "local storage content".getBytes(StandardCharsets.UTF_8);
        ObjectMetadata metadata = provider.put("permanent/2026/01/a.txt",
                new ByteArrayInputStream(payload), payload.length, "text/plain", Map.of());
        assertEquals(payload.length, metadata.size());
        assertTrue(provider.exists("permanent/2026/01/a.txt"));

        String content;
        try (InputStream in = provider.open("permanent/2026/01/a.txt")) {
            content = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        assertEquals("local storage content", content);

        provider.copy("permanent/2026/01/a.txt", "permanent/2026/01/b.txt");
        assertTrue(provider.exists("permanent/2026/01/b.txt"));

        provider.delete("permanent/2026/01/a.txt");
        assertFalse(provider.exists("permanent/2026/01/a.txt"));
        assertTrue(provider.health().ok());
    }

    @Test
    void rejectsPathTraversal() {
        StorageException error = assertThrows(StorageException.class,
                () -> provider.put("../escape.txt", new ByteArrayInputStream(new byte[]{1}), 1,
                        "text/plain", Map.of()));
        assertTrue(error.getMessage().contains("Key"));
        assertThrows(StorageException.class, () -> provider.open("/absolute.txt"));
        assertThrows(StorageException.class, () -> provider.exists("a/../../b"));
    }

    @Test
    void failsWhenDeclaredSizeDoesNotMatch() {
        assertThrows(StorageException.class, () -> provider.put("permanent/x.txt",
                new ByteArrayInputStream("abc".getBytes(StandardCharsets.UTF_8)), 10,
                "text/plain", Map.of()));
        assertFalse(provider.exists("permanent/x.txt"));
    }

    @Test
    void completesMultipartUpload() throws Exception {
        MultipartHandle handle = provider.createMultipart("temporary/upload-1/file.txt",
                "text/plain", Map.of());
        byte[] first = "hello ".getBytes(StandardCharsets.UTF_8);
        byte[] second = "world".getBytes(StandardCharsets.UTF_8);
        MultipartPart part1 = provider.uploadPart("temporary/upload-1/file.txt", handle.uploadId(),
                1, new ByteArrayInputStream(first), first.length);
        MultipartPart part2 = provider.uploadPart("temporary/upload-1/file.txt", handle.uploadId(),
                2, new ByteArrayInputStream(second), second.length);
        assertNotNull(part1.etag());

        MultipartPart merged = provider.completeMultipart("temporary/upload-1/file.txt",
                handle.uploadId(), List.of(part1, part2));
        assertEquals(first.length + second.length, merged.size());
        try (InputStream in = provider.open("temporary/upload-1/file.txt")) {
            assertEquals("hello world", new String(in.readAllBytes(), StandardCharsets.UTF_8));
        }
        assertFalse(java.nio.file.Files.exists(
                tempDir.resolve(".multipart").resolve(handle.uploadId())));
    }

    @Test
    void abortsMultipartUpload() {
        MultipartHandle handle = provider.createMultipart("temporary/upload-2/file.txt",
                "text/plain", Map.of());
        provider.abortMultipart("temporary/upload-2/file.txt", handle.uploadId());
        assertFalse(java.nio.file.Files.exists(
                tempDir.resolve(".multipart").resolve(handle.uploadId())));
    }

    @Test
    void listsWithPrefixAndCursor() {
        provider.put("permanent/a/1.txt", new ByteArrayInputStream(new byte[]{1}), -1,
                "text/plain", Map.of());
        provider.put("permanent/a/2.txt", new ByteArrayInputStream(new byte[]{2}), -1,
                "text/plain", Map.of());
        provider.put("permanent/b/3.txt", new ByteArrayInputStream(new byte[]{3}), -1,
                "text/plain", Map.of());

        ObjectPage first = provider.list("permanent/a", null, 1);
        assertEquals(1, first.items().size());
        assertEquals("permanent/a/1.txt", first.items().get(0).key());
        assertNotNull(first.nextCursor());

        ObjectPage second = provider.list("permanent/a", first.nextCursor(), 10);
        assertEquals(1, second.items().size());
        assertEquals("permanent/a/2.txt", second.items().get(0).key());
        assertEquals(null, second.nextCursor());
    }

    private static StorageProviderConfig config(String root) {
        return new StorageProviderConfig(UUID.randomUUID(), "local-test", "本地测试",
                com.platform.file.domain.storage.StorageType.LOCAL, null, null, null, root,
                null, null, true, false, true, true, true, Map.of(), 1);
    }
}
