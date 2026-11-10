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
import com.platform.file.shared.Hash;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;

public class LocalStorageProvider implements StorageProvider {
    private final StorageProviderConfig config;
    private final Path root;

    public LocalStorageProvider(StorageProviderConfig config) {
        this.config = config;
        if (config.rootPath() == null || config.rootPath().isBlank()) {
            throw new StorageException("LOCAL 存储必须配置 root_path");
        }
        this.root = Path.of(config.rootPath()).toAbsolutePath().normalize();
        try {
            Files.createDirectories(root);
        } catch (IOException e) {
            throw new StorageException("无法创建本地存储根目录", e);
        }
    }

    @Override
    public String type() {
        return "LOCAL";
    }

    @Override
    public StorageCapabilities capabilities() {
        return new StorageCapabilities(true, false, false, true, true);
    }

    @Override
    public ObjectMetadata put(String key, InputStream content, long size, String contentType,
                              Map<String, String> metadata) {
        Path target = resolve(key);
        try {
            Files.createDirectories(target.getParent());
            long written = Files.copy(content, target, StandardCopyOption.REPLACE_EXISTING);
            if (size >= 0 && written != size) {
                Files.deleteIfExists(target);
                throw new StorageException("写入大小与声明大小不一致");
            }
            return stat(key);
        } catch (StorageException e) {
            throw e;
        } catch (IOException e) {
            throw new StorageException("本地文件写入失败", e);
        }
    }

    @Override
    public InputStream open(String key) {
        try {
            return Files.newInputStream(resolve(key));
        } catch (IOException e) {
            throw new StorageException("本地文件不存在或无法读取: " + key, e);
        }
    }

    @Override
    public void copy(String sourceKey, String targetKey) {
        Path source = resolve(sourceKey);
        Path target = resolve(targetKey);
        try {
            if (!Files.isRegularFile(source)) {
                throw new StorageException("源文件不存在: " + sourceKey);
            }
            Files.createDirectories(target.getParent());
            Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING);
        } catch (StorageException e) {
            throw e;
        } catch (IOException e) {
            throw new StorageException("本地文件复制失败", e);
        }
    }

    @Override
    public void delete(String key) {
        try {
            Files.deleteIfExists(resolve(key));
        } catch (IOException e) {
            throw new StorageException("本地文件删除失败", e);
        }
    }

    @Override
    public boolean exists(String key) {
        return Files.isRegularFile(resolve(key));
    }

    @Override
    public ObjectMetadata stat(String key) {
        Path path = resolve(key);
        try {
            String contentType = Files.probeContentType(path);
            return new ObjectMetadata(key, Files.size(path), contentType, null,
                    Files.getLastModifiedTime(path).toInstant(), Map.of());
        } catch (IOException e) {
            throw new StorageException("本地文件元数据读取失败", e);
        }
    }

    @Override
    public ObjectPage list(String prefix, String cursor, int limit) {
        String normalized = prefix == null ? "" : prefix;
        Path base = resolve(normalized);
        if (!Files.exists(base)) {
            return new ObjectPage(List.of(), null);
        }
        List<ObjectMetadata> all = new ArrayList<>();
        try (Stream<Path> stream = Files.walk(base)) {
            stream.filter(Files::isRegularFile)
                    .filter(path -> !path.toString().contains("/.multipart/"))
                    .forEach(path -> {
                        String key = relative(path);
                        if (cursor != null && key.compareTo(cursor) <= 0) {
                            return;
                        }
                        try {
                            all.add(new ObjectMetadata(key, Files.size(path),
                                    Files.probeContentType(path), null,
                                    Files.getLastModifiedTime(path).toInstant(), Map.of()));
                        } catch (IOException e) {
                            throw new StorageException("遍历本地文件失败", e);
                        }
                    });
        } catch (IOException e) {
            throw new StorageException("遍历本地文件失败", e);
        }
        all.sort(Comparator.comparing(ObjectMetadata::key));
        List<ObjectMetadata> items = all.stream().limit(limit).toList();
        String next = all.size() > limit ? items.getLast().key() : null;
        return new ObjectPage(items, next);
    }

    @Override
    public PresignedUpload presignUpload(String key, String contentType, long maxSize, Duration ttl) {
        throw new StorageException("本地存储不支持预签名上传");
    }

    @Override
    public PresignedDownload presignDownload(String key, String filename, Duration ttl) {
        throw new StorageException("本地存储不支持预签名下载");
    }

    @Override
    public MultipartHandle createMultipart(String key, String contentType, Map<String, String> metadata) {
        String uploadId = UUID.randomUUID().toString();
        try {
            Files.createDirectories(multipartDir(uploadId));
        } catch (IOException e) {
            throw new StorageException("无法创建本地分片目录", e);
        }
        return new MultipartHandle(uploadId, key);
    }

    @Override
    public MultipartPart uploadPart(String key, String uploadId, int partNumber, InputStream content, long size) {
        if (partNumber < 1 || partNumber > 10000) {
            throw new StorageException("分片编号不合法");
        }
        Path part = multipartDir(uploadId).resolve(partNumber + ".part");
        try (OutputStream out = Files.newOutputStream(part, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            long written = content.transferTo(out);
            if (size >= 0 && written != size) {
                Files.deleteIfExists(part);
                throw new StorageException("分片大小与声明不一致");
            }
            return new MultipartPart(partNumber, Hash.sha256(part), written);
        } catch (IOException e) {
            throw new StorageException("本地分片写入失败", e);
        }
    }

    @Override
    public PartAuthorization presignPart(String key, String uploadId, int partNumber, Duration ttl) {
        throw new StorageException("本地存储不支持分片预签名");
    }

    @Override
    public MultipartPart completeMultipart(String key, String uploadId, List<MultipartPart> parts) {
        Path target = resolve(key);
        try {
            Files.createDirectories(target.getParent());
            Path tmp = target.resolveSibling(target.getFileName() + ".complete-" + UUID.randomUUID());
            try (OutputStream out = Files.newOutputStream(tmp, StandardOpenOption.CREATE_NEW)) {
                for (MultipartPart part : parts.stream()
                        .sorted(Comparator.comparingInt(MultipartPart::partNumber)).toList()) {
                    Path partPath = multipartDir(uploadId).resolve(part.partNumber() + ".part");
                    if (!Files.isRegularFile(partPath)) {
                        throw new StorageException("缺少分片 " + part.partNumber());
                    }
                    Files.copy(partPath, out);
                }
            }
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            long size = Files.size(target);
            String etag = Hash.sha256(target);
            deleteMultipart(uploadId);
            return new MultipartPart(parts.size(), etag, size);
        } catch (StorageException e) {
            throw e;
        } catch (IOException e) {
            throw new StorageException("本地分片合并失败", e);
        }
    }

    @Override
    public void abortMultipart(String key, String uploadId) {
        deleteMultipart(uploadId);
    }

    @Override
    public StorageHealth health() {
        try {
            Files.createDirectories(root);
            Path probe = Files.createTempFile(root, ".health-", ".tmp");
            Files.deleteIfExists(probe);
            return StorageHealth.ok("本地存储可读写");
        } catch (IOException e) {
            return StorageHealth.fail("本地存储不可写: " + e.getMessage());
        }
    }

    private void deleteMultipart(String uploadId) {
        Path dir = multipartDir(uploadId);
        if (!Files.exists(dir)) {
            return;
        }
        try (Stream<Path> stream = Files.walk(dir)) {
            stream.sorted(Comparator.reverseOrder()).forEach(path -> {
                try {
                    Files.deleteIfExists(path);
                } catch (IOException e) {
                    throw new StorageException("清理本地分片失败", e);
                }
            });
        } catch (IOException e) {
            throw new StorageException("清理本地分片失败", e);
        }
    }

    private Path multipartDir(String uploadId) {
        if (uploadId == null || !uploadId.matches("[A-Za-z0-9-]{8,64}")) {
            throw new StorageException("分片上传标识不合法");
        }
        return root.resolve(".multipart").resolve(uploadId).normalize();
    }

    private Path resolve(String key) {
        if (key == null || key.isBlank() || key.startsWith("/") || key.contains("\\")
                || key.contains("..") || key.contains("\u0000")) {
            throw new StorageException("对象 Key 不合法");
        }
        Path path = root.resolve(key).normalize();
        if (!path.startsWith(root)) {
            throw new StorageException("对象 Key 越界");
        }
        return path;
    }

    private String relative(Path path) {
        return root.relativize(path).toString().replace('\\', '/');
    }
}
