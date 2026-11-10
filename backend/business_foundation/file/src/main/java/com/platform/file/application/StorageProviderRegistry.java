package com.platform.file.application;

import com.platform.file.domain.model.StorageProviderConfig;
import com.platform.file.domain.model.StorageProviderRow;
import com.platform.file.domain.repository.StorageProviderRepository;
import com.platform.file.domain.storage.StorageProvider;
import com.platform.file.infrastructure.security.SecretCipher;
import com.platform.file.infrastructure.storage.LocalStorageProvider;
import com.platform.file.infrastructure.storage.OssStorageProvider;
import com.platform.file.infrastructure.storage.S3StorageProvider;
import com.platform.file.shared.ApiException;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class StorageProviderRegistry {
    private final StorageProviderRepository repository;
    private final SecretCipher cipher;
    private final Map<UUID, Cached> cache = new ConcurrentHashMap<>();

    public StorageProviderRegistry(StorageProviderRepository repository, SecretCipher cipher) {
        this.repository = repository;
        this.cipher = cipher;
    }

    public StorageProvider get(UUID id) {
        StorageProviderRow row = repository.findById(id)
                .orElseThrow(() -> ApiException.notFound("存储提供者不存在"));
        if (!row.enabled()) {
            throw ApiException.conflict("存储提供者已禁用: " + row.code());
        }
        return get(row);
    }

    public StorageProvider get(StorageProviderRow row) {
        Cached cached = cache.get(row.id());
        if (cached != null && cached.version == row.version()) {
            return cached.provider;
        }
        synchronized (this) {
            cached = cache.get(row.id());
            if (cached != null && cached.version == row.version()) {
                return cached.provider;
            }
            StorageProvider provider = build(toConfig(row));
            cache.put(row.id(), new Cached(row.version(), provider));
            if (cached != null) {
                closeQuietly(cached.provider);
            }
            return provider;
        }
    }

    public StorageProvider defaultProvider() {
        Optional<StorageProviderRow> row = repository.findDefault();
        if (row.isEmpty()) {
            row = repository.findAll(false).stream().findFirst();
        }
        StorageProviderRow provider = row.orElseThrow(() ->
                ApiException.unavailable("没有可用的存储提供者，请先创建并启用存储配置"));
        return get(provider);
    }

    public StorageProvider forUpload(UUID requestedProviderId) {
        if (requestedProviderId != null) {
            StorageProviderRow row = repository.findById(requestedProviderId)
                    .orElseThrow(() -> ApiException.notFound("存储提供者不存在"));
            if (!row.enabled() || !row.allowUpload()) {
                throw ApiException.conflict("存储提供者未启用上传: " + row.code());
            }
            return get(row);
        }
        return defaultProvider();
    }

    public StorageProviderConfig config(UUID id) {
        StorageProviderRow row = repository.findById(id)
                .orElseThrow(() -> ApiException.notFound("存储提供者不存在"));
        return toConfig(row);
    }

    public StorageProviderConfig config(StorageProviderRow row) {
        return toConfig(row);
    }

    public StorageProvider test(StorageProviderRow row) {
        return build(toConfig(row));
    }

    public void invalidate(UUID id) {
        Cached removed = cache.remove(id);
        if (removed != null) {
            closeQuietly(removed.provider);
        }
    }

    public List<StorageProviderRow> enabledProviders() {
        return repository.findAll(false);
    }

    public StorageProviderConfig toConfig(StorageProviderRow row) {
        return new StorageProviderConfig(
                row.id(), row.code(), row.name(), row.type(), row.endpoint(), row.region(),
                row.bucket(), row.rootPath(), resolveCredential(row.accessKeyEnv(), row.accessKeyCipher()),
                resolveCredential(row.secretKeyEnv(), row.secretKeyCipher()), row.enabled(),
                row.defaultProvider(), row.allowUpload(), row.allowDownload(), row.allowDelete(),
                row.options() == null ? Map.of() : row.options(), row.version());
    }

    private String resolveCredential(String envName, String cipherText) {
        if (envName != null && !envName.isBlank()) {
            String value = System.getenv(envName);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return cipher.decrypt(cipherText);
    }

    private StorageProvider build(StorageProviderConfig config) {
        return switch (config.type()) {
            case LOCAL -> new LocalStorageProvider(config);
            case S3 -> new S3StorageProvider(config);
            case OSS -> new OssStorageProvider(config);
        };
    }

    @PreDestroy
    public void closeAll() {
        cache.values().forEach(cached -> closeQuietly(cached.provider));
        cache.clear();
    }

    private static void closeQuietly(StorageProvider provider) {
        try {
            provider.close();
        } catch (Exception ignored) {
            // 关闭资源失败不影响主流程。
        }
    }

    private record Cached(int version, StorageProvider provider) {
    }
}
