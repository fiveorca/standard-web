package com.platform.file.application;

import com.platform.file.application.command.StorageProviderCommand;
import com.platform.file.config.AppProperties;
import com.platform.file.domain.model.StorageProviderRow;
import com.platform.file.domain.repository.StorageProviderRepository;
import com.platform.file.domain.storage.StorageHealth;
import com.platform.file.domain.storage.StorageProvider;
import com.platform.file.domain.storage.StorageType;
import com.platform.file.infrastructure.metrics.FileMetrics;
import com.platform.file.infrastructure.security.SecretCipher;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.Db;
import com.platform.file.shared.Ids;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class StorageProviderService {
    private final StorageProviderRepository repository;
    private final StorageProviderRegistry registry;
    private final SecretCipher cipher;
    private final AppProperties props;
    private final FileMetrics metrics;
    private final OperationLogService operationLog;
    private final Db db;

    public StorageProviderService(StorageProviderRepository repository, StorageProviderRegistry registry,
                                  SecretCipher cipher, AppProperties props, FileMetrics metrics,
                                  OperationLogService operationLog, Db db) {
        this.repository = repository;
        this.registry = registry;
        this.cipher = cipher;
        this.props = props;
        this.metrics = metrics;
        this.operationLog = operationLog;
        this.db = db;
    }

    public Map<String, Object> create(StorageProviderCommand command) {
        validate(command);
        if (repository.findByCode(command.code()).isPresent()) {
            throw ApiException.conflict("存储标识已存在: " + command.code());
        }
        UUID id = Ids.uuidV7();
        boolean makeDefault = Boolean.TRUE.equals(command.defaultProvider());
        StorageProviderRow row = newRow(id, command, makeDefault, null, null);
        db.inTx(() -> {
            if (makeDefault) {
                repository.clearDefault(id);
            }
            repository.insert(row);
        });
        registry.invalidate(id);
        return view(repository.findById(id).orElseThrow());
    }

    public Map<String, Object> update(UUID id, StorageProviderCommand command) {
        StorageProviderRow existing = repository.findById(id)
                .orElseThrow(() -> ApiException.notFound("存储提供者不存在"));
        validate(command);
        repository.findByCode(command.code())
                .filter(other -> !other.id().equals(id))
                .ifPresent(other -> {
                    throw ApiException.conflict("存储标识已存在: " + command.code());
                });
        String accessCipher = command.accessKey() == null || command.accessKey().isBlank()
                ? existing.accessKeyCipher() : cipher.encrypt(command.accessKey());
        String secretCipher = command.secretKey() == null || command.secretKey().isBlank()
                ? existing.secretKeyCipher() : cipher.encrypt(command.secretKey());
        boolean makeDefault = Boolean.TRUE.equals(command.defaultProvider()) || existing.defaultProvider();
        StorageProviderRow row = newRow(id, command, makeDefault, accessCipher, secretCipher);
        db.inTx(() -> {
            if (makeDefault) {
                repository.clearDefault(id);
                repository.setDefault(id);
            }
            repository.update(row);
        });
        registry.invalidate(id);
        return view(repository.findById(id).orElseThrow());
    }

    public List<Map<String, Object>> list(boolean includeDisabled) {
        return repository.findAll(includeDisabled).stream().map(this::view).toList();
    }

    public Map<String, Object> detail(UUID id) {
        return view(repository.findById(id).orElseThrow(() -> ApiException.notFound("存储提供者不存在")));
    }

    public void delete(UUID id) {
        StorageProviderRow row = repository.findById(id)
                .orElseThrow(() -> ApiException.notFound("存储提供者不存在"));
        if (repository.countFileObjects(id) > 0) {
            throw ApiException.conflict("存储提供者仍包含文件对象，不能删除: " + row.code());
        }
        repository.delete(id);
        registry.invalidate(id);
    }

    public Map<String, Object> test(UUID id) {
        StorageProviderRow row = repository.findById(id)
                .orElseThrow(() -> ApiException.notFound("存储提供者不存在"));
        long start = System.nanoTime();
        StorageHealth health;
        try (StorageProvider provider = registry.test(row)) {
            health = provider.health();
        } catch (Exception e) {
            health = StorageHealth.fail("连接测试失败: " + e.getMessage());
        }
        repository.updateHealth(id, health.ok() ? "UP" : "DOWN", health.message());
        long duration = (System.nanoTime() - start) / 1_000_000;
        if (health.ok()) {
            operationLog.success("TEST_CONNECTION", id, null, null, null, null, null, duration,
                    Map.of("message", String.valueOf(health.message())));
        } else {
            metrics.connectionFailed();
            operationLog.failure("TEST_CONNECTION", id, null, null, null, null, null, duration,
                    Map.of(), health.message());
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("provider_id", id.toString());
        out.put("ok", health.ok());
        out.put("message", health.message());
        out.put("checked_at", Instant.now().toString());
        return out;
    }

    public void setDefault(UUID id) {
        repository.findById(id).orElseThrow(() -> ApiException.notFound("存储提供者不存在"));
        db.inTx(() -> {
            repository.clearDefault(id);
            repository.setDefault(id);
        });
        registry.invalidate(id);
    }

    public void setEnabled(UUID id, boolean enabled) {
        repository.findById(id).orElseThrow(() -> ApiException.notFound("存储提供者不存在"));
        repository.setEnabled(id, enabled);
        registry.invalidate(id);
    }

    private StorageProviderRow newRow(UUID id, StorageProviderCommand command, boolean makeDefault,
                                      String accessCipher, String secretCipher) {
        String accessKeyCipher = accessCipher;
        String secretKeyCipher = secretCipher;
        if (accessCipher == null && command.accessKey() != null && !command.accessKey().isBlank()) {
            accessKeyCipher = cipher.encrypt(command.accessKey());
        }
        if (secretCipher == null && command.secretKey() != null && !command.secretKey().isBlank()) {
            secretKeyCipher = cipher.encrypt(command.secretKey());
        }
        String rootPath = blankToNull(command.rootPath());
        if (command.type() == StorageType.LOCAL && rootPath == null) {
            rootPath = props.storage.localRoot;
        }
        return new StorageProviderRow(
                id, command.code().trim(), command.name().trim(), command.type(),
                blankToNull(command.endpoint()), blankToNull(command.region()),
                blankToNull(command.bucket()), rootPath,
                accessKeyCipher, secretKeyCipher, blankToNull(command.accessKeyEnv()),
                blankToNull(command.secretKeyEnv()),
                command.enabled() == null || command.enabled(),
                makeDefault,
                command.allowUpload() == null || command.allowUpload(),
                command.allowDownload() == null || command.allowDownload(),
                command.allowDelete() == null || command.allowDelete(),
                command.options() == null ? Map.of() : command.options(),
                null, null, null, 0, Instant.now(), Instant.now());
    }

    private void validate(StorageProviderCommand command) {
        if (command.code() == null || !command.code().matches("[A-Za-z0-9][A-Za-z0-9_-]{0,63}")) {
            throw ApiException.validation("code", "存储标识必须是 1-64 位字母、数字、下划线或短横线");
        }
        if (command.name() == null || command.name().isBlank()) {
            throw ApiException.validation("name", "存储名称不能为空");
        }
        if (command.type() == null) {
            throw ApiException.validation("type", "存储类型不能为空");
        }
        boolean hasCredentials = (command.accessKey() != null && !command.accessKey().isBlank())
                || (command.accessKeyEnv() != null && !command.accessKeyEnv().isBlank());
        boolean hasSecret = (command.secretKey() != null && !command.secretKey().isBlank())
                || (command.secretKeyEnv() != null && !command.secretKeyEnv().isBlank());
        switch (command.type()) {
            case LOCAL -> {
                // root_path 未显式提供时使用服务配置的本地根目录。
            }
            case S3 -> {
                require(command.bucket() != null && !command.bucket().isBlank(), "bucket", "S3 必须配置 bucket");
                require(hasCredentials && hasSecret, "access_key",
                        "S3 必须配置访问凭据（access_key/secret_key 或对应环境变量）");
            }
            case OSS -> {
                require(command.endpoint() != null && !command.endpoint().isBlank(), "endpoint",
                        "OSS 必须配置 endpoint");
                require(command.bucket() != null && !command.bucket().isBlank(), "bucket", "OSS 必须配置 bucket");
                require(hasCredentials && hasSecret, "access_key",
                        "OSS 必须配置访问凭据（access_key/secret_key 或对应环境变量）");
            }
        }
    }

    private void require(boolean condition, String field, String message) {
        if (!condition) {
            throw ApiException.validation(field, message);
        }
    }

    public Map<String, Object> view(StorageProviderRow row) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", row.id().toString());
        out.put("code", row.code());
        out.put("name", row.name());
        out.put("type", row.type().name());
        out.put("endpoint", row.endpoint());
        out.put("region", row.region());
        out.put("bucket", row.bucket());
        out.put("root_path", row.rootPath());
        out.put("access_key_env", row.accessKeyEnv());
        out.put("secret_key_env", row.secretKeyEnv());
        out.put("credentials_configured", (row.accessKeyCipher() != null || row.accessKeyEnv() != null)
                && (row.secretKeyCipher() != null || row.secretKeyEnv() != null));
        out.put("enabled", row.enabled());
        out.put("is_default", row.defaultProvider());
        out.put("allow_upload", row.allowUpload());
        out.put("allow_download", row.allowDownload());
        out.put("allow_delete", row.allowDelete());
        out.put("options", row.options());
        out.put("last_health_status", row.lastHealthStatus());
        out.put("last_health_message", row.lastHealthMessage());
        out.put("last_checked_at", row.lastCheckedAt() == null ? null : row.lastCheckedAt().toString());
        out.put("created_at", row.createdAt() == null ? null : row.createdAt().toString());
        out.put("updated_at", row.updatedAt() == null ? null : row.updatedAt().toString());
        out.put("capabilities", capabilities(row.type()));
        return out;
    }

    private Map<String, Object> capabilities(StorageType type) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("server_upload", true);
        out.put("presign_upload", type != StorageType.LOCAL);
        out.put("presign_download", type != StorageType.LOCAL);
        out.put("multipart", true);
        out.put("listing", true);
        return out;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
