package com.platform.file.infrastructure.persistence;

import com.platform.file.domain.model.StorageProviderRow;
import com.platform.file.domain.repository.StorageProviderRepository;
import com.platform.file.domain.storage.StorageType;
import com.platform.file.shared.Db;
import com.platform.file.shared.Json;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static com.platform.file.infrastructure.persistence.Rows.bool;
import static com.platform.file.infrastructure.persistence.Rows.integer;
import static com.platform.file.infrastructure.persistence.Rows.instant;
import static com.platform.file.infrastructure.persistence.Rows.jsonMap;
import static com.platform.file.infrastructure.persistence.Rows.longValue;
import static com.platform.file.infrastructure.persistence.Rows.text;
import static com.platform.file.infrastructure.persistence.Rows.uuid;

@Repository
public class JdbcStorageProviderRepository implements StorageProviderRepository {
    private final Db db;

    public JdbcStorageProviderRepository(Db db) {
        this.db = db;
    }

    @Override
    public List<StorageProviderRow> findAll(boolean includeDisabled) {
        String sql = "SELECT * FROM storage_provider"
                + (includeDisabled ? "" : " WHERE enabled")
                + " ORDER BY is_default DESC, created_at ASC";
        return db.list(sql).stream().map(this::map).toList();
    }

    @Override
    public Optional<StorageProviderRow> findById(UUID id) {
        return db.find("SELECT * FROM storage_provider WHERE id = :id", Db.params("id", id))
                .map(this::map);
    }

    @Override
    public Optional<StorageProviderRow> findByCode(String code) {
        return db.find("SELECT * FROM storage_provider WHERE lower(code) = lower(:code)",
                Db.params("code", code)).map(this::map);
    }

    @Override
    public Optional<StorageProviderRow> findDefault() {
        return db.find("SELECT * FROM storage_provider WHERE is_default AND enabled LIMIT 1", Map.of())
                .map(this::map);
    }

    @Override
    public void insert(StorageProviderRow row) {
        db.update("""
                INSERT INTO storage_provider (
                    id, code, name, type, endpoint, region, bucket, root_path,
                    access_key_cipher, secret_key_cipher, access_key_env, secret_key_env,
                    enabled, is_default, allow_upload, allow_download, allow_delete,
                    options, version, created_at, updated_at
                ) VALUES (
                    :id, :code, :name, :type, :endpoint, :region, :bucket, :rootPath,
                    :accessKeyCipher, :secretKeyCipher, :accessKeyEnv, :secretKeyEnv,
                    :enabled, :isDefault, :allowUpload, :allowDownload, :allowDelete,
                    CAST(:options AS jsonb), 0, now(), now()
                )
                """, Db.params(
                "id", row.id(), "code", row.code(), "name", row.name(), "type", row.type().name(),
                "endpoint", row.endpoint(), "region", row.region(), "bucket", row.bucket(),
                "rootPath", row.rootPath(), "accessKeyCipher", row.accessKeyCipher(),
                "secretKeyCipher", row.secretKeyCipher(), "accessKeyEnv", row.accessKeyEnv(),
                "secretKeyEnv", row.secretKeyEnv(), "enabled", row.enabled(),
                "isDefault", row.defaultProvider(), "allowUpload", row.allowUpload(),
                "allowDownload", row.allowDownload(), "allowDelete", row.allowDelete(),
                "options", Json.write(row.options())));
    }

    @Override
    public void update(StorageProviderRow row) {
        db.update("""
                UPDATE storage_provider SET
                    code = :code, name = :name, type = :type, endpoint = :endpoint, region = :region,
                    bucket = :bucket, root_path = :rootPath, access_key_cipher = :accessKeyCipher,
                    secret_key_cipher = :secretKeyCipher, access_key_env = :accessKeyEnv,
                    secret_key_env = :secretKeyEnv, enabled = :enabled, allow_upload = :allowUpload,
                    allow_download = :allowDownload, allow_delete = :allowDelete,
                    options = CAST(:options AS jsonb), version = version + 1, updated_at = now()
                WHERE id = :id
                """, Db.params(
                "id", row.id(), "code", row.code(), "name", row.name(), "type", row.type().name(),
                "endpoint", row.endpoint(), "region", row.region(), "bucket", row.bucket(),
                "rootPath", row.rootPath(), "accessKeyCipher", row.accessKeyCipher(),
                "secretKeyCipher", row.secretKeyCipher(), "accessKeyEnv", row.accessKeyEnv(),
                "secretKeyEnv", row.secretKeyEnv(), "enabled", row.enabled(),
                "allowUpload", row.allowUpload(), "allowDownload", row.allowDownload(),
                "allowDelete", row.allowDelete(), "options", Json.write(row.options())));
    }

    @Override
    public void delete(UUID id) {
        db.update("DELETE FROM storage_provider WHERE id = :id", Db.params("id", id));
    }

    @Override
    public void clearDefault(UUID exceptId) {
        db.update("UPDATE storage_provider SET is_default = FALSE, updated_at = now() "
                + "WHERE is_default AND id <> :id", Db.params("id", exceptId));
    }

    @Override
    public void setDefault(UUID id) {
        db.update("UPDATE storage_provider SET is_default = TRUE, updated_at = now() WHERE id = :id",
                Db.params("id", id));
    }

    @Override
    public void setEnabled(UUID id, boolean enabled) {
        db.update("UPDATE storage_provider SET enabled = :enabled, "
                + "is_default = CASE WHEN :enabled THEN is_default ELSE FALSE END, "
                + "updated_at = now() WHERE id = :id",
                Db.params("id", id, "enabled", enabled));
    }

    @Override
    public void updateHealth(UUID id, String status, String message) {
        db.update("UPDATE storage_provider SET last_health_status = :status, "
                + "last_health_message = :message, last_checked_at = now() WHERE id = :id",
                Db.params("id", id, "status", status, "message", message));
    }

    @Override
    public long countFileObjects(UUID providerId) {
        return db.count("SELECT count(*) FROM file_object WHERE storage_provider_id = :id "
                + "AND deleted_at IS NULL", Db.params("id", providerId));
    }

    private StorageProviderRow map(Map<String, Object> row) {
        return new StorageProviderRow(
                uuid(row, "id"),
                text(row, "code"),
                text(row, "name"),
                StorageType.valueOf(text(row, "type")),
                text(row, "endpoint"),
                text(row, "region"),
                text(row, "bucket"),
                text(row, "root_path"),
                text(row, "access_key_cipher"),
                text(row, "secret_key_cipher"),
                text(row, "access_key_env"),
                text(row, "secret_key_env"),
                bool(row, "enabled"),
                bool(row, "is_default"),
                bool(row, "allow_upload"),
                bool(row, "allow_download"),
                bool(row, "allow_delete"),
                jsonMap(row, "options"),
                text(row, "last_health_status"),
                text(row, "last_health_message"),
                instant(row, "last_checked_at"),
                integer(row, "version"),
                instant(row, "created_at"),
                instant(row, "updated_at"));
    }

    @SuppressWarnings("unused")
    private static long number(Map<String, Object> row, String key) {
        return longValue(row, key);
    }

    @SuppressWarnings("unused")
    private static Instant created(Map<String, Object> row) {
        return instant(row, "created_at");
    }
}
