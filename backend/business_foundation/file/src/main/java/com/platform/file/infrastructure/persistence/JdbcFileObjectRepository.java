package com.platform.file.infrastructure.persistence;

import com.platform.file.domain.model.FileObject;
import com.platform.file.domain.repository.FileObjectRepository;
import com.platform.file.shared.Db;
import com.platform.file.shared.Json;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
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
public class JdbcFileObjectRepository implements FileObjectRepository {
    private final Db db;

    public JdbcFileObjectRepository(Db db) {
        this.db = db;
    }

    @Override
    public void insert(FileObject o) {
        db.update("""
                INSERT INTO file_object (
                    id, storage_provider_id, object_key, temp_key, sha256, file_size, mime_type,
                    extension, etag, status, delete_after, delete_attempts, last_error, verified_at,
                    metadata, created_at, updated_at, deleted_at
                ) VALUES (
                    :id, :providerId, :objectKey, :tempKey, :sha256, :fileSize, :mimeType,
                    :extension, :etag, :status, :deleteAfter, :deleteAttempts, :lastError, :verifiedAt,
                    CAST(:metadata AS jsonb), now(), now(), :deletedAt
                )
                """, Db.params(
                "id", o.id(), "providerId", o.storageProviderId(), "objectKey", o.objectKey(),
                "tempKey", o.tempKey(), "sha256", o.sha256(), "fileSize", o.fileSize(),
                "mimeType", o.mimeType(), "extension", o.extension(), "etag", o.etag(),
                "status", o.status(), "deleteAfter", o.deleteAfter(), "deleteAttempts", o.deleteAttempts(),
                "lastError", o.lastError(), "verifiedAt", o.verifiedAt(),
                "metadata", Json.write(o.metadata()), "deletedAt", o.deletedAt()));
    }

    @Override
    public Optional<FileObject> findById(UUID id) {
        return db.find("SELECT * FROM file_object WHERE id = :id", Db.params("id", id)).map(this::map);
    }

    @Override
    public Optional<FileObject> findByKey(UUID providerId, String objectKey) {
        return db.find("SELECT * FROM file_object WHERE storage_provider_id = :providerId "
                + "AND object_key = :objectKey AND deleted_at IS NULL",
                Db.params("providerId", providerId, "objectKey", objectKey)).map(this::map);
    }

    @Override
    public Optional<FileObject> findReusableByHash(UUID providerId, String sha256) {
        return db.find("""
                SELECT * FROM file_object
                WHERE storage_provider_id = :providerId AND sha256 = :sha256
                  AND status IN ('ACTIVE', 'MIGRATING', 'PENDING_DELETE')
                ORDER BY CASE status WHEN 'ACTIVE' THEN 0 WHEN 'MIGRATING' THEN 1 ELSE 2 END, created_at
                LIMIT 1
                """, Db.params("providerId", providerId, "sha256", sha256)).map(this::map);
    }

    @Override
    public List<FileObject> findByIds(Collection<UUID> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }
        return db.list("SELECT * FROM file_object WHERE id IN (:ids)", Db.params("ids", ids))
                .stream().map(this::map).toList();
    }

    @Override
    public int claimHash(UUID id, String sha256, String mimeType, long fileSize, String etag) {
        return db.update("""
                UPDATE file_object SET sha256 = :sha256, mime_type = :mimeType, file_size = :fileSize,
                    etag = :etag, status = 'MIGRATING', last_error = NULL, updated_at = now()
                WHERE id = :id AND status IN ('PENDING_UPLOAD', 'TEMP_UPLOADED', 'FAILED', 'QUARANTINED')
                """, Db.params("id", id, "sha256", sha256, "mimeType", mimeType,
                "fileSize", fileSize, "etag", etag));
    }

    @Override
    public int markTempUploaded(UUID id, long fileSize, String mimeType, String etag) {
        return db.update("""
                UPDATE file_object SET status = 'TEMP_UPLOADED', file_size = :fileSize,
                    mime_type = :mimeType, etag = :etag, last_error = NULL, updated_at = now()
                WHERE id = :id AND status IN ('PENDING_UPLOAD', 'TEMP_UPLOADED')
                """, Db.params("id", id, "fileSize", fileSize, "mimeType", mimeType, "etag", etag));
    }

    @Override
    public int activate(UUID id, long fileSize, String mimeType, String etag) {
        return db.update("""
                UPDATE file_object SET status = 'ACTIVE', file_size = :fileSize, mime_type = :mimeType,
                    etag = :etag, temp_key = NULL, delete_after = NULL, last_error = NULL,
                    verified_at = now(), updated_at = now()
                WHERE id = :id AND status IN ('MIGRATING', 'FAILED', 'QUARANTINED', 'ACTIVE', 'PENDING_DELETE')
                """, Db.params("id", id, "fileSize", fileSize, "mimeType", mimeType, "etag", etag));
    }

    @Override
    public int markStatus(UUID id, String status) {
        return db.update("UPDATE file_object SET status = :status, updated_at = now() WHERE id = :id",
                Db.params("id", id, "status", status));
    }

    @Override
    public int markPendingDelete(UUID id, Instant deleteAfter) {
        return db.update("""
                UPDATE file_object SET status = 'PENDING_DELETE', delete_after = :deleteAfter,
                    updated_at = now()
                WHERE id = :id AND status IN ('ACTIVE', 'FAILED', 'QUARANTINED', 'PENDING_DELETE')
                """, Db.params("id", id, "deleteAfter", deleteAfter));
    }

    @Override
    public int markDeleted(UUID id) {
        return db.update("""
                UPDATE file_object SET status = 'DELETED', deleted_at = now(), delete_after = NULL,
                    updated_at = now()
                WHERE id = :id AND status <> 'DELETED'
                """, Db.params("id", id));
    }

    @Override
    public int markQuarantined(UUID id, String error) {
        return db.update("""
                UPDATE file_object SET status = 'QUARANTINED', last_error = :error, updated_at = now()
                WHERE id = :id AND status <> 'DELETED'
                """, Db.params("id", id, "error", error));
    }

    @Override
    public int markFailed(UUID id, String error) {
        return db.update("""
                UPDATE file_object SET status = 'FAILED', last_error = :error, updated_at = now()
                WHERE id = :id AND status <> 'DELETED'
                """, Db.params("id", id, "error", error));
    }

    @Override
    public int recordDeleteFailure(UUID id, String error) {
        return db.update("""
                UPDATE file_object SET delete_attempts = delete_attempts + 1, last_error = :error,
                    updated_at = now()
                WHERE id = :id
                """, Db.params("id", id, "error", error));
    }

    @Override
    public int clearHash(UUID id) {
        return db.update("UPDATE file_object SET sha256 = NULL, updated_at = now() WHERE id = :id",
                Db.params("id", id));
    }

    @Override
    public List<FileObject> findDueForDeletion(Instant now, int limit) {
        return db.list("""
                SELECT * FROM file_object
                WHERE status = 'PENDING_DELETE' AND delete_after IS NOT NULL AND delete_after <= :now
                ORDER BY delete_after LIMIT :limit
                """, Db.params("now", now, "limit", limit)).stream().map(this::map).toList();
    }

    @Override
    public List<FileObject> findStaleByStatus(String status, Instant updatedBefore, int limit) {
        return db.list("""
                SELECT * FROM file_object WHERE status = :status AND updated_at < :before
                ORDER BY updated_at LIMIT :limit
                """, Db.params("status", status, "before", updatedBefore, "limit", limit))
                .stream().map(this::map).toList();
    }

    @Override
    public List<FileObject> listByStatus(String status, int limit) {
        return db.list("""
                SELECT * FROM file_object WHERE status = :status AND deleted_at IS NULL
                ORDER BY updated_at LIMIT :limit
                """, Db.params("status", status, "limit", limit)).stream().map(this::map).toList();
    }

    @Override
    public List<FileObject> findActiveWithoutRecords(int limit) {
        return db.list("""
                SELECT o.* FROM file_object o
                WHERE o.status = 'ACTIVE' AND o.deleted_at IS NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM file_record r
                      WHERE r.file_object_id = o.id AND r.status = 'ACTIVE' AND r.deleted_at IS NULL
                  )
                ORDER BY o.updated_at LIMIT :limit
                """, Db.params("limit", limit)).stream().map(this::map).toList();
    }

    @Override
    public List<FileObject> findDeletedWithKey(int limit) {
        return db.list("""
                SELECT * FROM file_object WHERE status = 'DELETED' AND object_key IS NOT NULL
                ORDER BY updated_at DESC LIMIT :limit
                """, Db.params("limit", limit)).stream().map(this::map).toList();
    }

    @Override
    public List<Map<String, Object>> statsByProvider() {
        return db.list("""
                SELECT p.id AS storage_provider_id, p.code, p.name, p.type,
                       count(o.id) FILTER (WHERE o.status = 'ACTIVE') AS file_count,
                       COALESCE(sum(o.file_size) FILTER (WHERE o.status = 'ACTIVE'), 0) AS total_bytes,
                       count(o.id) FILTER (WHERE o.status IN ('PENDING_UPLOAD', 'TEMP_UPLOADED', 'MIGRATING')) AS temporary_count,
                       count(o.id) FILTER (WHERE o.status = 'PENDING_DELETE') AS pending_delete_count
                FROM storage_provider p
                LEFT JOIN file_object o ON o.storage_provider_id = p.id
                GROUP BY p.id, p.code, p.name, p.type
                ORDER BY p.created_at
                """, Map.of());
    }

    @Override
    public Map<String, Object> totals() {
        return db.find("""
                SELECT count(*) FILTER (WHERE status = 'ACTIVE') AS file_count,
                       COALESCE(sum(file_size) FILTER (WHERE status = 'ACTIVE'), 0) AS total_bytes,
                       count(*) FILTER (WHERE status IN ('PENDING_UPLOAD', 'TEMP_UPLOADED', 'MIGRATING')) AS temporary_count,
                       count(*) FILTER (WHERE status = 'PENDING_DELETE') AS pending_delete_count,
                       count(*) FILTER (WHERE status = 'QUARANTINED') AS quarantined_count
                FROM file_object
                """, Map.of()).orElse(Map.of());
    }

    private FileObject map(Map<String, Object> row) {
        return new FileObject(
                uuid(row, "id"),
                uuid(row, "storage_provider_id"),
                text(row, "object_key"),
                text(row, "temp_key"),
                text(row, "sha256"),
                longValue(row, "file_size"),
                text(row, "mime_type"),
                text(row, "extension"),
                text(row, "etag"),
                text(row, "status"),
                instant(row, "delete_after"),
                integer(row, "delete_attempts"),
                text(row, "last_error"),
                instant(row, "verified_at"),
                jsonMap(row, "metadata"),
                instant(row, "created_at"),
                instant(row, "updated_at"),
                instant(row, "deleted_at"));
    }

    @SuppressWarnings("unused")
    private static boolean enabled(Map<String, Object> row) {
        return bool(row, "enabled");
    }
}
