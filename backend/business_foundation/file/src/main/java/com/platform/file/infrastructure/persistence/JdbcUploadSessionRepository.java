package com.platform.file.infrastructure.persistence;

import com.platform.file.domain.model.UploadSession;
import com.platform.file.domain.repository.UploadSessionRepository;
import com.platform.file.domain.storage.MultipartPart;
import com.platform.file.shared.Db;
import com.platform.file.shared.Json;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static com.platform.file.infrastructure.persistence.Rows.integer;
import static com.platform.file.infrastructure.persistence.Rows.instant;
import static com.platform.file.infrastructure.persistence.Rows.jsonMap;
import static com.platform.file.infrastructure.persistence.Rows.longValue;
import static com.platform.file.infrastructure.persistence.Rows.nullableLong;
import static com.platform.file.infrastructure.persistence.Rows.text;
import static com.platform.file.infrastructure.persistence.Rows.uuid;

@Repository
public class JdbcUploadSessionRepository implements UploadSessionRepository {
    private final Db db;

    public JdbcUploadSessionRepository(Db db) {
        this.db = db;
    }

    @Override
    public void insert(UploadSession s) {
        db.update("""
                INSERT INTO upload_session (
                    id, file_id, file_object_id, storage_provider_id, mode, status, object_key,
                    temp_key, multipart_id, expected_size, received_size, sha256, parts_total,
                    parts_completed, idempotency_key, expires_at, confirmed_at, cancelled_at,
                    error_message, metadata, created_at, updated_at
                ) VALUES (
                    :id, :fileId, :objectId, :providerId, :mode, :status, :objectKey,
                    :tempKey, :multipartId, :expectedSize, :receivedSize, :sha256, :partsTotal,
                    :partsCompleted, :idempotencyKey, :expiresAt, :confirmedAt, :cancelledAt,
                    :errorMessage, CAST(:metadata AS jsonb), now(), now()
                )
                """, Db.params(
                "id", s.id(), "fileId", s.fileId(), "objectId", s.fileObjectId(),
                "providerId", s.storageProviderId(), "mode", s.mode(), "status", s.status(),
                "objectKey", s.objectKey(), "tempKey", s.tempKey(), "multipartId", s.multipartId(),
                "expectedSize", s.expectedSize(), "receivedSize", s.receivedSize(), "sha256", s.sha256(),
                "partsTotal", s.partsTotal(), "partsCompleted", s.partsCompleted(),
                "idempotencyKey", s.idempotencyKey(), "expiresAt", s.expiresAt(),
                "confirmedAt", s.confirmedAt(), "cancelledAt", s.cancelledAt(),
                "errorMessage", s.errorMessage(), "metadata", Json.write(s.metadata())));
    }

    @Override
    public Optional<UploadSession> findById(UUID id) {
        return db.find("SELECT * FROM upload_session WHERE id = :id", Db.params("id", id)).map(this::map);
    }

    @Override
    public Optional<UploadSession> findByIdempotencyKey(String idempotencyKey) {
        return db.find("SELECT * FROM upload_session WHERE idempotency_key = :key",
                Db.params("key", idempotencyKey)).map(this::map);
    }

    @Override
    public int updateStatus(UUID id, String expected, String status, String error) {
        String sql = "UPDATE upload_session SET status = :status, error_message = :error, updated_at = now() "
                + "WHERE id = :id" + (expected == null ? "" : " AND status = :expected");
        Map<String, Object> params = Db.params("id", id, "status", status, "error", error);
        if (expected != null) {
            params.put("expected", expected);
        }
        return db.update(sql, params);
    }

    @Override
    public int markUploaded(UUID id, long receivedSize, String sha256) {
        return db.update("""
                UPDATE upload_session SET status = 'UPLOADED', received_size = :size,
                    sha256 = COALESCE(:sha256, sha256), error_message = NULL, updated_at = now()
                WHERE id = :id AND status IN ('CREATED', 'UPLOADING', 'UPLOADED')
                """, Db.params("id", id, "size", receivedSize, "sha256", sha256));
    }

    @Override
    public int markUploadedIfAbsent(UUID id, long receivedSize, String sha256) {
        return db.update("""
                UPDATE upload_session SET status = 'UPLOADED', received_size = :size,
                    sha256 = COALESCE(sha256, :sha256), updated_at = now()
                WHERE id = :id AND status IN ('CREATED', 'UPLOADING', 'UPLOADED', 'CONFIRMING', 'FAILED')
                """, Db.params("id", id, "size", receivedSize, "sha256", sha256));
    }

    @Override
    public int markMultipart(UUID id, String multipartId, int partsTotal) {
        return db.update("""
                UPDATE upload_session SET multipart_id = :multipartId, parts_total = :partsTotal,
                    status = 'UPLOADING', updated_at = now()
                WHERE id = :id AND status IN ('CREATED', 'UPLOADING')
                """, Db.params("id", id, "multipartId", multipartId, "partsTotal", partsTotal));
    }

    @Override
    public int updateReceived(UUID id, long receivedSize) {
        return db.update("UPDATE upload_session SET received_size = :size, updated_at = now() WHERE id = :id",
                Db.params("id", id, "size", receivedSize));
    }

    @Override
    public int setSha256(UUID id, String sha256) {
        return db.update("UPDATE upload_session SET sha256 = :sha256, updated_at = now() WHERE id = :id",
                Db.params("id", id, "sha256", sha256));
    }

    @Override
    public int setConfirming(UUID id) {
        return db.update("""
                UPDATE upload_session SET status = 'CONFIRMING', error_message = NULL, updated_at = now()
                WHERE id = :id AND status IN ('UPLOADED', 'FAILED', 'CONFIRMING')
                """, Db.params("id", id));
    }

    @Override
    public int setConfirmed(UUID id) {
        return db.update("""
                UPDATE upload_session SET status = 'CONFIRMED', confirmed_at = now(),
                    error_message = NULL, updated_at = now()
                WHERE id = :id AND status <> 'CONFIRMED'
                """, Db.params("id", id));
    }

    @Override
    public int setFailed(UUID id, String error) {
        return db.update("UPDATE upload_session SET status = 'FAILED', error_message = :error, "
                + "updated_at = now() WHERE id = :id AND status <> 'CONFIRMED'",
                Db.params("id", id, "error", error));
    }

    @Override
    public int incrementParts(UUID id, int completed) {
        return db.update("""
                UPDATE upload_session SET parts_completed = parts_completed + :completed, updated_at = now()
                WHERE id = :id
                """, Db.params("id", id, "completed", completed));
    }

    @Override
    public int setPartsCompleted(UUID id, int completed) {
        return db.update("UPDATE upload_session SET parts_completed = :completed, updated_at = now() "
                + "WHERE id = :id", Db.params("id", id, "completed", completed));
    }

    @Override
    public List<UploadSession> findExpired(Instant now, int limit) {
        return db.list("""
                SELECT * FROM upload_session
                WHERE status IN ('CREATED', 'UPLOADING', 'UPLOADED') AND expires_at <= :now
                ORDER BY expires_at LIMIT :limit
                """, Db.params("now", now, "limit", limit)).stream().map(this::map).toList();
    }

    @Override
    public List<UploadSession> findStaleConfirming(Instant before, int limit) {
        return db.list("""
                SELECT * FROM upload_session WHERE status = 'CONFIRMING' AND updated_at < :before
                ORDER BY updated_at LIMIT :limit
                """, Db.params("before", before, "limit", limit)).stream().map(this::map).toList();
    }

    @Override
    public void upsertPart(UUID uploadId, int partNumber, long size, String etag, String sha256) {
        db.update("""
                INSERT INTO upload_part (upload_id, part_number, file_size, etag, sha256, created_at)
                VALUES (:uploadId, :partNumber, :size, :etag, :sha256, now())
                ON CONFLICT (upload_id, part_number) DO UPDATE
                SET file_size = EXCLUDED.file_size, etag = EXCLUDED.etag, sha256 = EXCLUDED.sha256
                """, Db.params("uploadId", uploadId, "partNumber", partNumber, "size", size,
                "etag", etag, "sha256", sha256));
    }

    @Override
    public List<MultipartPart> listParts(UUID uploadId) {
        return db.list("SELECT part_number, etag, file_size FROM upload_part WHERE upload_id = :id "
                        + "ORDER BY part_number", Db.params("id", uploadId)).stream()
                .map(row -> new MultipartPart(integer(row, "part_number"), text(row, "etag"),
                        longValue(row, "file_size")))
                .toList();
    }

    @Override
    public void deleteParts(UUID uploadId) {
        db.update("DELETE FROM upload_part WHERE upload_id = :id", Db.params("id", uploadId));
    }

    private UploadSession map(Map<String, Object> row) {
        return new UploadSession(
                uuid(row, "id"),
                uuid(row, "file_id"),
                uuid(row, "file_object_id"),
                uuid(row, "storage_provider_id"),
                text(row, "mode"),
                text(row, "status"),
                text(row, "object_key"),
                text(row, "temp_key"),
                text(row, "multipart_id"),
                nullableLong(row, "expected_size"),
                longValue(row, "received_size"),
                text(row, "sha256"),
                nullableInt(row, "parts_total"),
                integer(row, "parts_completed"),
                text(row, "idempotency_key"),
                instant(row, "expires_at"),
                instant(row, "confirmed_at"),
                instant(row, "cancelled_at"),
                text(row, "error_message"),
                jsonMap(row, "metadata"),
                instant(row, "created_at"),
                instant(row, "updated_at"));
    }

    private static Integer nullableInt(Map<String, Object> row, String key) {
        Object value = row.get(key);
        return value == null ? null : ((Number) value).intValue();
    }
}
