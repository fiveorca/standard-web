package com.platform.file.infrastructure.persistence;

import com.platform.file.domain.model.FileRecord;
import com.platform.file.domain.model.RecordSearchCriteria;
import com.platform.file.domain.repository.FileRecordRepository;
import com.platform.file.shared.Db;
import com.platform.file.shared.Json;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static com.platform.file.infrastructure.persistence.Rows.instant;
import static com.platform.file.infrastructure.persistence.Rows.jsonMap;
import static com.platform.file.infrastructure.persistence.Rows.longValue;
import static com.platform.file.infrastructure.persistence.Rows.text;
import static com.platform.file.infrastructure.persistence.Rows.uuid;

@Repository
public class JdbcFileRecordRepository implements FileRecordRepository {
    private final Db db;

    public JdbcFileRecordRepository(Db db) {
        this.db = db;
    }

    @Override
    public void insert(FileRecord r) {
        db.update("""
                INSERT INTO file_record (
                    id, file_object_id, storage_provider_id, original_filename, display_name,
                    file_size, mime_type, extension, source_type, source_id, business_id, creator,
                    tenant_id, status, sha256, metadata, created_at, updated_at, deleted_at
                ) VALUES (
                    :id, :objectId, :providerId, :originalFilename, :displayName,
                    :fileSize, :mimeType, :extension, :sourceType, :sourceId, :businessId, :creator,
                    :tenantId, :status, :sha256, CAST(:metadata AS jsonb), now(), now(), :deletedAt
                )
                """, Db.params(
                "id", r.id(), "objectId", r.fileObjectId(), "providerId", r.storageProviderId(),
                "originalFilename", r.originalFilename(), "displayName", r.displayName(),
                "fileSize", r.fileSize(), "mimeType", r.mimeType(), "extension", r.extension(),
                "sourceType", r.sourceType(), "sourceId", r.sourceId(), "businessId", r.businessId(),
                "creator", r.creator(), "tenantId", r.tenantId(), "status", r.status(),
                "sha256", r.sha256(), "metadata", Json.write(r.metadata()), "deletedAt", r.deletedAt()));
    }

    @Override
    public Optional<FileRecord> findById(UUID id, boolean includeDeleted) {
        String sql = "SELECT * FROM file_record WHERE id = :id"
                + (includeDeleted ? "" : " AND deleted_at IS NULL");
        return db.find(sql, Db.params("id", id)).map(this::map);
    }

    @Override
    public List<FileRecord> findByIds(Collection<UUID> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }
        return db.list("SELECT * FROM file_record WHERE id IN (:ids) AND deleted_at IS NULL",
                Db.params("ids", ids)).stream().map(this::map).toList();
    }

    @Override
    public int activate(UUID id, UUID fileObjectId, long fileSize, String mimeType, String sha256) {
        return db.update("""
                UPDATE file_record SET file_object_id = :objectId, file_size = :fileSize,
                    mime_type = :mimeType, sha256 = :sha256, status = 'ACTIVE', updated_at = now()
                WHERE id = :id AND deleted_at IS NULL
                """, Db.params("id", id, "objectId", fileObjectId, "fileSize", fileSize,
                "mimeType", mimeType, "sha256", sha256));
    }

    @Override
    public int updateStatus(UUID id, String status) {
        return db.update("UPDATE file_record SET status = :status, updated_at = now() "
                + "WHERE id = :id AND deleted_at IS NULL", Db.params("id", id, "status", status));
    }

    @Override
    public int softDelete(UUID id) {
        return db.update("""
                UPDATE file_record SET status = 'DELETED', deleted_at = now(), updated_at = now()
                WHERE id = :id AND deleted_at IS NULL
                """, Db.params("id", id));
    }

    @Override
    public int updateUploadMeta(UUID id, long fileSize, String mimeType, String sha256) {
        return db.update("""
                UPDATE file_record SET file_size = :fileSize, mime_type = :mimeType,
                    sha256 = COALESCE(:sha256, sha256), updated_at = now()
                WHERE id = :id AND deleted_at IS NULL
                """, Db.params("id", id, "fileSize", fileSize, "mimeType", mimeType, "sha256", sha256));
    }

    @Override
    public long countActiveByObject(UUID fileObjectId) {
        return db.count("SELECT count(*) FROM file_record WHERE file_object_id = :objectId "
                + "AND status = 'ACTIVE' AND deleted_at IS NULL", Db.params("objectId", fileObjectId));
    }

    @Override
    public List<UUID> findActiveIdsByObject(UUID fileObjectId) {
        return db.list("SELECT id FROM file_record WHERE file_object_id = :objectId "
                        + "AND status = 'ACTIVE' AND deleted_at IS NULL", Db.params("objectId", fileObjectId))
                .stream().map(row -> uuid(row, "id")).toList();
    }

    @Override
    public List<FileRecord> search(RecordSearchCriteria criteria, int offset, int limit) {
        Query query = query(criteria, false);
        Map<String, Object> params = new LinkedHashMap<>(query.params());
        params.put("limit", limit);
        params.put("offset", offset);
        String sql = "SELECT r.* FROM file_record r" + query.where()
                + " ORDER BY " + sort(criteria.sort()) + " LIMIT :limit OFFSET :offset";
        return db.list(sql, params).stream().map(this::map).toList();
    }

    @Override
    public long count(RecordSearchCriteria criteria) {
        Query query = query(criteria, true);
        return db.count("SELECT count(*) FROM file_record r" + query.where(), query.params());
    }

    @Override
    public List<FileRecord> findStalePending(Instant before, int limit) {
        return db.list("""
                SELECT * FROM file_record
                WHERE status = 'PENDING_UPLOAD' AND updated_at < :before AND deleted_at IS NULL
                ORDER BY updated_at LIMIT :limit
                """, Db.params("before", before, "limit", limit)).stream().map(this::map).toList();
    }

    @Override
    public List<FileRecord> findActiveWithMissingObject(int limit) {
        return db.list("""
                SELECT r.* FROM file_record r
                LEFT JOIN file_object o ON o.id = r.file_object_id
                WHERE r.status = 'ACTIVE' AND r.deleted_at IS NULL
                  AND (r.file_object_id IS NULL OR o.id IS NULL OR o.deleted_at IS NOT NULL)
                ORDER BY r.updated_at LIMIT :limit
                """, Db.params("limit", limit)).stream().map(this::map).toList();
    }

    @Override
    public int quarantineByObject(UUID fileObjectId) {
        return db.update("UPDATE file_record SET status = 'QUARANTINED', updated_at = now() "
                        + "WHERE file_object_id = :objectId AND status = 'ACTIVE' AND deleted_at IS NULL",
                Db.params("objectId", fileObjectId));
    }

    @Override
    public List<Map<String, Object>> sourceStats() {
        return db.list("""
                SELECT source_type, source_id,
                       count(*) AS file_count,
                       count(*) FILTER (WHERE status = 'ACTIVE') AS active_count,
                       COALESCE(sum(file_size) FILTER (WHERE status = 'ACTIVE'), 0) AS total_bytes
                FROM file_record
                WHERE deleted_at IS NULL
                GROUP BY source_type, source_id
                ORDER BY file_count DESC
                """, Map.of());
    }

    @Override
    public long countActive() {
        return db.count("SELECT count(*) FROM file_record WHERE status = 'ACTIVE' AND deleted_at IS NULL",
                Map.of());
    }

    private Query query(RecordSearchCriteria c, boolean countOnly) {
        StringBuilder where = new StringBuilder(" WHERE r.deleted_at IS NULL");
        Map<String, Object> params = new LinkedHashMap<>();
        if (c.status() != null && !c.status().isBlank()) {
            where.append(" AND r.status = :status");
            params.put("status", c.status().toUpperCase(Locale.ROOT));
        }
        if (c.sourceType() != null && !c.sourceType().isBlank()) {
            where.append(" AND r.source_type = :sourceType");
            params.put("sourceType", c.sourceType());
        }
        if (c.sourceId() != null && !c.sourceId().isBlank()) {
            where.append(" AND r.source_id = :sourceId");
            params.put("sourceId", c.sourceId());
        }
        if (c.businessId() != null && !c.businessId().isBlank()) {
            where.append(" AND r.business_id = :businessId");
            params.put("businessId", c.businessId());
        }
        if (c.storageProviderId() != null) {
            where.append(" AND r.storage_provider_id = :providerId");
            params.put("providerId", c.storageProviderId());
        }
        if (c.creator() != null && !c.creator().isBlank()) {
            where.append(" AND r.creator = :creator");
            params.put("creator", c.creator());
        }
        if (c.tenantId() != null) {
            where.append(" AND r.tenant_id = :tenantId");
            params.put("tenantId", c.tenantId());
        }
        if (c.mimeType() != null && !c.mimeType().isBlank()) {
            where.append(" AND r.mime_type LIKE :mimeType");
            params.put("mimeType", c.mimeType().replace("*", "%"));
        }
        if (c.filename() != null && !c.filename().isBlank()) {
            where.append(" AND lower(coalesce(r.display_name, r.original_filename)) LIKE :filename");
            params.put("filename", "%" + c.filename().toLowerCase(Locale.ROOT) + "%");
        }
        if (c.createdFrom() != null) {
            where.append(" AND r.created_at >= :from");
            params.put("from", c.createdFrom());
        }
        if (c.createdTo() != null) {
            where.append(" AND r.created_at <= :to");
            params.put("to", c.createdTo());
        }
        return new Query(where.toString(), params);
    }

    private static String sort(String sort) {
        if (sort == null) {
            return "r.created_at DESC";
        }
        return switch (sort) {
            case "created_at_asc" -> "r.created_at ASC";
            case "updated_at_desc" -> "r.updated_at DESC";
            case "size_desc" -> "r.file_size DESC";
            case "size_asc" -> "r.file_size ASC";
            case "name_asc" -> "coalesce(r.display_name, r.original_filename) ASC";
            default -> "r.created_at DESC";
        };
    }

    private FileRecord map(Map<String, Object> row) {
        return new FileRecord(
                uuid(row, "id"),
                uuid(row, "file_object_id"),
                uuid(row, "storage_provider_id"),
                text(row, "original_filename"),
                text(row, "display_name"),
                longValue(row, "file_size"),
                text(row, "mime_type"),
                text(row, "extension"),
                text(row, "source_type"),
                text(row, "source_id"),
                text(row, "business_id"),
                text(row, "creator"),
                uuid(row, "tenant_id"),
                text(row, "status"),
                text(row, "sha256"),
                jsonMap(row, "metadata"),
                instant(row, "created_at"),
                instant(row, "updated_at"),
                instant(row, "deleted_at"));
    }

    private record Query(String where, Map<String, Object> params) {
    }
}
