package com.platform.file.infrastructure.persistence;

import com.platform.file.domain.model.OperationLog;
import com.platform.file.domain.repository.OperationLogRepository;
import com.platform.file.shared.Db;
import com.platform.file.shared.Json;
import org.springframework.stereotype.Repository;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Repository
public class JdbcOperationLogRepository implements OperationLogRepository {
    private final Db db;

    public JdbcOperationLogRepository(Db db) {
        this.db = db;
    }

    @Override
    public void insert(OperationLog log) {
        db.update("""
                INSERT INTO storage_operation_log (
                    id, operation, status, storage_provider_id, file_object_id, file_id, upload_id,
                    object_key, bytes, duration_ms, trace_id, detail, error_message, created_at
                ) VALUES (
                    :id, :operation, :status, :providerId, :objectId, :fileId, :uploadId,
                    :objectKey, :bytes, :durationMs, :traceId, CAST(:detail AS jsonb), :error, now()
                )
                """, Db.params("id", log.id(), "operation", log.operation(), "status", log.status(),
                "providerId", log.storageProviderId(), "objectId", log.fileObjectId(),
                "fileId", log.fileId(), "uploadId", log.uploadId(), "objectKey", log.objectKey(),
                "bytes", log.bytes(), "durationMs", log.durationMs(), "traceId", log.traceId(),
                "detail", Json.write(log.detail()), "error", log.errorMessage()));
    }

    @Override
    public List<Map<String, Object>> search(String operation, String status, String fileId, int offset, int limit) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        Map<String, Object> params = new LinkedHashMap<>();
        if (operation != null && !operation.isBlank()) {
            where.append(" AND operation = :operation");
            params.put("operation", operation);
        }
        if (status != null && !status.isBlank()) {
            where.append(" AND status = :status");
            params.put("status", status);
        }
        if (fileId != null && !fileId.isBlank()) {
            where.append(" AND file_id = :fileId");
            params.put("fileId", fileId);
        }
        params.put("limit", limit);
        params.put("offset", offset);
        return db.list("SELECT * FROM storage_operation_log" + where
                + " ORDER BY created_at DESC LIMIT :limit OFFSET :offset", params);
    }

    @Override
    public long count(String operation, String status, String fileId) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        Map<String, Object> params = new LinkedHashMap<>();
        if (operation != null && !operation.isBlank()) {
            where.append(" AND operation = :operation");
            params.put("operation", operation);
        }
        if (status != null && !status.isBlank()) {
            where.append(" AND status = :status");
            params.put("status", status);
        }
        if (fileId != null && !fileId.isBlank()) {
            where.append(" AND file_id = :fileId");
            params.put("fileId", fileId);
        }
        return db.count("SELECT count(*) FROM storage_operation_log" + where, params);
    }
}
