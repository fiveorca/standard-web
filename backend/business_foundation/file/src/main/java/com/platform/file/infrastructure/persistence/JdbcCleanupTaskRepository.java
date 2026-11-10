package com.platform.file.infrastructure.persistence;

import com.platform.file.domain.model.CleanupTask;
import com.platform.file.domain.repository.CleanupTaskRepository;
import com.platform.file.shared.Db;
import com.platform.file.shared.Json;
import org.springframework.stereotype.Repository;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static com.platform.file.infrastructure.persistence.Rows.bool;
import static com.platform.file.infrastructure.persistence.Rows.integer;
import static com.platform.file.infrastructure.persistence.Rows.instant;
import static com.platform.file.infrastructure.persistence.Rows.jsonMap;
import static com.platform.file.infrastructure.persistence.Rows.text;
import static com.platform.file.infrastructure.persistence.Rows.uuid;

@Repository
public class JdbcCleanupTaskRepository implements CleanupTaskRepository {
    private final Db db;

    public JdbcCleanupTaskRepository(Db db) {
        this.db = db;
    }

    @Override
    public void insert(CleanupTask t) {
        db.update("""
                INSERT INTO file_cleanup_task (
                    id, type, status, dry_run, storage_provider_id, scanned, deleted, repaired,
                    failed, details, error_message, started_at, finished_at, created_at
                ) VALUES (
                    :id, :type, :status, :dryRun, :providerId, :scanned, :deleted, :repaired,
                    :failed, CAST(:details AS jsonb), :error, now(), NULL, now()
                )
                """, Db.params("id", t.id(), "type", t.type(), "status", t.status(),
                "dryRun", t.dryRun(), "providerId", t.storageProviderId(), "scanned", t.scanned(),
                "deleted", t.deleted(), "repaired", t.repaired(), "failed", t.failed(),
                "details", Json.write(t.details()), "error", t.errorMessage()));
    }

    @Override
    public void finish(UUID id, String status, int scanned, int deleted, int repaired, int failed,
                       Map<String, Object> details, String error) {
        db.update("""
                UPDATE file_cleanup_task SET status = :status, scanned = :scanned, deleted = :deleted,
                    repaired = :repaired, failed = :failed, details = CAST(:details AS jsonb),
                    error_message = :error, finished_at = now()
                WHERE id = :id
                """, Db.params("id", id, "status", status, "scanned", scanned, "deleted", deleted,
                "repaired", repaired, "failed", failed, "details", Json.write(details), "error", error));
    }

    @Override
    public Optional<CleanupTask> findById(UUID id) {
        return db.find("SELECT * FROM file_cleanup_task WHERE id = :id", Db.params("id", id)).map(this::map);
    }

    @Override
    public List<CleanupTask> search(String type, String status, int offset, int limit) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        Map<String, Object> params = new LinkedHashMap<>();
        if (type != null && !type.isBlank()) {
            where.append(" AND type = :type");
            params.put("type", type);
        }
        if (status != null && !status.isBlank()) {
            where.append(" AND status = :status");
            params.put("status", status);
        }
        params.put("limit", limit);
        params.put("offset", offset);
        return db.list("SELECT * FROM file_cleanup_task" + where
                + " ORDER BY created_at DESC LIMIT :limit OFFSET :offset", params)
                .stream().map(this::map).toList();
    }

    @Override
    public long count(String type, String status) {
        StringBuilder where = new StringBuilder(" WHERE 1=1");
        Map<String, Object> params = new LinkedHashMap<>();
        if (type != null && !type.isBlank()) {
            where.append(" AND type = :type");
            params.put("type", type);
        }
        if (status != null && !status.isBlank()) {
            where.append(" AND status = :status");
            params.put("status", status);
        }
        return db.count("SELECT count(*) FROM file_cleanup_task" + where, params);
    }

    private CleanupTask map(Map<String, Object> row) {
        return new CleanupTask(
                uuid(row, "id"),
                text(row, "type"),
                text(row, "status"),
                bool(row, "dry_run"),
                uuid(row, "storage_provider_id"),
                integer(row, "scanned"),
                integer(row, "deleted"),
                integer(row, "repaired"),
                integer(row, "failed"),
                jsonMap(row, "details"),
                text(row, "error_message"),
                instant(row, "started_at"),
                instant(row, "finished_at"),
                instant(row, "created_at"));
    }
}
