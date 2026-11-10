package com.platform.file.infrastructure.persistence;

import com.platform.file.domain.model.FileSource;
import com.platform.file.domain.repository.FileSourceRepository;
import com.platform.file.shared.Db;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static com.platform.file.infrastructure.persistence.Rows.bool;
import static com.platform.file.infrastructure.persistence.Rows.instant;
import static com.platform.file.infrastructure.persistence.Rows.text;
import static com.platform.file.infrastructure.persistence.Rows.uuid;

@Repository
public class JdbcFileSourceRepository implements FileSourceRepository {
    private final Db db;

    public JdbcFileSourceRepository(Db db) {
        this.db = db;
    }

    @Override
    public List<FileSource> findAll(boolean includeDisabled) {
        String sql = "SELECT * FROM file_source" + (includeDisabled ? "" : " WHERE enabled")
                + " ORDER BY created_at ASC";
        return db.list(sql).stream().map(this::map).toList();
    }

    @Override
    public Optional<FileSource> findById(UUID id) {
        return db.find("SELECT * FROM file_source WHERE id = :id", Db.params("id", id)).map(this::map);
    }

    @Override
    public Optional<FileSource> findByCode(String code) {
        return db.find("SELECT * FROM file_source WHERE lower(code) = lower(:code)",
                Db.params("code", code)).map(this::map);
    }

    @Override
    public void insert(FileSource s) {
        db.update("""
                INSERT INTO file_source (id, code, name, description, enabled, created_at, updated_at)
                VALUES (:id, :code, :name, :description, :enabled, now(), now())
                """, Db.params("id", s.id(), "code", s.code(), "name", s.name(),
                "description", s.description(), "enabled", s.enabled()));
    }

    @Override
    public void update(FileSource s) {
        db.update("""
                UPDATE file_source SET code = :code, name = :name, description = :description,
                    enabled = :enabled, updated_at = now()
                WHERE id = :id
                """, Db.params("id", s.id(), "code", s.code(), "name", s.name(),
                "description", s.description(), "enabled", s.enabled()));
    }

    @Override
    public void delete(UUID id) {
        db.update("DELETE FROM file_source WHERE id = :id", Db.params("id", id));
    }

    private FileSource map(Map<String, Object> row) {
        return new FileSource(
                uuid(row, "id"),
                text(row, "code"),
                text(row, "name"),
                text(row, "description"),
                bool(row, "enabled"),
                instant(row, "created_at"),
                instant(row, "updated_at"));
    }
}
