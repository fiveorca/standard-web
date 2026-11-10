package com.platform.file.domain.repository;

import com.platform.file.domain.model.FileRecord;
import com.platform.file.domain.model.RecordSearchCriteria;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public interface FileRecordRepository {
    void insert(FileRecord record);

    Optional<FileRecord> findById(UUID id, boolean includeDeleted);

    List<FileRecord> findByIds(Collection<UUID> ids);

    int activate(UUID id, UUID fileObjectId, long fileSize, String mimeType, String sha256);

    int updateStatus(UUID id, String status);

    int softDelete(UUID id);

    int updateUploadMeta(UUID id, long fileSize, String mimeType, String sha256);

    long countActiveByObject(UUID fileObjectId);

    List<UUID> findActiveIdsByObject(UUID fileObjectId);

    List<FileRecord> search(RecordSearchCriteria criteria, int offset, int limit);

    long count(RecordSearchCriteria criteria);

    List<FileRecord> findStalePending(Instant before, int limit);

    List<FileRecord> findActiveWithMissingObject(int limit);

    int quarantineByObject(UUID fileObjectId);

    List<Map<String, Object>> sourceStats();

    long countActive();
}
