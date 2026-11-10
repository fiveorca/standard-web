package com.platform.file.domain.repository;

import com.platform.file.domain.model.CleanupTask;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public interface CleanupTaskRepository {
    void insert(CleanupTask task);

    void finish(UUID id, String status, int scanned, int deleted, int repaired, int failed,
                Map<String, Object> details, String error);

    Optional<CleanupTask> findById(UUID id);

    List<CleanupTask> search(String type, String status, int offset, int limit);

    long count(String type, String status);
}
