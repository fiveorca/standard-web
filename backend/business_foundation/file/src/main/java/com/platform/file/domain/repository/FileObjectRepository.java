package com.platform.file.domain.repository;

import com.platform.file.domain.model.FileObject;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public interface FileObjectRepository {
    void insert(FileObject object);

    Optional<FileObject> findById(UUID id);

    Optional<FileObject> findByKey(UUID providerId, String objectKey);

    Optional<FileObject> findReusableByHash(UUID providerId, String sha256);

    List<FileObject> findByIds(Collection<UUID> ids);

    int claimHash(UUID id, String sha256, String mimeType, long fileSize, String etag);

    int markTempUploaded(UUID id, long fileSize, String mimeType, String etag);

    int activate(UUID id, long fileSize, String mimeType, String etag);

    int markStatus(UUID id, String status);

    int markPendingDelete(UUID id, Instant deleteAfter);

    int markDeleted(UUID id);

    int markQuarantined(UUID id, String error);

    int markFailed(UUID id, String error);

    int recordDeleteFailure(UUID id, String error);

    int clearHash(UUID id);

    List<FileObject> findDueForDeletion(Instant now, int limit);

    List<FileObject> findStaleByStatus(String status, Instant updatedBefore, int limit);

    List<FileObject> listByStatus(String status, int limit);

    List<FileObject> findActiveWithoutRecords(int limit);

    List<FileObject> findDeletedWithKey(int limit);

    List<Map<String, Object>> statsByProvider();

    Map<String, Object> totals();
}
