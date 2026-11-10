package com.platform.file.domain.repository;

import com.platform.file.domain.model.UploadSession;
import com.platform.file.domain.storage.MultipartPart;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface UploadSessionRepository {
    void insert(UploadSession session);

    Optional<UploadSession> findById(UUID id);

    Optional<UploadSession> findByIdempotencyKey(String idempotencyKey);

    int updateStatus(UUID id, String expected, String status, String error);

    int markUploaded(UUID id, long receivedSize, String sha256);

    int markUploadedIfAbsent(UUID id, long receivedSize, String sha256);

    int markMultipart(UUID id, String multipartId, int partsTotal);

    int updateReceived(UUID id, long receivedSize);

    int setSha256(UUID id, String sha256);

    int setConfirming(UUID id);

    int setConfirmed(UUID id);

    int setFailed(UUID id, String error);

    int incrementParts(UUID id, int completed);

    int setPartsCompleted(UUID id, int completed);

    List<UploadSession> findExpired(Instant now, int limit);

    List<UploadSession> findStaleConfirming(Instant before, int limit);

    void upsertPart(UUID uploadId, int partNumber, long size, String etag, String sha256);

    List<MultipartPart> listParts(UUID uploadId);

    void deleteParts(UUID uploadId);
}
