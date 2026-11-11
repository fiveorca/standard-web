package com.platform.im.domain.repository;

import com.platform.im.domain.email.EmailSendRecord;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public interface EmailSendRecordRepository extends JpaRepository<EmailSendRecord, UUID> {
    List<EmailSendRecord> findByTaskIdOrderByCreatedAtDesc(UUID taskId);

    Page<EmailSendRecord> findByTaskId(UUID taskId, Pageable pageable);

    Page<EmailSendRecord> findBySenderId(UUID senderId, Pageable pageable);

    long countBySenderIdAndCreatedAtAfter(UUID senderId, Instant after);

    long countByTaskId(UUID taskId);

    long countByTaskIdAndStatus(UUID taskId, com.platform.im.domain.email.SendRecordStatus status);
}
