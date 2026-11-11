package com.platform.im.domain.repository;

import com.platform.im.domain.email.EmailTask;
import com.platform.im.domain.email.EmailTaskStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface EmailTaskRepository extends JpaRepository<EmailTask, UUID> {
    Optional<EmailTask> findByIdAndTenantId(UUID id, UUID tenantId);

    Optional<EmailTask> findFirstByTenantIdAndRequestId(UUID tenantId, String requestId);

    Optional<EmailTask> findFirstByTenantIdIsNullAndRequestId(String requestId);

    Optional<EmailTask> findFirstByRequestId(String requestId);

    Page<EmailTask> findAll(Pageable pageable);

    Page<EmailTask> findByTenantId(UUID tenantId, Pageable pageable);

    Page<EmailTask> findByTenantIdAndStatus(UUID tenantId, EmailTaskStatus status, Pageable pageable);

    Page<EmailTask> findByStatus(EmailTaskStatus status, Pageable pageable);

    Page<EmailTask> findByTenantIdAndSenderId(UUID tenantId, UUID senderId, Pageable pageable);

    Page<EmailTask> findBySenderId(UUID senderId, Pageable pageable);

    Page<EmailTask> findBySenderIdAndStatus(UUID senderId, EmailTaskStatus status, Pageable pageable);

    Page<EmailTask> findByTenantIdAndSenderIdAndStatus(
            UUID tenantId, UUID senderId, EmailTaskStatus status, Pageable pageable);

    List<EmailTask> findByIdIn(Collection<UUID> ids);

    long countByStatus(EmailTaskStatus status);

    long countByStatusIn(Collection<EmailTaskStatus> statuses);

    long countBySenderIdAndCreatedAtAfter(UUID senderId, Instant after);

    long countBySenderId(UUID senderId);

    @Modifying
    @Query(value = "UPDATE email_task SET status = 'RETRYING', next_retry_at = now(), "
            + "locked_by = NULL, locked_at = NULL, updated_at = now() "
            + "WHERE status = 'PROCESSING' AND (locked_at IS NULL OR locked_at < :cutoff)", nativeQuery = true)
    int recoverStaleTasks(@Param("cutoff") Instant cutoff);

    @Modifying
    @Query(value = "UPDATE email_task SET status = 'PENDING', next_retry_at = :next, updated_at = now() "
            + "WHERE id = :id AND status = 'FAILED'", nativeQuery = true)
    int requeueFailed(@Param("id") UUID id, @Param("next") Instant next);

    /**
     * 抢占待发送任务：行级锁 + SKIP LOCKED，支持多实例并发消费而不重复发送。
     */
    @Query(value = "SELECT id FROM email_task "
            + "WHERE status IN ('PENDING', 'RETRYING') AND (next_retry_at IS NULL OR next_retry_at <= now()) "
            + "ORDER BY created_at ASC LIMIT :limit FOR UPDATE SKIP LOCKED", nativeQuery = true)
    List<UUID> lockClaimableIds(@Param("limit") int limit);

    @Modifying
    @Query(value = "UPDATE email_task SET status = 'PROCESSING', locked_by = :worker, locked_at = now(), "
            + "started_at = COALESCE(started_at, now()), attempt_count = attempt_count + 1, updated_at = now() "
            + "WHERE id = :id AND status IN ('PENDING', 'RETRYING')", nativeQuery = true)
    int claimTask(@Param("id") UUID id, @Param("worker") String worker);
}
