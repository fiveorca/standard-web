package com.platform.im.domain.email;

import com.platform.im.domain.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "email_task")
public class EmailTask extends BaseEntity {
    @Column(name = "tenant_id")
    public UUID tenantId;

    @Column(name = "request_id", nullable = false)
    public String requestId;

    @Column(name = "sender_id", nullable = false)
    public UUID senderId;

    @Column(name = "subject")
    public String subject;

    @Column(name = "text_body")
    public String textBody;

    @Column(name = "html_body")
    public String htmlBody;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    public EmailTaskStatus status = EmailTaskStatus.PENDING;

    @Column(name = "attempt_count", nullable = false)
    public int attemptCount;

    @Column(name = "max_attempts", nullable = false)
    public int maxAttempts = 5;

    @Column(name = "next_retry_at")
    public Instant nextRetryAt;

    @Column(name = "last_error_code")
    public String lastErrorCode;

    @Column(name = "last_error_message")
    public String lastErrorMessage;

    @Column(name = "provider_message_id")
    public String providerMessageId;

    @Column(name = "accepted_at", nullable = false)
    public Instant acceptedAt;

    @Column(name = "started_at")
    public Instant startedAt;

    @Column(name = "finished_at")
    public Instant finishedAt;

    @Column(name = "locked_by")
    public String lockedBy;

    @Column(name = "locked_at")
    public Instant lockedAt;

    @Column(name = "trace_id")
    public String traceId;

    @Column(name = "payload_size", nullable = false)
    public int payloadSize;
}
