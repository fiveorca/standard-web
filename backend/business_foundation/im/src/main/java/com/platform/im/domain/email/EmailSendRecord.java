package com.platform.im.domain.email;

import com.platform.im.domain.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;

import java.util.UUID;

@Entity
@Table(name = "email_send_record")
public class EmailSendRecord extends BaseEntity {
    @Column(name = "task_id", nullable = false)
    public UUID taskId;

    @Column(name = "sender_id", nullable = false)
    public UUID senderId;

    @Column(name = "attempt", nullable = false)
    public int attempt;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    public SendRecordStatus status;

    @Column(name = "provider", nullable = false)
    public String provider;

    @Column(name = "provider_message_id")
    public String providerMessageId;

    @Column(name = "error_code")
    public String errorCode;

    @Column(name = "error_message")
    public String errorMessage;

    @Column(name = "duration_ms", nullable = false)
    public long durationMs;

    @Column(name = "response_detail")
    public String responseDetail;
}
