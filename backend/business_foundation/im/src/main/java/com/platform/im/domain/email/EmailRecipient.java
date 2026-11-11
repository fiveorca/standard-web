package com.platform.im.domain.email;

import com.platform.im.domain.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;

import java.util.UUID;

@Entity
@Table(name = "email_recipient")
public class EmailRecipient extends BaseEntity {
    @Column(name = "task_id", nullable = false)
    public UUID taskId;

    @Enumerated(EnumType.STRING)
    @Column(name = "recipient_type", nullable = false)
    public RecipientType recipientType;

    @Column(name = "address", nullable = false)
    public String address;

    @Column(name = "display_name")
    public String displayName;
}
