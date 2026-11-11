package com.platform.im.domain.email;

import com.platform.im.domain.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;

import java.util.UUID;

@Entity
@Table(name = "email_sender")
public class EmailSender extends BaseEntity {
    @Column(name = "tenant_id")
    public UUID tenantId;

    @Column(name = "code", nullable = false)
    public String code;

    @Column(name = "name", nullable = false)
    public String name;

    @Column(name = "from_address", nullable = false)
    public String fromAddress;

    @Column(name = "from_name")
    public String fromName;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider_type", nullable = false)
    public EmailProviderType providerType = EmailProviderType.SMTP;

    @Column(name = "is_default", nullable = false)
    public boolean defaultSender;

    @Column(name = "enabled", nullable = false)
    public boolean enabled = true;

    @Column(name = "rate_per_minute", nullable = false)
    public int ratePerMinute = 60;

    @Column(name = "rate_per_day", nullable = false)
    public int ratePerDay = 5000;

    @Column(name = "deleted", nullable = false)
    public boolean deleted;
}
