package com.platform.im.domain.email;

import com.platform.im.domain.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.util.UUID;

@Entity
@Table(name = "email_sender_config")
public class EmailSenderConfig extends BaseEntity {
    @Column(name = "sender_id", nullable = false)
    public UUID senderId;

    @Column(name = "smtp_host", nullable = false)
    public String smtpHost;

    @Column(name = "smtp_port", nullable = false)
    public int smtpPort = 587;

    @Column(name = "smtp_username")
    public String smtpUsername;

    @Column(name = "smtp_password_cipher")
    public String smtpPasswordCipher;

    @Column(name = "smtp_auth", nullable = false)
    public boolean smtpAuth = true;

    @Column(name = "ssl_enabled", nullable = false)
    public boolean sslEnabled;

    @Column(name = "starttls_enabled", nullable = false)
    public boolean starttlsEnabled = true;

    @Column(name = "connection_timeout_ms", nullable = false)
    public int connectionTimeoutMs = 10000;

    @Column(name = "read_timeout_ms", nullable = false)
    public int readTimeoutMs = 30000;

    @Column(name = "write_timeout_ms", nullable = false)
    public int writeTimeoutMs = 30000;
}
