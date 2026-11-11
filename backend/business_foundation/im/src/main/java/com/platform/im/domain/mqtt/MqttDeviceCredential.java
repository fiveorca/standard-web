package com.platform.im.domain.mqtt;

import com.platform.im.domain.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "mqtt_device_credential")
public class MqttDeviceCredential extends BaseEntity {
    @Column(name = "tenant_id")
    public UUID tenantId;

    @Column(name = "device_id", nullable = false)
    public String deviceId;

    @Column(name = "access_config_id", nullable = false)
    public UUID accessConfigId;

    @Column(name = "broker_id", nullable = false)
    public UUID brokerId;

    @Column(name = "username", nullable = false)
    public String username;

    @Column(name = "password_hash", nullable = false)
    public String passwordHash;

    @Column(name = "password_cipher", nullable = false)
    public String passwordCipher;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    public CredentialStatus status = CredentialStatus.ACTIVE;

    @Column(name = "config_version", nullable = false)
    public int configVersion = 1;

    @Column(name = "expires_at")
    public Instant expiresAt;

    @Column(name = "last_auth_at")
    public Instant lastAuthAt;

    @Column(name = "rotated_at")
    public Instant rotatedAt;

    @Column(name = "disabled_reason")
    public String disabledReason;

    @Column(name = "deleted", nullable = false)
    public boolean deleted;

    public boolean isUsable() {
        return !deleted && status == CredentialStatus.ACTIVE
                && (expiresAt == null || expiresAt.isAfter(Instant.now()));
    }
}
