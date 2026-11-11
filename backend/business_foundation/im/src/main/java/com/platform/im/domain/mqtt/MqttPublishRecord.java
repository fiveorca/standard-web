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
@Table(name = "mqtt_publish_record")
public class MqttPublishRecord extends BaseEntity {
    @Column(name = "tenant_id")
    public UUID tenantId;

    @Column(name = "message_id", nullable = false)
    public String messageId;

    @Column(name = "device_id")
    public String deviceId;

    @Column(name = "topic", nullable = false)
    public String topic;

    @Column(name = "content_type")
    public String contentType;

    @Column(name = "payload_hash", nullable = false)
    public String payloadHash;

    @Column(name = "payload_size", nullable = false)
    public int payloadSize;

    @Column(name = "qos", nullable = false)
    public int qos;

    @Column(name = "retained", nullable = false)
    public boolean retained;

    @Column(name = "message_expiry_interval_seconds", nullable = false)
    public long messageExpiryIntervalSeconds;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    public PublishStatus status = PublishStatus.PENDING;

    @Column(name = "broker_id")
    public UUID brokerId;

    @Column(name = "error_code")
    public String errorCode;

    @Column(name = "error_message")
    public String errorMessage;

    @Column(name = "trace_id")
    public String traceId;

    @Column(name = "source", nullable = false)
    public String source = "GRPC";

    @Column(name = "published_at")
    public Instant publishedAt;
}
