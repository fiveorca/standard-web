package com.platform.im.domain.mqtt;

import com.platform.im.domain.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.util.UUID;

@Entity
@Table(name = "mqtt_access_config")
public class MqttAccessConfig extends BaseEntity {
    @Column(name = "tenant_id")
    public UUID tenantId;

    @Column(name = "broker_id", nullable = false)
    public UUID brokerId;

    @Column(name = "code", nullable = false)
    public String code;

    @Column(name = "name", nullable = false)
    public String name;

    @Column(name = "enabled", nullable = false)
    public boolean enabled = true;

    @Column(name = "is_default", nullable = false)
    public boolean defaultConfig;

    @Column(name = "protocol_version", nullable = false)
    public String protocolVersion = "5.0";

    @Column(name = "default_qos", nullable = false)
    public int defaultQos = 1;

    @Column(name = "keep_alive_seconds", nullable = false)
    public int keepAliveSeconds = 60;

    @Column(name = "clean_start", nullable = false)
    public boolean cleanStart = true;

    @Column(name = "session_expiry_seconds", nullable = false)
    public long sessionExpirySeconds;

    @Column(name = "message_expiry_interval_seconds", nullable = false)
    public long messageExpiryIntervalSeconds;

    @Column(name = "retain_default", nullable = false)
    public boolean retainDefault;

    @Column(name = "publish_topic_template", nullable = false)
    public String publishTopicTemplate = "devices/{deviceId}/up";

    @Column(name = "subscribe_topic_template", nullable = false)
    public String subscribeTopicTemplate = "devices/{deviceId}/down";

    @Column(name = "service_topic_prefix", nullable = false)
    public String serviceTopicPrefix = "tenants/";

    @Column(name = "tls_enabled", nullable = false)
    public boolean tlsEnabled;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_mode", nullable = false)
    public DeviceAuthMode authMode = DeviceAuthMode.CREDENTIAL;

    @Column(name = "config_version", nullable = false)
    public int configVersion = 1;

    @Column(name = "metadata_json")
    public String metadataJson = "{}";

    @Column(name = "deleted", nullable = false)
    public boolean deleted;

    @Version
    @Column(name = "version", nullable = false)
    public int version;
}
