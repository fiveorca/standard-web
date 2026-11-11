package com.platform.im.domain.mqtt;

import com.platform.im.domain.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

import java.time.Instant;

@Entity
@Table(name = "mqtt_broker")
public class MqttBroker extends BaseEntity {
    @Column(name = "code", nullable = false)
    public String code;

    @Column(name = "name", nullable = false)
    public String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "broker_type", nullable = false)
    public BrokerType brokerType = BrokerType.EMQX;

    @Column(name = "host", nullable = false)
    public String host;

    @Column(name = "tcp_port", nullable = false)
    public int tcpPort = 1883;

    @Column(name = "tls_port")
    public Integer tlsPort;

    @Column(name = "protocol_version", nullable = false)
    public String protocolVersion = "5.0";

    @Column(name = "tls_enabled", nullable = false)
    public boolean tlsEnabled;

    @Column(name = "username")
    public String username;

    @Column(name = "password_cipher")
    public String passwordCipher;

    @Column(name = "client_id_prefix")
    public String clientIdPrefix;

    @Column(name = "keep_alive_seconds", nullable = false)
    public int keepAliveSeconds = 60;

    @Column(name = "clean_start", nullable = false)
    public boolean cleanStart = true;

    @Column(name = "session_expiry_seconds", nullable = false)
    public long sessionExpirySeconds;

    @Column(name = "connect_timeout_seconds", nullable = false)
    public int connectTimeoutSeconds = 10;

    @Column(name = "reconnect_delay_seconds", nullable = false)
    public int reconnectDelaySeconds = 5;

    @Column(name = "max_inflight", nullable = false)
    public int maxInflight = 100;

    @Column(name = "enabled", nullable = false)
    public boolean enabled = true;

    @Column(name = "is_default", nullable = false)
    public boolean defaultBroker;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    public BrokerConnectionStatus status = BrokerConnectionStatus.UNKNOWN;

    @Column(name = "status_message")
    public String statusMessage;

    @Column(name = "last_connected_at")
    public Instant lastConnectedAt;

    @Column(name = "last_checked_at")
    public Instant lastCheckedAt;

    @Column(name = "reconnect_count", nullable = false)
    public long reconnectCount;

    @Column(name = "options_json")
    public String optionsJson = "{}";

    @Version
    @Column(name = "version", nullable = false)
    public int version;
}
