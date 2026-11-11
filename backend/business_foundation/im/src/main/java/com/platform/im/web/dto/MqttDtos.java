package com.platform.im.web.dto;

import com.platform.im.domain.mqtt.AclAction;
import com.platform.im.domain.mqtt.AclEffect;
import com.platform.im.domain.mqtt.AclSubjectType;
import com.platform.im.domain.mqtt.BrokerType;
import com.platform.im.domain.mqtt.CredentialStatus;
import com.platform.im.domain.mqtt.DeviceAuthMode;
import com.platform.im.domain.mqtt.PublishStatus;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class MqttDtos {
    private MqttDtos() {
    }

    public record BrokerRequest(
            @NotBlank @Size(max = 64) String code,
            @NotBlank @Size(max = 128) String name,
            BrokerType brokerType,
            @NotBlank @Size(max = 255) String host,
            @Min(1) @Max(65535) Integer tcpPort,
            @Min(1) @Max(65535) Integer tlsPort,
            @Size(max = 16) String protocolVersion,
            Boolean tlsEnabled,
            @Size(max = 128) String username,
            @Size(max = 512) String password,
            @Size(max = 64) String clientIdPrefix,
            @Min(5) @Max(3600) Integer keepAliveSeconds,
            Boolean cleanStart,
            @Min(0) Long sessionExpirySeconds,
            @Min(1) @Max(120) Integer connectTimeoutSeconds,
            @Min(1) @Max(600) Integer reconnectDelaySeconds,
            @Min(1) @Max(65535) Integer maxInflight,
            Boolean enabled,
            Boolean defaultBroker,
            String optionsJson) {
    }

    public record BrokerView(
            UUID id,
            String code,
            String name,
            String brokerType,
            String host,
            int tcpPort,
            Integer tlsPort,
            String protocolVersion,
            boolean tlsEnabled,
            String username,
            String clientIdPrefix,
            int keepAliveSeconds,
            boolean cleanStart,
            long sessionExpirySeconds,
            int connectTimeoutSeconds,
            int reconnectDelaySeconds,
            int maxInflight,
            boolean enabled,
            boolean defaultBroker,
            String status,
            String statusMessage,
            Instant lastConnectedAt,
            Instant lastCheckedAt,
            long reconnectCount,
            boolean hasPassword,
            String optionsJson,
            Instant createdAt,
            Instant updatedAt) {
    }

    public record BrokerStatusView(
            UUID brokerId,
            String storedStatus,
            String statusMessage,
            boolean clientConnected,
            Instant lastConnectedAt,
            Instant lastCheckedAt,
            long reconnectCount) {
    }

    public record TestConnectionResult(boolean success, long latencyMs, String message) {
    }

    public record AccessConfigRequest(
            @Size(max = 64) String code,
            @NotBlank @Size(max = 128) String name,
            String tenantId,
            @NotNull UUID brokerId,
            Boolean enabled,
            Boolean defaultConfig,
            @Size(max = 16) String protocolVersion,
            @Min(0) @Max(2) Integer defaultQos,
            @Min(5) @Max(3600) Integer keepAliveSeconds,
            Boolean cleanStart,
            @Min(0) Long sessionExpirySeconds,
            @Min(0) Long messageExpiryIntervalSeconds,
            Boolean retainDefault,
            @Size(max = 512) String publishTopicTemplate,
            @Size(max = 512) String subscribeTopicTemplate,
            @Size(max = 512) String serviceTopicPrefix,
            Boolean tlsEnabled,
            DeviceAuthMode authMode,
            String metadataJson) {
    }

    public record AccessConfigView(
            UUID id,
            String code,
            String name,
            UUID tenantId,
            UUID brokerId,
            String brokerCode,
            boolean enabled,
            boolean defaultConfig,
            String protocolVersion,
            int defaultQos,
            int keepAliveSeconds,
            boolean cleanStart,
            long sessionExpirySeconds,
            long messageExpiryIntervalSeconds,
            boolean retainDefault,
            String publishTopicTemplate,
            String subscribeTopicTemplate,
            String serviceTopicPrefix,
            boolean tlsEnabled,
            String authMode,
            int configVersion,
            String metadataJson,
            Instant createdAt,
            Instant updatedAt) {
    }

    public record TopicAclRequest(
            @NotNull AclSubjectType subjectType,
            @NotBlank @Size(max = 128) String subjectId,
            @NotBlank @Size(max = 512) String topicPattern,
            @NotNull AclAction action,
            AclEffect effect,
            @Min(0) @Max(2) Integer qosMax,
            Integer priority,
            Boolean enabled) {
    }

    public record TopicAclView(
            UUID id,
            UUID accessConfigId,
            String subjectType,
            String subjectId,
            String topicPattern,
            String action,
            String effect,
            int qosMax,
            int priority,
            boolean enabled,
            Instant createdAt) {
    }

    public record CredentialCreateRequest(
            String tenantId,
            @NotBlank @Size(max = 128) String deviceId,
            UUID accessConfigId,
            Instant expiresAt,
            Boolean createDefaultAcls) {
    }

    public record CredentialView(
            UUID id,
            UUID tenantId,
            String deviceId,
            UUID accessConfigId,
            UUID brokerId,
            String username,
            CredentialStatus status,
            int configVersion,
            Instant expiresAt,
            Instant lastAuthAt,
            Instant rotatedAt,
            String disabledReason,
            Instant createdAt,
            Instant updatedAt) {
    }

    public record CredentialCreatedView(CredentialView credential, String password) {
    }

    public record TopicPermissionView(String topic, String action, String effect, int qosMax) {
    }

    public record DeviceConfigView(
            UUID tenantId,
            String deviceId,
            String brokerUrl,
            int port,
            String protocolVersion,
            boolean tlsEnabled,
            String clientId,
            String username,
            String password,
            int keepAlive,
            boolean cleanStart,
            long sessionExpiry,
            int defaultQos,
            String publishTopic,
            String subscribeTopic,
            List<TopicPermissionView> topicPermissions,
            int configVersion,
            int accessConfigVersion,
            Instant expiresAt) {
    }

    public record PublishRecordView(
            UUID id,
            UUID tenantId,
            String messageId,
            String deviceId,
            String topic,
            String contentType,
            int payloadSize,
            int qos,
            boolean retained,
            long messageExpiryIntervalSeconds,
            PublishStatus status,
            UUID brokerId,
            String errorCode,
            String errorMessage,
            String traceId,
            Instant publishedAt,
            Instant createdAt) {
    }

    public record MqttAuthRequest(
            @NotBlank String username,
            @NotBlank String password,
            String clientid,
            String peerhost) {
    }

    public record MqttAclRequest(
            @NotBlank String username,
            @NotBlank String topic,
            @NotBlank String action,
            String clientid,
            String peerhost) {
    }
}
