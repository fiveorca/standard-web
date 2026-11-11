package com.platform.im.web.dto;

import com.platform.im.domain.email.EmailProviderType;
import com.platform.im.domain.email.EmailTaskStatus;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public final class EmailDtos {
    private EmailDtos() {
    }

    public record SmtpConfig(
            @NotBlank @Size(max = 255) String host,
            @Min(1) @Max(65535) Integer port,
            @Size(max = 255) String username,
            @Size(max = 512) String password,
            Boolean auth,
            Boolean ssl,
            Boolean starttls,
            @Min(1000) @Max(120000) Integer connectionTimeoutMs,
            @Min(1000) @Max(300000) Integer readTimeoutMs,
            @Min(1000) @Max(300000) Integer writeTimeoutMs) {
    }

    public record SenderRequest(
            String tenantId,
            @Size(max = 64) String code,
            @NotBlank @Size(max = 128) String name,
            @NotBlank @Email @Size(max = 255) String fromAddress,
            @Size(max = 128) String fromName,
            EmailProviderType providerType,
            Boolean defaultSender,
            Boolean enabled,
            @Min(1) @Max(100000) Integer ratePerMinute,
            @Min(1) @Max(10000000) Integer ratePerDay,
            @NotNull @Valid SmtpConfig smtp) {
    }

    public record SenderView(
            UUID id,
            UUID tenantId,
            String code,
            String name,
            String fromAddress,
            String fromName,
            String providerType,
            boolean defaultSender,
            boolean enabled,
            int ratePerMinute,
            int ratePerDay,
            String smtpHost,
            int smtpPort,
            String smtpUsername,
            boolean smtpAuth,
            boolean sslEnabled,
            boolean starttlsEnabled,
            int connectionTimeoutMs,
            int readTimeoutMs,
            int writeTimeoutMs,
            boolean hasPassword,
            Instant createdAt,
            Instant updatedAt) {
    }

    public record PasswordUpdateRequest(@NotBlank @Size(max = 512) String password) {
    }

    public record TestEmailRequest(@NotBlank @Email String to) {
    }

    public record EmailTaskView(
            UUID id,
            UUID tenantId,
            String requestId,
            UUID senderId,
            String subject,
            EmailTaskStatus status,
            int attemptCount,
            int maxAttempts,
            Instant nextRetryAt,
            String lastErrorCode,
            String lastErrorMessage,
            String providerMessageId,
            Instant acceptedAt,
            Instant startedAt,
            Instant finishedAt,
            int payloadSize,
            Instant createdAt,
            Instant updatedAt) {
    }

    public record RecipientView(String type, String address, String displayName) {
    }

    public record AttachmentView(UUID id, String filename, String contentType, long size) {
    }

    public record SendRecordView(UUID id, int attempt, String status, String provider,
                                 String providerMessageId, String errorCode, String errorMessage,
                                 long durationMs, Instant createdAt) {
    }

    public record EmailTaskDetailView(
            EmailTaskView task,
            List<RecipientView> recipients,
            List<AttachmentView> attachments,
            List<SendRecordView> sendRecords) {
    }

    public record TestConnectionResultView(boolean success, long latencyMs, String message) {
    }

    public record AuditLogView(
            UUID id,
            UUID tenantId,
            String actor,
            String actorType,
            String action,
            String resourceType,
            String resourceId,
            String method,
            String path,
            Integer status,
            String ipAddress,
            String traceId,
            Long durationMs,
            Instant createdAt) {
    }
}
