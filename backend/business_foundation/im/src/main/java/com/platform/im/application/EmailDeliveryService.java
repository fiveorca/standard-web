package com.platform.im.application;

import com.platform.im.config.AppProperties;
import com.platform.im.domain.email.EmailRecipient;
import com.platform.im.domain.email.EmailSendRecord;
import com.platform.im.domain.email.EmailSender;
import com.platform.im.domain.email.EmailSenderConfig;
import com.platform.im.domain.email.EmailTask;
import com.platform.im.domain.email.EmailTaskStatus;
import com.platform.im.domain.email.RecipientType;
import com.platform.im.domain.email.SendRecordStatus;
import com.platform.im.domain.repository.EmailAttachmentRepository;
import com.platform.im.domain.repository.EmailRecipientRepository;
import com.platform.im.domain.repository.EmailSendRecordRepository;
import com.platform.im.domain.repository.EmailSenderConfigRepository;
import com.platform.im.domain.repository.EmailSenderRepository;
import com.platform.im.domain.repository.EmailTaskRepository;
import com.platform.im.infrastructure.email.EmailMetrics;
import com.platform.im.infrastructure.email.EmailProvider;
import com.platform.im.infrastructure.email.EmailProviderRegistry;
import com.platform.im.shared.CryptoService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.file.Paths;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * 单个邮件任务的实际投递：限流、重试退避、发送记录与状态流转。
 */
@Service
public class EmailDeliveryService {
    private static final Logger log = LoggerFactory.getLogger(EmailDeliveryService.class);

    private final EmailTaskRepository taskRepository;
    private final EmailRecipientRepository recipientRepository;
    private final EmailAttachmentRepository attachmentRepository;
    private final EmailSendRecordRepository sendRecordRepository;
    private final EmailSenderRepository senderRepository;
    private final EmailSenderConfigRepository configRepository;
    private final EmailProviderRegistry providerRegistry;
    private final EmailMetrics metrics;
    private final CryptoService crypto;
    private final AppProperties props;

    public EmailDeliveryService(EmailTaskRepository taskRepository,
                                EmailRecipientRepository recipientRepository,
                                EmailAttachmentRepository attachmentRepository,
                                EmailSendRecordRepository sendRecordRepository,
                                EmailSenderRepository senderRepository,
                                EmailSenderConfigRepository configRepository,
                                EmailProviderRegistry providerRegistry,
                                EmailMetrics metrics,
                                CryptoService crypto,
                                AppProperties props) {
        this.taskRepository = taskRepository;
        this.recipientRepository = recipientRepository;
        this.attachmentRepository = attachmentRepository;
        this.sendRecordRepository = sendRecordRepository;
        this.senderRepository = senderRepository;
        this.configRepository = configRepository;
        this.providerRegistry = providerRegistry;
        this.metrics = metrics;
        this.crypto = crypto;
        this.props = props;
    }

    @Transactional
    public void deliver(UUID taskId) {
        EmailTask task = taskRepository.findById(taskId).orElse(null);
        if (task == null || task.status != EmailTaskStatus.PROCESSING) {
            return;
        }
        if (sendRecordRepository.countByTaskIdAndStatus(taskId, SendRecordStatus.SUCCESS) > 0) {
            markSuccess(task, task.providerMessageId, "已存在成功发送记录，跳过重复投递");
            return;
        }
        EmailSender sender = senderRepository.findByIdAndDeletedFalse(task.senderId).orElse(null);
        if (sender == null || !sender.enabled) {
            fail(task, "SENDER_UNAVAILABLE", "邮件发送方不存在或已禁用");
            return;
        }
        EmailSenderConfig config = configRepository.findBySenderId(sender.id).orElse(null);
        if (config == null || config.smtpHost == null || config.smtpHost.isBlank()) {
            fail(task, "SENDER_CONFIG_INVALID", "邮件发送方 SMTP 配置不完整");
            return;
        }
        if (rateLimited(task, sender)) {
            return;
        }
        EmailProvider provider = providerRegistry.require(sender.providerType);
        List<EmailRecipient> recipients = recipientRepository.findByTaskIdOrderByCreatedAtAsc(taskId);
        EmailProvider.OutgoingEmail email = buildEmail(task, sender, recipients);
        long start = System.nanoTime();
        EmailProvider.EmailSendResult result;
        try {
            result = provider.send(email, config,
                    config.smtpPasswordCipher == null || config.smtpPasswordCipher.isBlank()
                            ? null : crypto.decrypt(config.smtpPasswordCipher));
        } catch (RuntimeException ex) {
            result = new EmailProvider.EmailSendResult(false, null, "PROVIDER_EXCEPTION",
                    ex.getClass().getSimpleName() + ": " + ex.getMessage(), null);
        }
        long durationMs = (System.nanoTime() - start) / 1_000_000;
        saveRecord(task, sender, result, durationMs);
        if (result.success()) {
            metrics.recordSuccess(System.nanoTime() - start);
            markSuccess(task, result.providerMessageId(), result.responseDetail());
        } else {
            metrics.recordFailure(System.nanoTime() - start);
            fail(task, result.errorCode(), result.errorMessage());
        }
    }

    private EmailProvider.OutgoingEmail buildEmail(EmailTask task, EmailSender sender,
                                                   List<EmailRecipient> recipients) {
        List<EmailProvider.EmailAddress> to = new ArrayList<>();
        List<EmailProvider.EmailAddress> cc = new ArrayList<>();
        List<EmailProvider.EmailAddress> bcc = new ArrayList<>();
        for (EmailRecipient recipient : recipients) {
            EmailProvider.EmailAddress address =
                    new EmailProvider.EmailAddress(recipient.address, recipient.displayName);
            if (recipient.recipientType == RecipientType.CC) {
                cc.add(address);
            } else if (recipient.recipientType == RecipientType.BCC) {
                bcc.add(address);
            } else {
                to.add(address);
            }
        }
        List<EmailProvider.OutgoingAttachment> attachments = attachmentRepository
                .findByTaskIdOrderByCreatedAtAsc(task.id).stream()
                .map(a -> new EmailProvider.OutgoingAttachment(a.filename, a.contentType,
                        Paths.get(a.storagePath)))
                .toList();
        return new EmailProvider.OutgoingEmail(task.id, sender.fromAddress, sender.fromName,
                to, cc, bcc, task.subject, task.textBody, task.htmlBody, attachments);
    }

    private boolean rateLimited(EmailTask task, EmailSender sender) {
        if (!props.email.rateLimitEnabled) {
            return false;
        }
        Instant now = Instant.now();
        long perMinute = sendRecordRepository.countBySenderIdAndCreatedAtAfter(
                sender.id, now.minus(1, ChronoUnit.MINUTES));
        if (perMinute >= sender.ratePerMinute) {
            requeue(task, now.plusSeconds(30), "RATE_LIMITED", "发送方分钟级限流，稍后重试");
            metrics.recordRetry();
            return true;
        }
        long perDay = sendRecordRepository.countBySenderIdAndCreatedAtAfter(
                sender.id, now.minus(1, ChronoUnit.DAYS));
        if (perDay >= sender.ratePerDay) {
            requeue(task, now.plusSeconds(300), "RATE_LIMITED", "发送方日级限流，稍后重试");
            metrics.recordRetry();
            return true;
        }
        return false;
    }

    private void saveRecord(EmailTask task, EmailSender sender,
                            EmailProvider.EmailSendResult result, long durationMs) {
        EmailSendRecord record = new EmailSendRecord();
        record.taskId = task.id;
        record.senderId = sender.id;
        record.attempt = Math.max(1, task.attemptCount);
        record.status = result.success() ? SendRecordStatus.SUCCESS : SendRecordStatus.FAILED;
        record.provider = sender.providerType.name();
        record.providerMessageId = result.providerMessageId();
        record.errorCode = result.errorCode();
        record.errorMessage = truncate(result.errorMessage(), 2048);
        record.durationMs = durationMs;
        record.responseDetail = truncate(result.responseDetail(), 2048);
        sendRecordRepository.save(record);
    }

    private void markSuccess(EmailTask task, String providerMessageId, String detail) {
        task.status = EmailTaskStatus.SUCCESS;
        task.providerMessageId = providerMessageId;
        task.finishedAt = Instant.now();
        task.nextRetryAt = null;
        task.lockedBy = null;
        task.lockedAt = null;
        task.lastErrorCode = null;
        task.lastErrorMessage = null;
        taskRepository.save(task);
        log.info("email task delivered taskId={} providerMessageId={}", task.id, providerMessageId);
    }

    private void fail(EmailTask task, String errorCode, String errorMessage) {
        Instant now = Instant.now();
        task.lastErrorCode = truncate(errorCode == null ? "SEND_FAILED" : errorCode, 64);
        task.lastErrorMessage = truncate(errorMessage, 2048);
        task.lockedBy = null;
        task.lockedAt = null;
        if (task.attemptCount >= task.maxAttempts) {
            task.status = EmailTaskStatus.FAILED;
            task.finishedAt = now;
            task.nextRetryAt = null;
            log.warn("email task failed permanently taskId={} attempts={} error={}",
                    task.id, task.attemptCount, task.lastErrorMessage);
        } else {
            task.status = EmailTaskStatus.RETRYING;
            task.nextRetryAt = now.plusSeconds(backoffSeconds(task.attemptCount));
            metrics.recordRetry();
            log.info("email task scheduled for retry taskId={} attempt={} nextRetryAt={}",
                    task.id, task.attemptCount, task.nextRetryAt);
        }
        taskRepository.save(task);
    }

    private void requeue(EmailTask task, Instant nextRetryAt, String code, String message) {
        task.status = EmailTaskStatus.RETRYING;
        task.nextRetryAt = nextRetryAt;
        task.lastErrorCode = code;
        task.lastErrorMessage = message;
        task.lockedBy = null;
        task.lockedAt = null;
        // 限流不是投递失败，不消耗重试次数
        task.attemptCount = Math.max(0, task.attemptCount - 1);
        taskRepository.save(task);
    }

    private long backoffSeconds(int attempt) {
        long base = Math.max(1, props.email.retryBaseSeconds);
        long max = Math.max(base, props.email.retryMaxSeconds);
        int exponent = Math.max(0, Math.min(20, attempt - 1));
        long delay = base * (1L << exponent);
        return Math.min(delay, max);
    }

    static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
