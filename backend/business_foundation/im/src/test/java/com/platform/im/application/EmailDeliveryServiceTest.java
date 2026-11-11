package com.platform.im.application;

import com.platform.im.config.AppProperties;
import com.platform.im.domain.email.EmailAttachment;
import com.platform.im.domain.email.EmailProviderType;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EmailDeliveryServiceTest {
    private EmailTaskRepository taskRepository;
    private EmailRecipientRepository recipientRepository;
    private EmailAttachmentRepository attachmentRepository;
    private EmailSendRecordRepository sendRecordRepository;
    private EmailSenderRepository senderRepository;
    private EmailSenderConfigRepository configRepository;
    private EmailProviderRegistry providerRegistry;
    private EmailMetrics metrics;
    private EmailProvider provider;
    private EmailDeliveryService service;
    private AppProperties props;
    private EmailTask task;
    private EmailSender sender;

    @BeforeEach
    void setUp() {
        taskRepository = mock(EmailTaskRepository.class);
        recipientRepository = mock(EmailRecipientRepository.class);
        attachmentRepository = mock(EmailAttachmentRepository.class);
        sendRecordRepository = mock(EmailSendRecordRepository.class);
        senderRepository = mock(EmailSenderRepository.class);
        configRepository = mock(EmailSenderConfigRepository.class);
        providerRegistry = mock(EmailProviderRegistry.class);
        metrics = mock(EmailMetrics.class);
        provider = mock(EmailProvider.class);

        props = new AppProperties();
        props.email.rateLimitEnabled = false;
        props.email.retryBaseSeconds = 10;
        props.email.retryMaxSeconds = 100;

        service = new EmailDeliveryService(taskRepository, recipientRepository, attachmentRepository,
                sendRecordRepository, senderRepository, configRepository, providerRegistry,
                metrics, mock(CryptoService.class), props);

        task = new EmailTask();
        task.id = UUID.randomUUID();
        task.senderId = UUID.randomUUID();
        task.status = EmailTaskStatus.PROCESSING;
        task.attemptCount = 1;
        task.maxAttempts = 3;
        task.subject = "Subject";
        task.textBody = "Body";

        sender = new EmailSender();
        sender.id = task.senderId;
        sender.enabled = true;
        sender.providerType = EmailProviderType.SMTP;
        sender.fromAddress = "noreply@example.com";
        sender.fromName = "IM";
        sender.ratePerMinute = 100;
        sender.ratePerDay = 1000;

        EmailSenderConfig config = new EmailSenderConfig();
        config.senderId = sender.id;
        config.smtpHost = "localhost";
        config.smtpPort = 25;

        EmailRecipient recipient = new EmailRecipient();
        recipient.taskId = task.id;
        recipient.recipientType = RecipientType.TO;
        recipient.address = "user@example.com";

        when(taskRepository.findById(task.id)).thenReturn(Optional.of(task));
        when(sendRecordRepository.countByTaskIdAndStatus(task.id, SendRecordStatus.SUCCESS)).thenReturn(0L);
        when(senderRepository.findByIdAndDeletedFalse(sender.id)).thenReturn(Optional.of(sender));
        when(configRepository.findBySenderId(sender.id)).thenReturn(Optional.of(config));
        when(recipientRepository.findByTaskIdOrderByCreatedAtAsc(task.id)).thenReturn(List.of(recipient));
        when(attachmentRepository.findByTaskIdOrderByCreatedAtAsc(task.id)).thenReturn(List.<EmailAttachment>of());
        when(providerRegistry.require(EmailProviderType.SMTP)).thenReturn(provider);
        when(sendRecordRepository.save(any(EmailSendRecord.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void marksTaskSuccessAndStoresSendRecord() {
        when(provider.send(any(), any(), any())).thenReturn(new EmailProvider.EmailSendResult(
                true, "<msg@test>", null, null, "ok"));

        service.deliver(task.id);

        assertEquals(EmailTaskStatus.SUCCESS, task.status);
        assertEquals("<msg@test>", task.providerMessageId);
        assertNotNull(task.finishedAt);
        assertNull(task.lastErrorCode);
        ArgumentCaptor<EmailSendRecord> captor = ArgumentCaptor.forClass(EmailSendRecord.class);
        verify(sendRecordRepository).save(captor.capture());
        assertEquals(SendRecordStatus.SUCCESS, captor.getValue().status);
        assertEquals(1, captor.getValue().attempt);
        verify(metrics).recordSuccess(org.mockito.ArgumentMatchers.anyLong());
    }

    @Test
    void schedulesRetryWhenAttemptsRemain() {
        when(provider.send(any(), any(), any())).thenReturn(new EmailProvider.EmailSendResult(
                false, null, "SMTP_SEND_FAILED", "boom", null));

        Instant before = Instant.now();
        service.deliver(task.id);

        assertEquals(EmailTaskStatus.RETRYING, task.status);
        assertNotNull(task.nextRetryAt);
        assertTrue(task.nextRetryAt.isAfter(before.plusSeconds(9)));
        assertEquals("SMTP_SEND_FAILED", task.lastErrorCode);
        verify(metrics).recordFailure(org.mockito.ArgumentMatchers.anyLong());
        verify(metrics).recordRetry();
    }

    @Test
    void marksFailedAfterMaxAttempts() {
        task.attemptCount = 3;
        when(provider.send(any(), any(), any())).thenReturn(new EmailProvider.EmailSendResult(
                false, null, "SMTP_SEND_FAILED", "boom", null));

        service.deliver(task.id);

        assertEquals(EmailTaskStatus.FAILED, task.status);
        assertNotNull(task.finishedAt);
        assertNull(task.nextRetryAt);
    }

    @Test
    void skipsDeliveryWhenSuccessRecordExists() {
        when(sendRecordRepository.countByTaskIdAndStatus(task.id, SendRecordStatus.SUCCESS)).thenReturn(1L);

        service.deliver(task.id);

        assertEquals(EmailTaskStatus.SUCCESS, task.status);
        verify(provider, never()).send(any(), any(), any());
    }

    @Test
    void rateLimitedTaskIsRequeuedWithoutConsumingAttempt() {
        props.email.rateLimitEnabled = true;
        when(sendRecordRepository.countBySenderIdAndCreatedAtAfter(eq(sender.id), any(Instant.class)))
                .thenReturn(1000L, 0L);

        service.deliver(task.id);

        assertEquals(EmailTaskStatus.RETRYING, task.status);
        assertEquals(0, task.attemptCount);
        assertEquals("RATE_LIMITED", task.lastErrorCode);
        verify(provider, never()).send(any(), any(), any());
        verify(metrics).recordRetry();
    }

    @Test
    void disabledSenderFailsTask() {
        sender.enabled = false;
        service.deliver(task.id);
        assertEquals("SENDER_UNAVAILABLE", task.lastErrorCode);
        verify(provider, never()).send(any(), any(), any());
    }
}
