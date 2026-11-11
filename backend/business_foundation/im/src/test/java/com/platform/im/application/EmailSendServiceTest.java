package com.platform.im.application;

import com.platform.im.config.AppProperties;
import com.platform.im.domain.email.EmailProviderType;
import com.platform.im.domain.email.EmailSender;
import com.platform.im.domain.email.EmailSenderConfig;
import com.platform.im.domain.email.EmailTask;
import com.platform.im.domain.email.EmailTaskStatus;
import com.platform.im.domain.repository.EmailAttachmentRepository;
import com.platform.im.domain.repository.EmailRecipientRepository;
import com.platform.im.domain.repository.EmailSendRecordRepository;
import com.platform.im.domain.repository.EmailSenderConfigRepository;
import com.platform.im.domain.repository.EmailSenderRepository;
import com.platform.im.domain.repository.EmailTaskRepository;
import com.platform.im.infrastructure.email.EmailAttachmentStore;
import com.platform.im.shared.ApiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EmailSendServiceTest {
    private static final UUID TENANT = UUID.randomUUID();

    private EmailTaskRepository taskRepository;
    private EmailRecipientRepository recipientRepository;
    private EmailSenderRepository senderRepository;
    private EmailSenderConfigRepository configRepository;
    private EmailSendService service;
    private EmailSender sender;

    @BeforeEach
    void setUp() {
        taskRepository = mock(EmailTaskRepository.class);
        recipientRepository = mock(EmailRecipientRepository.class);
        EmailAttachmentRepository attachmentRepository = mock(EmailAttachmentRepository.class);
        EmailSendRecordRepository sendRecordRepository = mock(EmailSendRecordRepository.class);
        senderRepository = mock(EmailSenderRepository.class);
        configRepository = mock(EmailSenderConfigRepository.class);
        EmailAttachmentStore attachmentStore = mock(EmailAttachmentStore.class);

        AppProperties props = new AppProperties();
        props.email.maxRecipients = 10;

        service = new EmailSendService(taskRepository, recipientRepository, attachmentRepository,
                sendRecordRepository, senderRepository, configRepository, attachmentStore, props);

        sender = new EmailSender();
        sender.id = UUID.randomUUID();
        sender.tenantId = TENANT;
        sender.enabled = true;
        sender.providerType = EmailProviderType.SMTP;
        sender.fromAddress = "noreply@example.com";
        sender.ratePerMinute = 60;
        sender.ratePerDay = 1000;

        EmailSenderConfig config = new EmailSenderConfig();
        config.senderId = sender.id;
        config.smtpHost = "localhost";

        when(senderRepository.findFirstByTenantIdAndDefaultSenderTrueAndDeletedFalse(TENANT))
                .thenReturn(Optional.of(sender));
        when(configRepository.findBySenderId(sender.id)).thenReturn(Optional.of(config));
        when(taskRepository.saveAndFlush(any(EmailTask.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(recipientRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void acceptsEmailAndPersistsRecipients() {
        when(taskRepository.findFirstByTenantIdAndRequestId(TENANT, "req-1")).thenReturn(Optional.empty());

        EmailSendService.AcceptedTask accepted = service.accept(command("req-1",
                List.of("a@example.com", "b@example.com"), List.of("cc@example.com"),
                List.of(), "主题", "正文", null));

        assertTrue(accepted.created());
        assertEquals(EmailTaskStatus.PENDING, accepted.status());
        assertNotNull(accepted.taskId());
        verify(recipientRepository, org.mockito.Mockito.times(3)).save(any());
    }

    @Test
    void returnsExistingTaskForDuplicateRequestId() {
        EmailTask existing = new EmailTask();
        existing.id = UUID.randomUUID();
        existing.requestId = "req-1";
        existing.status = EmailTaskStatus.SUCCESS;
        when(taskRepository.findFirstByTenantIdAndRequestId(TENANT, "req-1")).thenReturn(Optional.of(existing));

        EmailSendService.AcceptedTask accepted = service.accept(command("req-1",
                List.of("a@example.com"), List.of(), List.of(), "主题", "正文", null));

        assertFalse(accepted.created());
        assertEquals(existing.id, accepted.taskId());
        assertEquals(EmailTaskStatus.SUCCESS, accepted.status());
        verify(taskRepository, never()).saveAndFlush(any());
    }

    @Test
    void rejectsEmailWithoutRecipients() {
        ApiException exception = assertThrows(ApiException.class, () -> service.accept(
                command(null, List.of(), List.of(), List.of(), "主题", "正文", null)));
        assertEquals(422, exception.status());
    }

    @Test
    void rejectsEmailWithoutBody() {
        ApiException exception = assertThrows(ApiException.class, () -> service.accept(
                command(null, List.of("a@example.com"), List.of(), List.of(), "主题", null, null)));
        assertEquals(422, exception.status());
    }

    @Test
    void rejectsInvalidRecipientAddress() {
        ApiException exception = assertThrows(ApiException.class, () -> service.accept(
                command(null, List.of("not-an-email"), List.of(), List.of(), "主题", "正文", null)));
        assertEquals(422, exception.status());
    }

    @Test
    void failsWhenNoDefaultSenderConfigured() {
        when(senderRepository.findFirstByTenantIdAndDefaultSenderTrueAndDeletedFalse(TENANT))
                .thenReturn(Optional.empty());
        when(senderRepository.findFirstByDefaultSenderTrueAndDeletedFalse()).thenReturn(Optional.empty());

        ApiException exception = assertThrows(ApiException.class, () -> service.accept(
                command(null, List.of("a@example.com"), List.of(), List.of(), "主题", "正文", null)));
        assertEquals(503, exception.status());
    }

    private EmailSendService.EmailSendCommand command(String requestId, List<String> to, List<String> cc,
                                                      List<String> bcc, String subject, String text,
                                                      String html) {
        return new EmailSendService.EmailSendCommand(TENANT, requestId, null, to, cc, bcc,
                subject, text, html, List.of());
    }
}
