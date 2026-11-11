package com.platform.im.infrastructure.email;

import com.platform.im.domain.email.EmailProviderType;
import com.platform.im.domain.email.EmailSenderConfig;

import java.nio.file.Path;
import java.util.List;
import java.util.UUID;

/**
 * 邮件供应商适配接口。SMTP 为第一阶段实现，后续可扩展 SES/SendGrid/Mailgun。
 */
public interface EmailProvider {
    EmailProviderType type();

    EmailSendResult send(OutgoingEmail email, EmailSenderConfig config, String password);

    void testConnection(EmailSenderConfig config, String password);

    record OutgoingEmail(
            UUID taskId,
            String fromAddress,
            String fromName,
            List<EmailAddress> to,
            List<EmailAddress> cc,
            List<EmailAddress> bcc,
            String subject,
            String textBody,
            String htmlBody,
            List<OutgoingAttachment> attachments) {
    }

    record EmailAddress(String address, String displayName) {
    }

    record OutgoingAttachment(String filename, String contentType, Path path) {
    }

    record EmailSendResult(boolean success, String providerMessageId, String errorCode,
                           String errorMessage, String responseDetail) {
    }
}
