package com.platform.im.infrastructure.email;

import com.platform.im.domain.email.EmailProviderType;
import com.platform.im.domain.email.EmailSenderConfig;
import jakarta.mail.Authenticator;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.PasswordAuthentication;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;
import jakarta.mail.util.ByteArrayDataSource;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.util.Date;
import java.util.List;
import java.util.Properties;

/**
 * Jakarta Mail SMTP 适配器：支持 SSL、STARTTLS、认证、超时与附件。
 */
@Component
public class SmtpEmailProvider implements EmailProvider {
    @Override
    public EmailProviderType type() {
        return EmailProviderType.SMTP;
    }

    @Override
    public EmailSendResult send(OutgoingEmail email, EmailSenderConfig config, String password) {
        try {
            Session session = session(config, password);
            MimeMessage message = new MimeMessage(session);
            message.setFrom(address(email.fromAddress(), email.fromName()));
            message.setReplyTo(new InternetAddress[]{address(email.fromAddress(), email.fromName())});
            message.setRecipients(Message.RecipientType.TO, toAddresses(email.to()));
            if (email.cc() != null && !email.cc().isEmpty()) {
                message.setRecipients(Message.RecipientType.CC, toAddresses(email.cc()));
            }
            if (email.bcc() != null && !email.bcc().isEmpty()) {
                message.setRecipients(Message.RecipientType.BCC, toAddresses(email.bcc()));
            }
            message.setSubject(email.subject() == null ? "" : email.subject(), "UTF-8");
            message.setSentDate(new Date());
            // 固定 Message-ID 便于接收端按任务幂等去重
            message.setHeader("Message-ID", "<" + email.taskId() + "@im-service>");
            message.setHeader("X-IM-Task-Id", email.taskId().toString());

            MimeMultipart multipart = new MimeMultipart();
            if (email.textBody() != null && !email.textBody().isBlank()) {
                MimeBodyPart textPart = new MimeBodyPart();
                textPart.setText(email.textBody(), "UTF-8");
                multipart.addBodyPart(textPart);
            }
            if (email.htmlBody() != null && !email.htmlBody().isBlank()) {
                MimeBodyPart htmlPart = new MimeBodyPart();
                htmlPart.setContent(email.htmlBody(), "text/html; charset=UTF-8");
                multipart.addBodyPart(htmlPart);
            }
            if (email.attachments() != null) {
                for (OutgoingAttachment attachment : email.attachments()) {
                    MimeBodyPart part = new MimeBodyPart();
                    byte[] content = Files.readAllBytes(attachment.path());
                    String contentType = attachment.contentType() == null
                            ? "application/octet-stream" : attachment.contentType();
                    part.setDataHandler(new jakarta.activation.DataHandler(
                            new ByteArrayDataSource(content, contentType)));
                    part.setFileName(attachment.filename());
                    multipart.addBodyPart(part);
                }
            }
            if (multipart.getCount() == 0) {
                message.setText("", "UTF-8");
            } else {
                message.setContent(multipart);
            }

            Transport.send(message);
            String messageId = message.getMessageID();
            return new EmailSendResult(true, messageId, null, null,
                    "SMTP accepted, messageId=" + messageId);
        } catch (MessagingException e) {
            return failure(e);
        } catch (Exception e) {
            return new EmailSendResult(false, null, "SMTP_ERROR",
                    e.getClass().getSimpleName() + ": " + e.getMessage(), null);
        }
    }

    @Override
    public void testConnection(EmailSenderConfig config, String password) {
        try (Transport transport = session(config, password).getTransport()) {
            if (config.smtpAuth) {
                transport.connect(config.smtpHost, config.smtpPort,
                        config.smtpUsername, password == null ? "" : password);
            } else {
                transport.connect(config.smtpHost, config.smtpPort, null, null);
            }
        } catch (MessagingException e) {
            throw new IllegalStateException(describe(e), e);
        }
    }

    private Session session(EmailSenderConfig config, String password) {
        Properties properties = new Properties();
        String protocol = config.sslEnabled ? "smtps" : "smtp";
        properties.put("mail.transport.protocol", protocol);
        properties.put("mail." + protocol + ".host", config.smtpHost);
        properties.put("mail." + protocol + ".port", String.valueOf(config.smtpPort));
        properties.put("mail." + protocol + ".auth", String.valueOf(config.smtpAuth));
        properties.put("mail." + protocol + ".connectiontimeout", String.valueOf(config.connectionTimeoutMs));
        properties.put("mail." + protocol + ".timeout", String.valueOf(config.readTimeoutMs));
        properties.put("mail." + protocol + ".writetimeout", String.valueOf(config.writeTimeoutMs));
        if (config.sslEnabled) {
            properties.put("mail.smtps.ssl.enable", "true");
        }
        if (config.starttlsEnabled && !config.sslEnabled) {
            properties.put("mail.smtp.starttls.enable", "true");
            properties.put("mail.smtp.starttls.required", "true");
        }
        if (config.smtpAuth) {
            final String username = config.smtpUsername;
            final String secret = password == null ? "" : password;
            return Session.getInstance(properties, new Authenticator() {
                @Override
                protected PasswordAuthentication getPasswordAuthentication() {
                    return new PasswordAuthentication(username, secret);
                }
            });
        }
        return Session.getInstance(properties);
    }

    private static InternetAddress[] toAddresses(List<EmailAddress> addresses) {
        if (addresses == null) {
            return new InternetAddress[0];
        }
        return addresses.stream().map(a -> address(a.address(), a.displayName()))
                .toArray(InternetAddress[]::new);
    }

    private static InternetAddress address(String address, String name) {
        try {
            return name == null || name.isBlank()
                    ? new InternetAddress(address)
                    : new InternetAddress(address, name, "UTF-8");
        } catch (Exception e) {
            throw new IllegalArgumentException("非法邮箱地址: " + address, e);
        }
    }

    private static EmailSendResult failure(MessagingException e) {
        String code = "SMTP_ERROR";
        String name = e.getClass().getSimpleName();
        if (name.contains("Authentication")) {
            code = "SMTP_AUTH_FAILED";
        } else if (name.contains("Connect")) {
            code = "SMTP_CONNECT_FAILED";
        } else if (name.contains("Send")) {
            code = "SMTP_SEND_FAILED";
        }
        return new EmailSendResult(false, null, code, describe(e), null);
    }

    private static String describe(MessagingException e) {
        String message = e.getMessage();
        if (e.getNextException() != null) {
            message = message + " / " + e.getNextException().getMessage();
        }
        return message == null ? e.getClass().getSimpleName() : message;
    }
}
