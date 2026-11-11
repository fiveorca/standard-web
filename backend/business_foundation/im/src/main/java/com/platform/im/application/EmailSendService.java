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
import com.platform.im.domain.repository.EmailAttachmentRepository;
import com.platform.im.domain.repository.EmailRecipientRepository;
import com.platform.im.domain.repository.EmailSendRecordRepository;
import com.platform.im.domain.repository.EmailSenderConfigRepository;
import com.platform.im.domain.repository.EmailSenderRepository;
import com.platform.im.domain.repository.EmailTaskRepository;
import com.platform.im.infrastructure.email.EmailAttachmentStore;
import com.platform.im.shared.ApiException;
import com.platform.im.shared.Ids;
import com.platform.im.shared.PageQuery;
import com.platform.im.shared.PageResult;
import com.platform.im.web.dto.EmailDtos;
import org.slf4j.MDC;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * 邮件受理与查询：同步完成校验、落库与附件存储，实际发送由异步 Worker 完成。
 */
@Service
public class EmailSendService {
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}$");
    private static final int MAX_SUBJECT = 255;
    private static final int MAX_BODY_BYTES = 1_048_576;

    private final EmailTaskRepository taskRepository;
    private final EmailRecipientRepository recipientRepository;
    private final EmailAttachmentRepository attachmentRepository;
    private final EmailSendRecordRepository sendRecordRepository;
    private final EmailSenderRepository senderRepository;
    private final EmailSenderConfigRepository configRepository;
    private final EmailAttachmentStore attachmentStore;
    private final AppProperties props;

    public EmailSendService(EmailTaskRepository taskRepository,
                            EmailRecipientRepository recipientRepository,
                            EmailAttachmentRepository attachmentRepository,
                            EmailSendRecordRepository sendRecordRepository,
                            EmailSenderRepository senderRepository,
                            EmailSenderConfigRepository configRepository,
                            EmailAttachmentStore attachmentStore,
                            AppProperties props) {
        this.taskRepository = taskRepository;
        this.recipientRepository = recipientRepository;
        this.attachmentRepository = attachmentRepository;
        this.sendRecordRepository = sendRecordRepository;
        this.senderRepository = senderRepository;
        this.configRepository = configRepository;
        this.attachmentStore = attachmentStore;
        this.props = props;
    }

    @Transactional
    public AcceptedTask accept(EmailSendCommand command) {
        validate(command);
        String requestId = command.requestId() == null || command.requestId().isBlank()
                ? UUID.randomUUID().toString() : command.requestId().trim();
        UUID tenantId = command.tenantId();
        EmailTask replay = findReplay(tenantId, requestId);
        if (replay != null) {
            return new AcceptedTask(replay.id, replay.requestId, replay.status, false);
        }
        EmailSender sender = resolveSender(tenantId, command.senderId());
        EmailTask task = new EmailTask();
        task.id = Ids.uuid();
        task.tenantId = tenantId;
        task.requestId = requestId;
        task.senderId = sender.id;
        task.subject = command.subject() == null ? "" : command.subject().trim();
        task.textBody = command.textBody();
        task.htmlBody = command.htmlBody();
        task.status = EmailTaskStatus.PENDING;
        task.attemptCount = 0;
        task.maxAttempts = props.email.maxAttempts;
        task.acceptedAt = Instant.now();
        task.traceId = MDC.get("traceId");
        task.payloadSize = payloadSize(command);
        try {
            taskRepository.saveAndFlush(task);
        } catch (DataIntegrityViolationException duplicate) {
            EmailTask existing = findReplay(tenantId, requestId);
            if (existing != null) {
                return new AcceptedTask(existing.id, existing.requestId, existing.status, false);
            }
            throw duplicate;
        }

        saveRecipients(task.id, command.to(), RecipientType.TO);
        saveRecipients(task.id, command.cc(), RecipientType.CC);
        saveRecipients(task.id, command.bcc(), RecipientType.BCC);
        if (command.attachments() != null) {
            for (EmailAttachmentInput input : command.attachments()) {
                EmailAttachmentStore.StoredAttachment stored = attachmentStore.store(
                        task.id, input.filename(), input.contentType(), input.content());
                EmailAttachment attachment = new EmailAttachment();
                attachment.taskId = task.id;
                attachment.filename = stored.filename();
                attachment.contentType = stored.contentType();
                attachment.fileSize = stored.size();
                attachment.storagePath = stored.storagePath();
                attachment.sha256 = stored.sha256();
                attachmentRepository.save(attachment);
            }
        }
        return new AcceptedTask(task.id, task.requestId, task.status, true);
    }

    public BatchResult acceptBatch(List<EmailSendCommand> commands) {
        if (commands == null || commands.isEmpty()) {
            throw ApiException.validation("emails", "批量发送列表不能为空");
        }
        if (commands.size() > 100) {
            throw ApiException.validation("emails", "单次批量最多 100 封邮件");
        }
        List<BatchItem> items = new ArrayList<>(commands.size());
        for (EmailSendCommand command : commands) {
            try {
                AcceptedTask task = accept(command);
                items.add(new BatchItem(command.requestId(), task.taskId(), true, "0",
                        task.created() ? "accepted" : "idempotent_replay"));
            } catch (ApiException e) {
                items.add(new BatchItem(command.requestId(), null, false, String.valueOf(e.code()),
                        e.getMessage()));
            } catch (RuntimeException e) {
                items.add(new BatchItem(command.requestId(), null, false, "50001",
                        "邮件受理失败: " + e.getMessage()));
            }
        }
        long accepted = items.stream().filter(BatchItem::accepted).count();
        return new BatchResult(items.size(), (int) accepted, items.size() - (int) accepted, items);
    }

    public EmailDtos.EmailTaskView status(UUID tenantId, UUID taskId, String requestId) {
        EmailTask task;
        if (taskId != null) {
            task = taskRepository.findById(taskId)
                    .orElseThrow(() -> ApiException.notFound("邮件任务不存在"));
        } else {
            String id = requestId == null ? "" : requestId.trim();
            if (id.isEmpty()) {
                throw ApiException.validation("request_id", "taskId 与 requestId 至少提供一个");
            }
            task = (tenantId == null
                    ? taskRepository.findFirstByTenantIdIsNullAndRequestId(id)
                    : taskRepository.findFirstByTenantIdAndRequestId(tenantId, id))
                    .or(() -> taskRepository.findFirstByRequestId(id))
                    .orElseThrow(() -> ApiException.notFound("邮件任务不存在"));
        }
        checkTenant(task, tenantId);
        return toView(task);
    }

    public EmailDtos.EmailTaskDetailView detail(UUID tenantId, UUID taskId) {
        EmailTask task = taskRepository.findById(taskId)
                .orElseThrow(() -> ApiException.notFound("邮件任务不存在"));
        checkTenant(task, tenantId);
        List<EmailDtos.RecipientView> recipients = recipientRepository
                .findByTaskIdOrderByCreatedAtAsc(taskId).stream()
                .map(r -> new EmailDtos.RecipientView(r.recipientType.name(), r.address, r.displayName))
                .toList();
        List<EmailDtos.AttachmentView> attachments = attachmentRepository
                .findByTaskIdOrderByCreatedAtAsc(taskId).stream()
                .map(a -> new EmailDtos.AttachmentView(a.id, a.filename, a.contentType, a.fileSize))
                .toList();
        List<EmailDtos.SendRecordView> records = sendRecordRepository
                .findByTaskIdOrderByCreatedAtDesc(taskId).stream()
                .map(this::toRecordView)
                .toList();
        return new EmailDtos.EmailTaskDetailView(toView(task), recipients, attachments, records);
    }

    public PageResult<EmailDtos.EmailTaskView> list(Integer page, Integer size, UUID tenantId,
                                                    UUID senderId, EmailTaskStatus status) {
        PageQuery query = PageQuery.of(page, size);
        Sort sort = Sort.by(Sort.Direction.DESC, "createdAt");
        Page<EmailTask> result;
        if (tenantId != null && senderId != null && status != null) {
            result = taskRepository.findByTenantIdAndSenderIdAndStatus(
                    tenantId, senderId, status, query.pageable(sort));
        } else if (tenantId != null && senderId != null) {
            result = taskRepository.findByTenantIdAndSenderId(tenantId, senderId, query.pageable(sort));
        } else if (tenantId != null && status != null) {
            result = taskRepository.findByTenantIdAndStatus(tenantId, status, query.pageable(sort));
        } else if (tenantId != null) {
            result = taskRepository.findByTenantId(tenantId, query.pageable(sort));
        } else if (senderId != null && status != null) {
            result = taskRepository.findBySenderIdAndStatus(senderId, status, query.pageable(sort));
        } else if (senderId != null) {
            result = taskRepository.findBySenderId(senderId, query.pageable(sort));
        } else if (status != null) {
            result = taskRepository.findByStatus(status, query.pageable(sort));
        } else {
            result = taskRepository.findAll(query.pageable(sort));
        }
        return PageResult.of(result, this::toView);
    }

    @Transactional
    public EmailDtos.EmailTaskView retry(UUID taskId) {
        EmailTask task = taskRepository.findById(taskId)
                .orElseThrow(() -> ApiException.notFound("邮件任务不存在"));
        if (task.status != EmailTaskStatus.FAILED) {
            throw ApiException.conflict("仅失败任务可以手动重试，当前状态: " + task.status);
        }
        int updated = taskRepository.requeueFailed(taskId, Instant.now());
        if (updated == 0) {
            throw ApiException.conflict("任务状态已变化，请刷新后重试");
        }
        taskRepository.flush();
        return toView(taskRepository.findById(taskId).orElseThrow());
    }

    public PageResult<EmailDtos.SendRecordView> listRecords(Integer page, Integer size,
                                                            UUID tenantId, UUID taskId, UUID senderId) {
        PageQuery query = PageQuery.of(page, size);
        Sort sort = Sort.by(Sort.Direction.DESC, "createdAt");
        Page<EmailSendRecord> result;
        if (taskId != null) {
            EmailTask task = taskRepository.findById(taskId)
                    .orElseThrow(() -> ApiException.notFound("邮件任务不存在"));
            checkTenant(task, tenantId);
            result = sendRecordRepository.findByTaskId(taskId, query.pageable(sort));
        } else if (senderId != null) {
            result = sendRecordRepository.findBySenderId(senderId, query.pageable(sort));
        } else {
            result = sendRecordRepository.findAll(query.pageable(sort));
        }
        return PageResult.of(result, this::toRecordView);
    }

    public EmailDtos.EmailTaskView toView(EmailTask task) {
        return new EmailDtos.EmailTaskView(task.id, task.tenantId, task.requestId, task.senderId,
                task.subject, task.status, task.attemptCount, task.maxAttempts, task.nextRetryAt,
                task.lastErrorCode, task.lastErrorMessage, task.providerMessageId, task.acceptedAt,
                task.startedAt, task.finishedAt, task.payloadSize, task.createdAt, task.updatedAt);
    }

    private EmailDtos.SendRecordView toRecordView(EmailSendRecord record) {
        return new EmailDtos.SendRecordView(record.id, record.attempt, record.status.name(),
                record.provider, record.providerMessageId, record.errorCode, record.errorMessage,
                record.durationMs, record.createdAt);
    }

    private void validate(EmailSendCommand command) {
        if (command == null) {
            throw ApiException.badRequest("邮件请求不能为空");
        }
        int total = count(command.to()) + count(command.cc()) + count(command.bcc());
        if (total == 0) {
            throw ApiException.validation("to", "至少需要一个收件人");
        }
        if (total > props.email.maxRecipients) {
            throw ApiException.validation("to", "收件人总数不能超过 " + props.email.maxRecipients);
        }
        if (command.subject() == null || command.subject().isBlank()) {
            throw ApiException.validation("subject", "邮件主题不能为空");
        }
        if (command.subject().length() > MAX_SUBJECT) {
            throw ApiException.validation("subject", "邮件主题不能超过 " + MAX_SUBJECT + " 个字符");
        }
        if ((command.textBody() == null || command.textBody().isBlank())
                && (command.htmlBody() == null || command.htmlBody().isBlank())) {
            throw ApiException.validation("body", "纯文本与 HTML 正文至少提供一个");
        }
        if (command.textBody() != null
                && command.textBody().getBytes(StandardCharsets.UTF_8).length > MAX_BODY_BYTES) {
            throw ApiException.payloadTooLarge("纯文本正文超过 1MB");
        }
        if (command.htmlBody() != null
                && command.htmlBody().getBytes(StandardCharsets.UTF_8).length > MAX_BODY_BYTES) {
            throw ApiException.payloadTooLarge("HTML 正文超过 1MB");
        }
        validateRecipients(command.to(), "to");
        validateRecipients(command.cc(), "cc");
        validateRecipients(command.bcc(), "bcc");
        if (command.attachments() != null) {
            long totalBytes = command.attachments().stream()
                    .filter(Objects::nonNull)
                    .mapToLong(a -> a.content() == null ? 0 : a.content().length)
                    .sum();
            if (totalBytes > props.email.maxTotalAttachmentBytes) {
                throw ApiException.payloadTooLarge("附件总大小超过限制 " + props.email.maxTotalAttachmentBytes + " 字节");
            }
        }
    }

    private void validateRecipients(List<String> addresses, String field) {
        if (addresses == null) {
            return;
        }
        for (String address : addresses) {
            if (address == null || address.isBlank()) {
                throw ApiException.validation(field, "收件人地址不能为空");
            }
            String value = address.trim();
            if (value.length() > 320 || !EMAIL_PATTERN.matcher(value).matches()) {
                throw ApiException.validation(field, "非法邮箱地址: " + value);
            }
        }
    }

    private static int count(List<String> addresses) {
        return addresses == null ? 0 : addresses.size();
    }

    private EmailSender resolveSender(UUID tenantId, UUID senderId) {
        EmailSender sender;
        if (senderId != null) {
            sender = senderRepository.findByIdAndDeletedFalse(senderId)
                    .orElseThrow(() -> ApiException.notFound("邮件发送方不存在"));
            if (!tenantCompatible(tenantId, sender.tenantId)) {
                throw ApiException.notFound("邮件发送方不存在");
            }
        } else if (tenantId != null) {
            sender = senderRepository.findFirstByTenantIdAndDefaultSenderTrueAndDeletedFalse(tenantId)
                    .or(() -> senderRepository.findFirstByDefaultSenderTrueAndDeletedFalse()
                            .filter(candidate -> candidate.tenantId == null))
                    .orElseThrow(() -> ApiException.unavailable("租户未配置默认邮件发送方"));
        } else {
            sender = senderRepository.findFirstByDefaultSenderTrueAndDeletedFalse()
                    .orElseThrow(() -> ApiException.unavailable("未配置默认邮件发送方"));
        }
        if (!sender.enabled) {
            throw ApiException.unavailable("邮件发送方已禁用");
        }
        if (sender.providerType != EmailProviderType.SMTP) {
            throw ApiException.unavailable("暂不支持的邮件供应商: " + sender.providerType);
        }
        EmailSenderConfig config = configRepository.findBySenderId(sender.id).orElse(null);
        if (config == null || config.smtpHost == null || config.smtpHost.isBlank()) {
            throw ApiException.unavailable("邮件发送方 SMTP 配置不完整");
        }
        return sender;
    }

    private static boolean tenantCompatible(UUID requestedTenant, UUID senderTenant) {
        if (requestedTenant == null) {
            return senderTenant == null;
        }
        return senderTenant == null || senderTenant.equals(requestedTenant);
    }

    private EmailTask findReplay(UUID tenantId, String requestId) {
        return tenantId == null
                ? taskRepository.findFirstByTenantIdIsNullAndRequestId(requestId).orElse(null)
                : taskRepository.findFirstByTenantIdAndRequestId(tenantId, requestId).orElse(null);
    }

    private void checkTenant(EmailTask task, UUID tenantId) {
        if (tenantId != null && !tenantId.equals(task.tenantId)) {
            throw ApiException.notFound("邮件任务不存在");
        }
    }

    private void saveRecipients(UUID taskId, List<String> addresses, RecipientType type) {
        if (addresses == null) {
            return;
        }
        for (String address : addresses) {
            EmailRecipient recipient = new EmailRecipient();
            recipient.taskId = taskId;
            recipient.recipientType = type;
            recipient.address = address.trim();
            recipientRepository.save(recipient);
        }
    }

    private int payloadSize(EmailSendCommand command) {
        int size = 0;
        if (command.textBody() != null) {
            size += command.textBody().getBytes(StandardCharsets.UTF_8).length;
        }
        if (command.htmlBody() != null) {
            size += command.htmlBody().getBytes(StandardCharsets.UTF_8).length;
        }
        if (command.attachments() != null) {
            size += command.attachments().stream()
                    .filter(Objects::nonNull)
                    .mapToInt(a -> a.content() == null ? 0 : a.content().length)
                    .sum();
        }
        return size;
    }

    public record EmailAttachmentInput(String filename, String contentType, byte[] content) {
    }

    public record EmailSendCommand(UUID tenantId, String requestId, UUID senderId,
                                   List<String> to, List<String> cc, List<String> bcc,
                                   String subject, String textBody, String htmlBody,
                                   List<EmailAttachmentInput> attachments) {
    }

    public record AcceptedTask(UUID taskId, String requestId, EmailTaskStatus status, boolean created) {
    }

    public record BatchItem(String requestId, UUID taskId, boolean accepted, String code, String message) {
    }

    public record BatchResult(int total, int acceptedCount, int failureCount, List<BatchItem> items) {
    }
}
