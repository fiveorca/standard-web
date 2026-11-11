package com.platform.im.application;

import com.platform.im.domain.email.EmailProviderType;
import com.platform.im.domain.email.EmailSender;
import com.platform.im.domain.email.EmailSenderConfig;
import com.platform.im.domain.repository.EmailSenderConfigRepository;
import com.platform.im.domain.repository.EmailSenderRepository;
import com.platform.im.domain.repository.EmailTaskRepository;
import com.platform.im.infrastructure.email.EmailProvider;
import com.platform.im.infrastructure.email.EmailProviderRegistry;
import com.platform.im.shared.ApiException;
import com.platform.im.shared.CryptoService;
import com.platform.im.shared.Ids;
import com.platform.im.shared.PageQuery;
import com.platform.im.shared.PageResult;
import com.platform.im.web.dto.EmailDtos;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Locale;
import java.util.UUID;

@Service
public class EmailSenderService {
    private final EmailSenderRepository senderRepository;
    private final EmailSenderConfigRepository configRepository;
    private final EmailTaskRepository taskRepository;
    private final EmailProviderRegistry providerRegistry;
    private final CryptoService crypto;

    public EmailSenderService(EmailSenderRepository senderRepository,
                              EmailSenderConfigRepository configRepository,
                              EmailTaskRepository taskRepository,
                              EmailProviderRegistry providerRegistry,
                              CryptoService crypto) {
        this.senderRepository = senderRepository;
        this.configRepository = configRepository;
        this.taskRepository = taskRepository;
        this.providerRegistry = providerRegistry;
        this.crypto = crypto;
    }

    public PageResult<EmailDtos.SenderView> list(Integer page, Integer size, String q, String tenantId) {
        PageQuery query = PageQuery.of(page, size);
        Sort sort = Sort.by(Sort.Direction.DESC, "createdAt");
        UUID tenant = Ids.parseUuid(tenantId, "tenant_id");
        Page<EmailSender> result;
        if (q != null && !q.isBlank()) {
            result = senderRepository.findByCodeContainingIgnoreCaseAndDeletedFalse(q.trim(), query.pageable(sort));
        } else if (tenant != null) {
            result = senderRepository.findByTenantIdAndDeletedFalse(tenant, query.pageable(sort));
        } else {
            result = senderRepository.findByDeletedFalse(query.pageable(sort));
        }
        return PageResult.of(result, this::toView);
    }

    public EmailDtos.SenderView get(UUID id) {
        return toView(require(id));
    }

    @Transactional
    public EmailDtos.SenderView create(EmailDtos.SenderRequest request) {
        EmailSender sender = new EmailSender();
        sender.tenantId = Ids.parseUuid(request.tenantId(), "tenant_id");
        sender.code = resolveCode(request.code(), request.name());
        if (senderRepository.existsByCodeIgnoreCaseAndDeletedFalse(sender.code)) {
            throw ApiException.conflict("邮件发送方 code 已存在");
        }
        sender.name = request.name().trim();
        sender.fromAddress = request.fromAddress().trim();
        sender.fromName = request.fromName() == null ? null : request.fromName().trim();
        sender.providerType = request.providerType() == null ? EmailProviderType.SMTP : request.providerType();
        sender.ratePerMinute = request.ratePerMinute() == null ? 60 : request.ratePerMinute();
        sender.ratePerDay = request.ratePerDay() == null ? 5000 : request.ratePerDay();
        sender.enabled = request.enabled() == null || request.enabled();
        if (Boolean.TRUE.equals(request.defaultSender())) {
            clearDefault(sender.tenantId);
            sender.defaultSender = true;
        }
        EmailSender saved = senderRepository.save(sender);
        EmailSenderConfig config = buildConfig(saved.id, request.smtp(), null);
        configRepository.save(config);
        return toView(saved);
    }

    @Transactional
    public EmailDtos.SenderView update(UUID id, EmailDtos.SenderRequest request) {
        EmailSender sender = require(id);
        String code = request.code() == null || request.code().isBlank() ? sender.code : request.code().trim();
        senderRepository.findByCodeIgnoreCaseAndDeletedFalse(code).ifPresent(existing -> {
            if (!existing.id.equals(id)) {
                throw ApiException.conflict("邮件发送方 code 已存在");
            }
        });
        UUID newTenant = Ids.parseUuid(request.tenantId(), "tenant_id");
        if (sender.defaultSender && !java.util.Objects.equals(sender.tenantId, newTenant)) {
            sender.defaultSender = false;
        }
        sender.code = code;
        sender.tenantId = newTenant;
        sender.name = request.name().trim();
        sender.fromAddress = request.fromAddress().trim();
        sender.fromName = request.fromName() == null ? null : request.fromName().trim();
        if (request.providerType() != null) {
            sender.providerType = request.providerType();
        }
        if (request.ratePerMinute() != null) {
            sender.ratePerMinute = request.ratePerMinute();
        }
        if (request.ratePerDay() != null) {
            sender.ratePerDay = request.ratePerDay();
        }
        if (request.enabled() != null) {
            sender.enabled = request.enabled();
            if (!sender.enabled) {
                sender.defaultSender = false;
            }
        }
        if (Boolean.TRUE.equals(request.defaultSender()) && !sender.defaultSender) {
            if (!sender.enabled) {
                throw ApiException.badRequest("禁用的发送方不能设为默认");
            }
            clearDefault(sender.tenantId);
            sender.defaultSender = true;
        }
        EmailSender saved = senderRepository.save(sender);
        EmailSenderConfig config = configRepository.findBySenderId(id)
                .orElseGet(() -> buildConfig(id, request.smtp(), null));
        applyConfig(config, request.smtp(), null);
        configRepository.save(config);
        return toView(saved);
    }

    @Transactional
    public void delete(UUID id) {
        EmailSender sender = require(id);
        long references = taskRepository.countBySenderId(id);
        if (references > 0) {
            throw ApiException.conflict("发送方仍被 " + references + " 个邮件任务引用，无法删除，可改为禁用");
        }
        sender.deleted = true;
        sender.defaultSender = false;
        senderRepository.save(sender);
        configRepository.deleteBySenderId(id);
    }

    @Transactional
    public EmailDtos.SenderView setEnabled(UUID id, boolean enabled) {
        EmailSender sender = require(id);
        sender.enabled = enabled;
        if (!enabled) {
            sender.defaultSender = false;
        }
        return toView(senderRepository.save(sender));
    }

    @Transactional
    public EmailDtos.SenderView setDefault(UUID id) {
        EmailSender sender = require(id);
        if (!sender.enabled) {
            throw ApiException.badRequest("禁用的发送方不能设为默认");
        }
        clearDefault(sender.tenantId);
        sender.defaultSender = true;
        return toView(senderRepository.save(sender));
    }

    @Transactional
    public EmailDtos.SenderView updatePassword(UUID id, String password) {
        EmailSender sender = require(id);
        EmailSenderConfig config = configRepository.findBySenderId(id)
                .orElseThrow(() -> ApiException.conflict("发送方未配置 SMTP 连接"));
        config.smtpPasswordCipher = password == null || password.isBlank() ? null : crypto.encrypt(password);
        configRepository.save(config);
        return toView(sender);
    }

    public EmailDtos.TestConnectionResultView testConnection(UUID id) {
        EmailSender sender = require(id);
        EmailSenderConfig config = configRepository.findBySenderId(id)
                .orElseThrow(() -> ApiException.conflict("发送方未配置 SMTP 连接"));
        EmailProvider provider = providerRegistry.require(sender.providerType);
        long start = System.nanoTime();
        try {
            provider.testConnection(config, decrypt(config));
            return new EmailDtos.TestConnectionResultView(true, (System.nanoTime() - start) / 1_000_000,
                    "SMTP 连接成功");
        } catch (Exception e) {
            return new EmailDtos.TestConnectionResultView(false, (System.nanoTime() - start) / 1_000_000,
                    "SMTP 连接失败: " + e.getMessage());
        }
    }

    public EmailDtos.TestConnectionResultView sendTestEmail(UUID id, String to) {
        EmailSender sender = require(id);
        if (!sender.enabled) {
            throw ApiException.badRequest("发送方已禁用");
        }
        EmailSenderConfig config = configRepository.findBySenderId(id)
                .orElseThrow(() -> ApiException.conflict("发送方未配置 SMTP 连接"));
        EmailProvider provider = providerRegistry.require(sender.providerType);
        EmailProvider.OutgoingEmail email = new EmailProvider.OutgoingEmail(
                UUID.randomUUID(), sender.fromAddress, sender.fromName,
                List.of(new EmailProvider.EmailAddress(to, null)), List.of(), List.of(),
                "IM Service SMTP 测试邮件",
                "这是一封来自 IM 通信服务的 SMTP 测试邮件，收到即表示发送方配置可用。",
                null, List.of());
        long start = System.nanoTime();
        EmailProvider.EmailSendResult result = provider.send(email, config, decrypt(config));
        long latency = (System.nanoTime() - start) / 1_000_000;
        if (!result.success()) {
            return new EmailDtos.TestConnectionResultView(false, latency,
                    "测试邮件发送失败: " + result.errorMessage());
        }
        return new EmailDtos.TestConnectionResultView(true, latency, "测试邮件已发送");
    }

    public EmailSender require(UUID id) {
        return senderRepository.findByIdAndDeletedFalse(id)
                .orElseThrow(() -> ApiException.notFound("邮件发送方不存在"));
    }

    public EmailDtos.SenderView toView(EmailSender sender) {
        EmailSenderConfig config = configRepository.findBySenderId(sender.id).orElse(null);
        return new EmailDtos.SenderView(sender.id, sender.tenantId, sender.code, sender.name,
                sender.fromAddress, sender.fromName, sender.providerType.name(), sender.defaultSender,
                sender.enabled, sender.ratePerMinute, sender.ratePerDay,
                config == null ? null : config.smtpHost,
                config == null ? 0 : config.smtpPort,
                config == null ? null : config.smtpUsername,
                config != null && config.smtpAuth,
                config != null && config.sslEnabled,
                config != null && config.starttlsEnabled,
                config == null ? 0 : config.connectionTimeoutMs,
                config == null ? 0 : config.readTimeoutMs,
                config == null ? 0 : config.writeTimeoutMs,
                config != null && config.smtpPasswordCipher != null && !config.smtpPasswordCipher.isBlank(),
                sender.createdAt, sender.updatedAt);
    }

    public String decrypt(EmailSenderConfig config) {
        return config.smtpPasswordCipher == null || config.smtpPasswordCipher.isBlank()
                ? null : crypto.decrypt(config.smtpPasswordCipher);
    }

    private EmailSenderConfig buildConfig(UUID senderId, EmailDtos.SmtpConfig smtp, String keepCipher) {
        EmailSenderConfig config = new EmailSenderConfig();
        config.senderId = senderId;
        applyConfig(config, smtp, keepCipher);
        return config;
    }

    private void applyConfig(EmailSenderConfig config, EmailDtos.SmtpConfig smtp, String keepCipher) {
        if (smtp == null) {
            throw ApiException.validation("smtp", "SMTP 配置不能为空");
        }
        config.smtpHost = smtp.host().trim();
        config.smtpPort = smtp.port() == null ? 587 : smtp.port();
        config.smtpUsername = smtp.username() == null || smtp.username().isBlank() ? null : smtp.username().trim();
        if (smtp.password() != null && !smtp.password().isBlank()) {
            config.smtpPasswordCipher = crypto.encrypt(smtp.password());
        } else if (keepCipher != null) {
            config.smtpPasswordCipher = keepCipher;
        }
        config.smtpAuth = smtp.auth() == null || smtp.auth();
        config.sslEnabled = Boolean.TRUE.equals(smtp.ssl());
        config.starttlsEnabled = smtp.starttls() == null || smtp.starttls();
        config.connectionTimeoutMs = smtp.connectionTimeoutMs() == null ? 10000 : smtp.connectionTimeoutMs();
        config.readTimeoutMs = smtp.readTimeoutMs() == null ? 30000 : smtp.readTimeoutMs();
        config.writeTimeoutMs = smtp.writeTimeoutMs() == null ? 30000 : smtp.writeTimeoutMs();
    }

    private String resolveCode(String code, String name) {
        if (code != null && !code.isBlank()) {
            return code.trim();
        }
        String base = name == null ? "sender" : name.trim().toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "-").replaceAll("^-+|-+$", "");
        if (base.isBlank()) {
            base = "sender";
        }
        return base + "-" + Ids.randomToken(4).toLowerCase(Locale.ROOT);
    }

    private void clearDefault(UUID tenantId) {
        if (tenantId == null) {
            senderRepository.findFirstByDefaultSenderTrueAndDeletedFalse().ifPresent(existing -> {
                if (existing.tenantId == null) {
                    existing.defaultSender = false;
                    senderRepository.save(existing);
                }
            });
        } else {
            senderRepository.findFirstByTenantIdAndDefaultSenderTrueAndDeletedFalse(tenantId)
                    .ifPresent(existing -> {
                        existing.defaultSender = false;
                        senderRepository.save(existing);
                    });
        }
    }
}
