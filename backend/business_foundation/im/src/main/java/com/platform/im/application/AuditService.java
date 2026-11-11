package com.platform.im.application;

import com.platform.im.domain.audit.OperationAuditLog;
import com.platform.im.domain.repository.OperationAuditLogRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class AuditService {
    private final OperationAuditLogRepository repository;

    public AuditService(OperationAuditLogRepository repository) {
        this.repository = repository;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void record(AuditEntry entry) {
        OperationAuditLog log = new OperationAuditLog();
        log.tenantId = entry.tenantId();
        log.actor = entry.actor();
        log.actorType = entry.actorType();
        log.action = entry.action();
        log.resourceType = entry.resourceType();
        log.resourceId = entry.resourceId();
        log.method = entry.method();
        log.path = entry.path();
        log.status = entry.status();
        log.ipAddress = entry.ipAddress();
        log.userAgent = entry.userAgent();
        log.traceId = entry.traceId();
        log.durationMs = entry.durationMs();
        log.detailJson = entry.detailJson();
        log.createdAt = Instant.now();
        repository.save(log);
    }

    public record AuditEntry(UUID tenantId, String actor, String actorType, String action,
                             String resourceType, String resourceId, String method, String path,
                             Integer status, String ipAddress, String userAgent, String traceId,
                             Long durationMs, String detailJson) {
    }
}
