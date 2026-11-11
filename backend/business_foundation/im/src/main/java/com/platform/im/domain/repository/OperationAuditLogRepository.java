package com.platform.im.domain.repository;

import com.platform.im.domain.audit.OperationAuditLog;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.UUID;

public interface OperationAuditLogRepository extends JpaRepository<OperationAuditLog, UUID> {
    Page<OperationAuditLog> findAll(Pageable pageable);

    Page<OperationAuditLog> findByTenantId(UUID tenantId, Pageable pageable);

    Page<OperationAuditLog> findByActionContainingIgnoreCase(String action, Pageable pageable);
}
