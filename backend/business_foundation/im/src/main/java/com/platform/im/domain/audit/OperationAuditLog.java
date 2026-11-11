package com.platform.im.domain.audit;

import com.platform.im.domain.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;

import java.util.UUID;

@Entity
@Table(name = "operation_audit_log")
public class OperationAuditLog extends BaseEntity {
    @Column(name = "tenant_id")
    public UUID tenantId;

    @Column(name = "actor")
    public String actor;

    @Column(name = "actor_type")
    public String actorType;

    @Column(name = "action", nullable = false)
    public String action;

    @Column(name = "resource_type")
    public String resourceType;

    @Column(name = "resource_id")
    public String resourceId;

    @Column(name = "method")
    public String method;

    @Column(name = "path")
    public String path;

    @Column(name = "status")
    public Integer status;

    @Column(name = "ip_address")
    public String ipAddress;

    @Column(name = "user_agent")
    public String userAgent;

    @Column(name = "trace_id")
    public String traceId;

    @Column(name = "duration_ms")
    public Long durationMs;

    @Column(name = "detail_json")
    public String detailJson;
}
