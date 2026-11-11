package com.platform.im.domain.mqtt;

import com.platform.im.domain.common.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Table;

import java.util.UUID;

@Entity
@Table(name = "mqtt_topic_acl")
public class MqttTopicAcl extends BaseEntity {
    @Column(name = "tenant_id")
    public UUID tenantId;

    @Column(name = "access_config_id", nullable = false)
    public UUID accessConfigId;

    @Enumerated(EnumType.STRING)
    @Column(name = "subject_type", nullable = false)
    public AclSubjectType subjectType;

    @Column(name = "subject_id", nullable = false)
    public String subjectId;

    @Column(name = "topic_pattern", nullable = false)
    public String topicPattern;

    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false)
    public AclAction action;

    @Enumerated(EnumType.STRING)
    @Column(name = "effect", nullable = false)
    public AclEffect effect = AclEffect.ALLOW;

    @Column(name = "qos_max", nullable = false)
    public int qosMax = 2;

    @Column(name = "priority", nullable = false)
    public int priority;

    @Column(name = "enabled", nullable = false)
    public boolean enabled = true;
}
