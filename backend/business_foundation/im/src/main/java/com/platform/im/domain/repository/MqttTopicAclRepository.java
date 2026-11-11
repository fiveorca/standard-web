package com.platform.im.domain.repository;

import com.platform.im.domain.mqtt.AclAction;
import com.platform.im.domain.mqtt.AclSubjectType;
import com.platform.im.domain.mqtt.MqttTopicAcl;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface MqttTopicAclRepository extends JpaRepository<MqttTopicAcl, UUID> {
    List<MqttTopicAcl> findByAccessConfigIdAndEnabledTrueOrderByPriorityDesc(UUID accessConfigId);

    List<MqttTopicAcl> findByAccessConfigIdAndSubjectTypeAndSubjectIdAndActionAndEnabledTrueOrderByPriorityDesc(
            UUID accessConfigId, AclSubjectType subjectType, String subjectId, AclAction action);

    List<MqttTopicAcl> findByAccessConfigIdAndSubjectTypeAndActionAndEnabledTrueOrderByPriorityDesc(
            UUID accessConfigId, AclSubjectType subjectType, AclAction action);

    List<MqttTopicAcl> findByAccessConfigIdOrderByPriorityDesc(UUID accessConfigId);

    long countByAccessConfigId(UUID accessConfigId);

    void deleteByAccessConfigId(UUID accessConfigId);
}
