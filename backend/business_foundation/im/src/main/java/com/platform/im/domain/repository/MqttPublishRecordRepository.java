package com.platform.im.domain.repository;

import com.platform.im.domain.mqtt.MqttPublishRecord;
import com.platform.im.domain.mqtt.PublishStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface MqttPublishRecordRepository extends JpaRepository<MqttPublishRecord, UUID> {
    Optional<MqttPublishRecord> findByTenantIdAndMessageId(UUID tenantId, String messageId);

    Optional<MqttPublishRecord> findFirstByTenantIdIsNullAndMessageId(String messageId);

    Optional<MqttPublishRecord> findByIdAndTenantId(UUID id, UUID tenantId);

    Page<MqttPublishRecord> findAll(Pageable pageable);

    Page<MqttPublishRecord> findByTenantId(UUID tenantId, Pageable pageable);

    Page<MqttPublishRecord> findByTenantIdAndStatus(UUID tenantId, PublishStatus status, Pageable pageable);

    Page<MqttPublishRecord> findByTenantIdAndDeviceId(UUID tenantId, String deviceId, Pageable pageable);

    Page<MqttPublishRecord> findByTenantIdAndStatusAndDeviceId(
            UUID tenantId, PublishStatus status, String deviceId, Pageable pageable);

    Page<MqttPublishRecord> findByStatus(PublishStatus status, Pageable pageable);

    Page<MqttPublishRecord> findByDeviceId(String deviceId, Pageable pageable);

    Page<MqttPublishRecord> findByStatusAndDeviceId(PublishStatus status, String deviceId, Pageable pageable);
}
