package com.platform.im.domain.repository;

import com.platform.im.domain.mqtt.MqttDeviceCredential;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface MqttDeviceCredentialRepository extends JpaRepository<MqttDeviceCredential, UUID> {
    Optional<MqttDeviceCredential> findByIdAndDeletedFalse(UUID id);

    Optional<MqttDeviceCredential> findByTenantIdAndDeviceIdAndDeletedFalse(UUID tenantId, String deviceId);

    Optional<MqttDeviceCredential> findFirstByTenantIdIsNullAndDeviceIdAndDeletedFalse(String deviceId);

    Optional<MqttDeviceCredential> findFirstByDeviceIdAndDeletedFalseOrderByCreatedAtAsc(String deviceId);

    Optional<MqttDeviceCredential> findByUsernameAndDeletedFalse(String username);

    Page<MqttDeviceCredential> findByDeletedFalse(Pageable pageable);

    Page<MqttDeviceCredential> findByTenantIdAndDeletedFalse(UUID tenantId, Pageable pageable);

    Page<MqttDeviceCredential> findByTenantIdAndDeviceIdContainingIgnoreCaseAndDeletedFalse(
            UUID tenantId, String deviceId, Pageable pageable);

    Page<MqttDeviceCredential> findByDeviceIdContainingIgnoreCaseAndDeletedFalse(String deviceId, Pageable pageable);

    List<MqttDeviceCredential> findByAccessConfigIdAndDeletedFalse(UUID accessConfigId);

    long countByAccessConfigIdAndDeletedFalse(UUID accessConfigId);

    long countByTenantIdAndDeviceIdAndDeletedFalse(UUID tenantId, String deviceId);
}
