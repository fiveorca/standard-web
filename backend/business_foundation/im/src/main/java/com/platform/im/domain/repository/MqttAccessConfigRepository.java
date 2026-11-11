package com.platform.im.domain.repository;

import com.platform.im.domain.mqtt.MqttAccessConfig;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface MqttAccessConfigRepository extends JpaRepository<MqttAccessConfig, UUID> {
    Optional<MqttAccessConfig> findByIdAndDeletedFalse(UUID id);

    Optional<MqttAccessConfig> findByCodeIgnoreCaseAndDeletedFalse(String code);

    boolean existsByCodeIgnoreCaseAndDeletedFalse(String code);

    Optional<MqttAccessConfig> findFirstByDefaultConfigTrueAndDeletedFalseAndTenantIdIsNull();

    Optional<MqttAccessConfig> findFirstByTenantIdAndDefaultConfigTrueAndDeletedFalse(UUID tenantId);

    Page<MqttAccessConfig> findByDeletedFalse(Pageable pageable);

    Page<MqttAccessConfig> findByTenantIdAndDeletedFalse(UUID tenantId, Pageable pageable);

    Page<MqttAccessConfig> findByCodeContainingIgnoreCaseAndDeletedFalse(String code, Pageable pageable);

    List<MqttAccessConfig> findByBrokerIdAndDeletedFalse(UUID brokerId);

    List<MqttAccessConfig> findByDeletedFalseOrderByNameAsc();

    long countByBrokerIdAndDeletedFalse(UUID brokerId);
}
