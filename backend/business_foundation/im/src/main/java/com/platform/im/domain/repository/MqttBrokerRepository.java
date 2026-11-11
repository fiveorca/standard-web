package com.platform.im.domain.repository;

import com.platform.im.domain.mqtt.MqttBroker;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface MqttBrokerRepository extends JpaRepository<MqttBroker, UUID> {
    Optional<MqttBroker> findByCodeIgnoreCase(String code);

    boolean existsByCodeIgnoreCase(String code);

    Optional<MqttBroker> findFirstByDefaultBrokerTrue();

    Optional<MqttBroker> findFirstByDefaultBrokerTrueAndEnabledTrue();

    List<MqttBroker> findByEnabledTrueOrderByNameAsc();

    Page<MqttBroker> findByCodeContainingIgnoreCaseOrNameContainingIgnoreCase(
            String code, String name, Pageable pageable);

    long countByDefaultBrokerTrue();
}
