package com.platform.im.infrastructure.mqtt;

import com.platform.im.domain.mqtt.BrokerConnectionStatus;
import com.platform.im.domain.repository.MqttBrokerRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

@Service
public class MqttBrokerStatusService {
    private final MqttBrokerRepository repository;

    public MqttBrokerStatusService(MqttBrokerRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public void update(UUID brokerId, BrokerConnectionStatus status, String message,
                       Instant connectedAt, boolean incrementReconnect) {
        repository.findById(brokerId).ifPresent(broker -> {
            broker.status = status;
            broker.statusMessage = message;
            broker.lastCheckedAt = Instant.now();
            if (connectedAt != null) {
                broker.lastConnectedAt = connectedAt;
            }
            if (incrementReconnect) {
                broker.reconnectCount = broker.reconnectCount + 1;
            }
            repository.save(broker);
        });
    }
}
