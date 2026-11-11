package com.platform.im.infrastructure.mqtt;

import com.platform.im.domain.mqtt.MqttBroker;
import com.platform.im.domain.repository.MqttBrokerRepository;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Component
public class MqttHealthIndicator implements HealthIndicator {
    private final MqttBrokerRepository brokerRepository;
    private final MqttPublisher publisher;

    public MqttHealthIndicator(MqttBrokerRepository brokerRepository, MqttPublisher publisher) {
        this.brokerRepository = brokerRepository;
        this.publisher = publisher;
    }

    @Override
    public Health health() {
        try {
            List<MqttBroker> brokers = brokerRepository.findByEnabledTrueOrderByNameAsc();
            Map<String, Object> details = new LinkedHashMap<>();
            int connected = 0;
            for (MqttBroker broker : brokers) {
                boolean isConnected = publisher.isConnected(broker.id);
                if (isConnected) {
                    connected++;
                }
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("connected", isConnected);
                item.put("storedStatus", broker.status);
                item.put("lastConnectedAt", broker.lastConnectedAt);
                item.put("reconnectCount", broker.reconnectCount);
                details.put(broker.code, item);
            }
            details.put("enabledBrokers", brokers.size());
            details.put("connectedBrokers", connected);
            return Health.up().withDetails(details).build();
        } catch (Exception e) {
            return Health.down(e).build();
        }
    }
}
