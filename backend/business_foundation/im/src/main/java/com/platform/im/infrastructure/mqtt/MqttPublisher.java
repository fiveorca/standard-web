package com.platform.im.infrastructure.mqtt;

import com.platform.im.domain.mqtt.MqttBroker;

import java.util.Map;
import java.util.UUID;

public interface MqttPublisher {
    void publish(MqttBroker broker, String topic, byte[] payload, int qos,
                 boolean retained, long messageExpiryIntervalSeconds);

    TestResult testConnection(MqttBroker broker);

    boolean isConnected(UUID brokerId);

    void evict(UUID brokerId);

    Map<UUID, Boolean> connectionStates();

    record TestResult(boolean success, long latencyMs, String message) {
    }
}
