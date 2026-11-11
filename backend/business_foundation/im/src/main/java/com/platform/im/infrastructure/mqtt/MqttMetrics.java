package com.platform.im.infrastructure.mqtt;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

@Component
public class MqttMetrics {
    private final Counter publishSuccess;
    private final Counter publishFailure;
    private final Counter reconnect;
    private final Timer publishTimer;

    public MqttMetrics(MeterRegistry registry) {
        this.publishSuccess = Counter.builder("im.mqtt.publish.total")
                .tag("result", "success").register(registry);
        this.publishFailure = Counter.builder("im.mqtt.publish.total")
                .tag("result", "failure").register(registry);
        this.reconnect = Counter.builder("im.mqtt.reconnect.total").register(registry);
        this.publishTimer = Timer.builder("im.mqtt.publish.duration").register(registry);
    }

    public void recordSuccess(long durationNanos) {
        publishSuccess.increment();
        publishTimer.record(java.time.Duration.ofNanos(durationNanos));
    }

    public void recordFailure(long durationNanos) {
        publishFailure.increment();
        publishTimer.record(java.time.Duration.ofNanos(durationNanos));
    }

    public void recordReconnect() {
        reconnect.increment();
    }
}
