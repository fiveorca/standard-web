package com.platform.im.infrastructure.email;

import com.platform.im.domain.email.EmailTaskStatus;
import com.platform.im.domain.repository.EmailTaskRepository;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

@Component
public class EmailMetrics {
    private final Counter success;
    private final Counter failure;
    private final Counter retry;
    private final Timer sendTimer;
    private final AtomicInteger processing = new AtomicInteger();

    public EmailMetrics(MeterRegistry registry, EmailTaskRepository taskRepository) {
        this.success = Counter.builder("im.email.send.total").tag("result", "success").register(registry);
        this.failure = Counter.builder("im.email.send.total").tag("result", "failure").register(registry);
        this.retry = Counter.builder("im.email.retry.total").register(registry);
        this.sendTimer = Timer.builder("im.email.send.duration").register(registry);
        Gauge.builder("im.email.pending.tasks", taskRepository,
                        repo -> repo.countByStatusIn(List.of(EmailTaskStatus.PENDING, EmailTaskStatus.RETRYING)))
                .description("待发送与待重试邮件任务数")
                .register(registry);
        Gauge.builder("im.email.worker.processing", processing, AtomicInteger::get)
                .description("当前正在发送的邮件任务数")
                .register(registry);
    }

    public void recordSuccess(long durationNanos) {
        success.increment();
        sendTimer.record(Duration.ofNanos(durationNanos));
    }

    public void recordFailure(long durationNanos) {
        failure.increment();
        sendTimer.record(Duration.ofNanos(durationNanos));
    }

    public void recordRetry() {
        retry.increment();
    }

    public int beginProcessing() {
        return processing.incrementAndGet();
    }

    public void endProcessing() {
        processing.updateAndGet(value -> Math.max(0, value - 1));
    }
}
