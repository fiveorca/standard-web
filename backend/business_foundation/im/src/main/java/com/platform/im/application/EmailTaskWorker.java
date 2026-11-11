package com.platform.im.application;

import com.platform.im.config.AppProperties;
import com.platform.im.infrastructure.email.EmailMetrics;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 邮件异步发送 Worker：定时抢占任务、恢复僵死任务并逐个投递。
 */
@Component
public class EmailTaskWorker {
    private static final Logger log = LoggerFactory.getLogger(EmailTaskWorker.class);
    private static final long RECOVERY_INTERVAL_MS = 60_000;

    private final EmailTaskClaimer claimer;
    private final EmailDeliveryService deliveryService;
    private final EmailMetrics metrics;
    private final AppProperties props;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final AtomicLong lastRecoveryAt = new AtomicLong(0);

    public EmailTaskWorker(EmailTaskClaimer claimer,
                           EmailDeliveryService deliveryService,
                           EmailMetrics metrics,
                           AppProperties props) {
        this.claimer = claimer;
        this.deliveryService = deliveryService;
        this.metrics = metrics;
        this.props = props;
    }

    @Scheduled(fixedDelayString = "${im.email.poll-interval-ms:2000}",
            initialDelayString = "${im.email.poll-interval-ms:2000}")
    public void poll() {
        if (!props.email.workerEnabled) {
            return;
        }
        if (!running.compareAndSet(false, true)) {
            return;
        }
        try {
            recoverStaleIfNeeded();
            List<UUID> taskIds = claimer.claim(props.email.batchSize);
            for (UUID taskId : taskIds) {
                metrics.beginProcessing();
                try {
                    deliveryService.deliver(taskId);
                } catch (RuntimeException ex) {
                    log.error("email delivery crashed taskId={}", taskId, ex);
                } finally {
                    metrics.endProcessing();
                }
            }
        } catch (RuntimeException ex) {
            log.error("email worker poll failed", ex);
        } finally {
            running.set(false);
        }
    }

    private void recoverStaleIfNeeded() {
        long now = Instant.now().toEpochMilli();
        long last = lastRecoveryAt.get();
        if (now - last < RECOVERY_INTERVAL_MS) {
            return;
        }
        if (lastRecoveryAt.compareAndSet(last, now)) {
            int recovered = claimer.recoverStale();
            if (recovered > 0) {
                log.warn("recovered {} stale email tasks", recovered);
            }
        }
    }

    public boolean isRunning() {
        return running.get();
    }
}
