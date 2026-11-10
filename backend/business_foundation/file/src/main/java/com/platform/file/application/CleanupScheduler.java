package com.platform.file.application;

import com.platform.file.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * 定时清理调度。任务本身通过数据库锁互斥，多实例部署时同一时刻只有一个实例执行。
 */
@Component
public class CleanupScheduler {
    private static final Logger log = LoggerFactory.getLogger(CleanupScheduler.class);

    private final CleanupService cleanup;
    private final AppProperties props;

    public CleanupScheduler(CleanupService cleanup, AppProperties props) {
        this.cleanup = cleanup;
        this.props = props;
    }

    @Scheduled(fixedDelayString = "${file.cleanup.expiry-interval-ms:60000}", initialDelay = 45000)
    public void expireUploads() {
        if (!props.cleanup.enabled) {
            return;
        }
        try {
            cleanup.uploadExpiry();
        } catch (Exception e) {
            log.warn("定时回收过期上传任务失败: {}", e.getMessage());
        }
    }

    @Scheduled(fixedDelayString = "${file.cleanup.delete-interval-ms:300000}", initialDelay = 60000)
    public void deletePendingObjects() {
        if (!props.cleanup.enabled) {
            return;
        }
        try {
            cleanup.physicalDelete(props.cleanup.dryRun);
        } catch (Exception e) {
            log.warn("定时物理删除文件对象失败: {}", e.getMessage());
        }
    }

    @Scheduled(fixedDelayString = "${file.cleanup.scan-interval-ms:3600000}", initialDelay = 120000)
    public void scanOrphans() {
        if (!props.cleanup.enabled) {
            return;
        }
        try {
            cleanup.scanOrphans(null, props.cleanup.dryRun);
        } catch (Exception e) {
            log.warn("定时孤儿文件扫描失败: {}", e.getMessage());
        }
    }

    @Scheduled(fixedDelayString = "${file.cleanup.consistency-interval-ms:3600000}", initialDelay = 180000)
    public void checkConsistency() {
        if (!props.cleanup.enabled) {
            return;
        }
        try {
            cleanup.consistencyCheck(props.cleanup.dryRun);
        } catch (Exception e) {
            log.warn("定时一致性检查失败: {}", e.getMessage());
        }
    }
}
