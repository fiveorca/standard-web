package com.platform.file.infrastructure.metrics;

import com.platform.file.shared.Db;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

@Component
public class FileMetrics {
    private static final Logger log = LoggerFactory.getLogger(FileMetrics.class);

    private final MeterRegistry registry;
    private final Db db;

    private final Counter uploadSuccess;
    private final Counter uploadFailure;
    private final Counter downloadCount;
    private final Counter dedupHit;
    private final Counter cleanupSuccess;
    private final Counter cleanupFailure;
    private final Counter storageConnectionFailure;
    private final Timer uploadTimer;
    private final Timer downloadTimer;

    private final Map<UUID, ProviderUsage> providerUsage = new ConcurrentHashMap<>();
    private final AtomicLong totalFiles = new AtomicLong();
    private final AtomicLong totalBytes = new AtomicLong();
    private final AtomicLong temporaryFiles = new AtomicLong();
    private final AtomicLong orphanFiles = new AtomicLong();

    public FileMetrics(MeterRegistry registry, Db db) {
        this.registry = registry;
        this.db = db;
        this.uploadSuccess = Counter.builder("file.upload.success").description("上传成功数量").register(registry);
        this.uploadFailure = Counter.builder("file.upload.failure").description("上传失败数量").register(registry);
        this.downloadCount = Counter.builder("file.download.count").description("下载数量").register(registry);
        this.dedupHit = Counter.builder("file.dedup.hit").description("内容去重命中次数").register(registry);
        this.cleanupSuccess = Counter.builder("file.cleanup.success").description("清理成功数量").register(registry);
        this.cleanupFailure = Counter.builder("file.cleanup.failure").description("清理失败数量").register(registry);
        this.storageConnectionFailure = Counter.builder("file.storage.connection.failure")
                .description("存储后端连接异常数量").register(registry);
        this.uploadTimer = Timer.builder("file.upload.duration").description("上传耗时").register(registry);
        this.downloadTimer = Timer.builder("file.download.duration").description("下载耗时").register(registry);

        Gauge.builder("file.count", totalFiles, AtomicLong::get).description("文件对象总数").register(registry);
        Gauge.builder("file.size.bytes", totalBytes, AtomicLong::get).description("文件总大小").register(registry);
        Gauge.builder("file.temporary.count", temporaryFiles, AtomicLong::get).description("临时文件数量").register(registry);
        Gauge.builder("file.orphan.count", orphanFiles, AtomicLong::get).description("最近扫描发现的孤儿文件数量").register(registry);
    }

    @PostConstruct
    public void init() {
        refresh();
    }

    @Scheduled(fixedDelayString = "${file.cleanup.expiry-interval-ms:60000}", initialDelay = 15000)
    public void refresh() {
        try {
            Map<String, Object> totals = db.find("""
                    SELECT count(*) FILTER (WHERE status = 'ACTIVE') AS files,
                           COALESCE(sum(file_size) FILTER (WHERE status = 'ACTIVE'), 0) AS bytes,
                           count(*) FILTER (WHERE status IN ('PENDING_UPLOAD', 'TEMP_UPLOADED', 'MIGRATING')) AS temp
                    FROM file_object
                    """, Map.of()).orElse(Map.of());
            totalFiles.set(longValue(totals.get("files")));
            totalBytes.set(longValue(totals.get("bytes")));
            temporaryFiles.set(longValue(totals.get("temp")));

            Map<UUID, ProviderUsage> current = new LinkedHashMap<>();
            db.list("""
                    SELECT storage_provider_id, count(*) AS files, COALESCE(sum(file_size), 0) AS bytes
                    FROM file_object
                    WHERE status = 'ACTIVE'
                    GROUP BY storage_provider_id
                    """, Map.of()).forEach(row -> {
                UUID id = UUID.fromString(String.valueOf(row.get("storage_provider_id")));
                current.computeIfAbsent(id, key -> new ProviderUsage()).update(
                        longValue(row.get("files")), longValue(row.get("bytes")));
            });
            current.forEach((id, usage) -> {
                providerUsage.put(id, usage);
                Gauge.builder("file.provider.usage.bytes", usage, ProviderUsage::bytes)
                        .tag("provider", id.toString())
                        .description("各存储提供者使用空间")
                        .register(registry);
                Gauge.builder("file.provider.file.count", usage, ProviderUsage::files)
                        .tag("provider", id.toString())
                        .description("各存储提供者文件数量")
                        .register(registry);
            });
        } catch (Exception e) {
            log.debug("refresh file metrics skipped: {}", e.getMessage());
        }
    }

    public void uploadSucceeded(long nanos) {
        uploadSuccess.increment();
        uploadTimer.record(nanos, java.util.concurrent.TimeUnit.NANOSECONDS);
    }

    public void uploadFailed() {
        uploadFailure.increment();
    }

    public void downloaded(long nanos) {
        downloadCount.increment();
        downloadTimer.record(nanos, java.util.concurrent.TimeUnit.NANOSECONDS);
    }

    public void downloadRequested() {
        downloadCount.increment();
    }

    public void dedupHit() {
        dedupHit.increment();
    }

    public void cleanupSucceeded() {
        cleanupSuccess.increment();
    }

    public void cleanupFailed() {
        cleanupFailure.increment();
    }

    public void connectionFailed() {
        storageConnectionFailure.increment();
    }

    public void setOrphanFiles(long value) {
        orphanFiles.set(value);
    }

    private static long longValue(Object value) {
        return value == null ? 0 : ((Number) value).longValue();
    }

    private static final class ProviderUsage {
        private final AtomicLong files = new AtomicLong();
        private final AtomicLong bytes = new AtomicLong();

        void update(long fileCount, long byteCount) {
            files.set(fileCount);
            bytes.set(byteCount);
        }

        long files() {
            return files.get();
        }

        long bytes() {
            return bytes.get();
        }
    }
}
