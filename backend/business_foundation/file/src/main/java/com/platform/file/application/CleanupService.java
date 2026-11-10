package com.platform.file.application;

import com.platform.file.config.AppProperties;
import com.platform.file.domain.model.CleanupTask;
import com.platform.file.domain.model.FileObject;
import com.platform.file.domain.model.FileRecord;
import com.platform.file.domain.model.StorageProviderRow;
import com.platform.file.domain.model.UploadSession;
import com.platform.file.domain.repository.CleanupTaskRepository;
import com.platform.file.domain.repository.FileObjectRepository;
import com.platform.file.domain.repository.FileRecordRepository;
import com.platform.file.domain.repository.StorageProviderRepository;
import com.platform.file.domain.repository.UploadSessionRepository;
import com.platform.file.domain.storage.ObjectMetadata;
import com.platform.file.domain.storage.ObjectPage;
import com.platform.file.domain.storage.StorageProvider;
import com.platform.file.infrastructure.metrics.FileMetrics;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.Ids;
import com.platform.file.shared.PageQuery;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * 文件清理与一致性运维。所有写操作都在任务锁内执行，支持 Dry Run。
 */
@Service
public class CleanupService {
    private static final Logger log = LoggerFactory.getLogger(CleanupService.class);

    private final StorageProviderRepository providers;
    private final StorageProviderRegistry registry;
    private final FileObjectRepository objects;
    private final FileRecordRepository records;
    private final UploadSessionRepository sessions;
    private final CleanupTaskRepository tasks;
    private final UploadService uploadService;
    private final JobLock locks;
    private final FileMetrics metrics;
    private final OperationLogService operationLog;
    private final AppProperties props;

    public CleanupService(StorageProviderRepository providers, StorageProviderRegistry registry,
                          FileObjectRepository objects, FileRecordRepository records,
                          UploadSessionRepository sessions, CleanupTaskRepository tasks,
                          UploadService uploadService, JobLock locks,
                          FileMetrics metrics, OperationLogService operationLog, AppProperties props) {
        this.providers = providers;
        this.registry = registry;
        this.objects = objects;
        this.records = records;
        this.sessions = sessions;
        this.tasks = tasks;
        this.uploadService = uploadService;
        this.locks = locks;
        this.metrics = metrics;
        this.operationLog = operationLog;
        this.props = props;
    }

    // ───────────────────────── 对外入口 ─────────────────────────

    public Map<String, Object> scanOrphans(UUID providerId, boolean dryRun) {
        return runTask("ORPHAN_SCAN", dryRun, providerId, "cleanup:orphan",
                () -> doOrphanScan(providerId, dryRun));
    }

    public Map<String, Object> physicalDelete(boolean dryRun) {
        return runTask("PHYSICAL_DELETE", dryRun, null, "cleanup:delete",
                () -> doPhysicalDelete(dryRun));
    }

    public Map<String, Object> consistencyCheck(boolean dryRun) {
        return runTask("CONSISTENCY_CHECK", dryRun, null, "cleanup:consistency",
                () -> doConsistency(dryRun));
    }

    public Map<String, Object> uploadExpiry() {
        return runTask("UPLOAD_EXPIRY", false, null, "cleanup:expiry", this::doUploadExpiry);
    }

    public Map<String, Object> manualCleanup(UUID providerId, boolean dryRun) {
        return runTask("MANUAL_CLEANUP", dryRun, providerId, "cleanup:manual", () -> {
            TaskResult expiry = doUploadExpiry();
            TaskResult deletion = doPhysicalDelete(dryRun);
            TaskResult orphans = doOrphanScan(providerId, dryRun);
            TaskResult merged = new TaskResult();
            merged.scanned = expiry.scanned + deletion.scanned + orphans.scanned;
            merged.deleted = expiry.deleted + deletion.deleted + orphans.deleted;
            merged.repaired = deletion.repaired + orphans.repaired;
            merged.failed = expiry.failed + deletion.failed + orphans.failed;
            merged.details.put("upload_expiry", expiry.details);
            merged.details.put("physical_delete", deletion.details);
            merged.details.put("orphan_scan", orphans.details);
            return merged;
        });
    }

    public Map<String, Object> tasks(String type, String status, PageQuery page) {
        List<CleanupTask> found = tasks.search(type, status, page.offset(), page.size());
        long total = tasks.count(type, status);
        List<Map<String, Object>> items = found.stream().map(this::view).toList();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("items", items);
        out.put("total", total);
        out.put("page", page.page());
        out.put("page_size", page.size());
        return out;
    }

    public Map<String, Object> task(UUID id) {
        return view(tasks.findById(id)
                .orElseThrow(() -> ApiException.notFound("清理任务不存在")));
    }

    // ───────────────────────── 上传过期 ─────────────────────────

    private TaskResult doUploadExpiry() {
        TaskResult result = new TaskResult();
        int expired = uploadService.expireDueSessions(props.cleanup.maxPerRun);
        result.scanned = expired;
        result.deleted = expired;
        result.details.put("expired_sessions", expired);
        return result;
    }

    // ───────────────────────── 物理删除 ─────────────────────────

    private TaskResult doPhysicalDelete(boolean dryRun) {
        TaskResult result = new TaskResult();
        Instant now = Instant.now();
        List<FileObject> due = objects.findDueForDeletion(now, props.cleanup.maxPerRun);
        List<String> skipped = new ArrayList<>();
        for (FileObject object : due) {
            result.scanned++;
            long references = records.countActiveByObject(object.id());
            if (references > 0) {
                result.repaired++;
                if (!dryRun) {
                    objects.activate(object.id(), object.fileSize(), object.mimeType(), object.etag());
                }
                skipped.add(object.id() + ": 仍被 " + references + " 条记录引用");
                continue;
            }
            StorageProviderRow row = providers.findById(object.storageProviderId()).orElse(null);
            if (row == null) {
                result.failed++;
                skipped.add(object.id() + ": 存储提供者不存在");
                continue;
            }
            if (!row.allowDelete()) {
                skipped.add(object.id() + ": 存储提供者不允许删除");
                continue;
            }
            if (dryRun) {
                result.deleted++;
                @SuppressWarnings("unchecked")
                List<String> planned = (List<String>) result.details
                        .computeIfAbsent("planned", key -> new ArrayList<String>());
                planned.add(object.objectKey());
                continue;
            }
            try {
                StorageProvider provider = registry.get(row);
                if (object.objectKey() != null) {
                    provider.delete(object.objectKey());
                }
                if (object.tempKey() != null) {
                    try {
                        provider.delete(object.tempKey());
                    } catch (Exception ignored) {
                        // 临时对象可能已被删除，忽略。
                    }
                }
                objects.markDeleted(object.id());
                result.deleted++;
                metrics.cleanupSucceeded();
                operationLog.success("PHYSICAL_DELETE", row.id(), object.id(), null, null,
                        object.objectKey(), object.fileSize(), 0,
                        Map.of("delete_attempts", object.deleteAttempts()));
            } catch (Exception e) {
                result.failed++;
                metrics.cleanupFailed();
                objects.recordDeleteFailure(object.id(), rootMessage(e));
                operationLog.failure("PHYSICAL_DELETE", row.id(), object.id(), null, null,
                        object.objectKey(), object.fileSize(), 0, Map.of(), rootMessage(e));
                log.warn("物理删除文件对象失败 objectId={}: {}", object.id(), e.getMessage());
            }
        }
        if (!skipped.isEmpty()) {
            result.details.put("skipped", skipped.size() > 100 ? skipped.subList(0, 100) : skipped);
        }
        return result;
    }

    // ───────────────────────── 孤儿扫描 ─────────────────────────

    private TaskResult doOrphanScan(UUID requestedProviderId, boolean dryRun) {
        TaskResult result = new TaskResult();
        List<StorageProviderRow> targets = new ArrayList<>();
        if (requestedProviderId != null) {
            targets.add(providers.findById(requestedProviderId)
                    .orElseThrow(() -> ApiException.notFound("存储提供者不存在")));
        } else {
            targets.addAll(providers.findAll(false));
        }
        Instant cutoff = Instant.now().minusSeconds(Math.max(1, props.cleanup.orphanSafetyMinutes) * 60);
        List<String> orphans = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        String prefix = normalizePrefix(props.storage.permanentPrefix);
        int totalOrphans = 0;
        outer:
        for (StorageProviderRow row : targets) {
            StorageProvider provider;
            try {
                provider = registry.get(row);
            } catch (Exception e) {
                result.failed++;
                failures.add(row.code() + ": " + rootMessage(e));
                continue;
            }
            String cursor = null;
            do {
                ObjectPage page;
                try {
                    page = provider.list(prefix, cursor, Math.max(1, props.cleanup.batchSize));
                } catch (Exception e) {
                    result.failed++;
                    failures.add(row.code() + ": " + rootMessage(e));
                    break;
                }
                for (ObjectMetadata item : page.items()) {
                    if (result.scanned >= props.cleanup.maxPerRun) {
                        break outer;
                    }
                    result.scanned++;
                    if (item.lastModified() != null && item.lastModified().isAfter(cutoff)) {
                        continue;
                    }
                    if (objects.findByKey(row.id(), item.key()).isPresent()) {
                        continue;
                    }
                    totalOrphans++;
                    if (orphans.size() < 100) {
                        orphans.add(item.key());
                    }
                    if (dryRun) {
                        result.deleted++;
                        continue;
                    }
                    try {
                        if (objects.findByKey(row.id(), item.key()).isEmpty()) {
                            provider.delete(item.key());
                            result.deleted++;
                            metrics.cleanupSucceeded();
                            operationLog.success("ORPHAN_DELETE", row.id(), null, null, null,
                                    item.key(), item.size(), 0, Map.of("dry_run", false));
                        }
                    } catch (Exception e) {
                        result.failed++;
                        failures.add(item.key() + ": " + rootMessage(e));
                        metrics.cleanupFailed();
                        operationLog.failure("ORPHAN_DELETE", row.id(), null, null, null,
                                item.key(), item.size(), 0, Map.of(), rootMessage(e));
                    }
                }
                cursor = page.nextCursor();
            } while (cursor != null);
        }
        metrics.setOrphanFiles(totalOrphans);
        result.details.put("orphan_count", totalOrphans);
        result.details.put("orphans", orphans);
        if (!failures.isEmpty()) {
            result.details.put("failures", failures.size() > 100 ? failures.subList(0, 100) : failures);
        }
        return result;
    }

    // ───────────────────────── 一致性检查 ─────────────────────────

    private TaskResult doConsistency(boolean dryRun) {
        TaskResult result = new TaskResult();
        int limit = props.cleanup.maxPerRun;
        Instant grace = Instant.now().plusSeconds(Math.max(1, props.cleanup.deleteGraceMinutes) * 60);
        List<String> repaired = new ArrayList<>();

        List<FileObject> orphanObjects = objects.findActiveWithoutRecords(limit);
        for (FileObject object : orphanObjects) {
            result.scanned++;
            result.repaired++;
            repaired.add("object_without_records:" + object.id());
            if (!dryRun) {
                objects.markPendingDelete(object.id(), grace);
            }
        }

        List<FileRecord> missingObjects = records.findActiveWithMissingObject(limit);
        for (FileRecord record : missingObjects) {
            result.scanned++;
            result.repaired++;
            repaired.add("record_missing_object:" + record.id());
            if (!dryRun) {
                records.updateStatus(record.id(), "QUARANTINED");
            }
        }

        for (FileObject object : objects.listByStatus("ACTIVE", limit)) {
            result.scanned++;
            StorageProviderRow row = providers.findById(object.storageProviderId()).orElse(null);
            if (row == null) {
                result.failed++;
                continue;
            }
            try {
                StorageProvider provider = registry.get(row);
                if (!provider.exists(object.objectKey())) {
                    result.repaired++;
                    repaired.add("missing_physical_object:" + object.id());
                    if (!dryRun) {
                        objects.markQuarantined(object.id(), "一致性检查：物理文件缺失");
                        records.quarantineByObject(object.id());
                    }
                }
            } catch (Exception e) {
                result.failed++;
                log.warn("一致性检查读取存储失败 objectId={}: {}", object.id(), e.getMessage());
            }
        }

        Instant staleBefore = Instant.now().minusSeconds(Math.max(1, props.upload.confirmTimeoutMinutes) * 120);
        for (FileObject object : objects.findStaleByStatus("MIGRATING", staleBefore, limit)) {
            result.scanned++;
            result.repaired++;
            repaired.add("stale_migrating:" + object.id());
            if (!dryRun) {
                objects.markFailed(object.id(), "一致性检查：迁移状态超时，已重置为可重试");
            }
        }
        for (FileRecord record : records.findStalePending(staleBefore, limit)) {
            result.scanned++;
            result.repaired++;
            repaired.add("stale_pending_record:" + record.id());
            if (!dryRun) {
                records.updateStatus(record.id(), "EXPIRED");
            }
        }
        for (UploadSession session : sessions.findStaleConfirming(staleBefore, limit)) {
            result.scanned++;
            result.repaired++;
            repaired.add("stale_confirming_session:" + session.id());
            if (!dryRun) {
                sessions.setFailed(session.id(), "一致性检查：确认状态超时，已重置为可重试");
            }
        }

        for (FileObject object : objects.findDeletedWithKey(limit)) {
            result.scanned++;
            StorageProviderRow row = providers.findById(object.storageProviderId()).orElse(null);
            if (row == null) {
                result.failed++;
                continue;
            }
            try {
                StorageProvider provider = registry.get(row);
                if (provider.exists(object.objectKey())) {
                    if (!dryRun) {
                        provider.delete(object.objectKey());
                    }
                    result.deleted++;
                    repaired.add("residual_deleted_object:" + object.id());
                }
            } catch (Exception e) {
                result.failed++;
                log.warn("清理已删除对象残留失败 objectId={}: {}", object.id(), e.getMessage());
            }
        }

        result.details.put("repaired_items", repaired.size() > 100 ? repaired.subList(0, 100) : repaired);
        result.details.put("dry_run_planned", result.repaired + result.deleted);
        return result;
    }

    // ───────────────────────── 任务包装 ─────────────────────────

    private Map<String, Object> runTask(String type, boolean dryRun, UUID providerId, String lockName,
                                        Work work) {
        if (!locks.acquire(lockName, props.cleanup.lockSeconds)) {
            CleanupTask skipped = new CleanupTask(Ids.uuidV7(), type, "SKIPPED", dryRun, providerId,
                    0, 0, 0, 0, Map.of("reason", "任务正在执行中，本次跳过"), null, null, null, null);
            tasks.insert(skipped);
            return view(skipped);
        }
        CleanupTask task = new CleanupTask(Ids.uuidV7(), type, "RUNNING", dryRun, providerId,
                0, 0, 0, 0, Map.of(), null, null, null, null);
        tasks.insert(task);
        try {
            TaskResult result = work.run();
            task = new CleanupTask(task.id(), type, "SUCCESS", dryRun, providerId, result.scanned,
                    result.deleted, result.repaired, result.failed, result.details, null,
                    task.startedAt(), Instant.now(), task.createdAt());
            tasks.finish(task.id(), "SUCCESS", result.scanned, result.deleted, result.repaired,
                    result.failed, result.details, null);
        } catch (Exception e) {
            String message = rootMessage(e);
            tasks.finish(task.id(), "FAILED", 0, 0, 0, 0, Map.of(), message);
            task = new CleanupTask(task.id(), type, "FAILED", dryRun, providerId, 0, 0, 0, 0,
                    Map.of(), message, task.startedAt(), Instant.now(), task.createdAt());
            log.error("清理任务执行失败 type={}", type, e);
        } finally {
            locks.release(lockName);
        }
        return view(tasks.findById(task.id()).orElse(task));
    }

    private Map<String, Object> view(CleanupTask task) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("task_id", task.id().toString());
        out.put("type", task.type());
        out.put("status", task.status());
        out.put("dry_run", task.dryRun());
        out.put("storage_provider_id", task.storageProviderId() == null ? null : task.storageProviderId().toString());
        out.put("scanned", task.scanned());
        out.put("deleted", task.deleted());
        out.put("repaired", task.repaired());
        out.put("failed", task.failed());
        out.put("details", task.details());
        out.put("error_message", task.errorMessage());
        out.put("started_at", task.startedAt() == null ? null : task.startedAt().toString());
        out.put("finished_at", task.finishedAt() == null ? null : task.finishedAt().toString());
        return out;
    }

    public Map<String, Object> summary() {
        Map<String, Object> out = new LinkedHashMap<>();
        List<CleanupTask> latest = tasks.search(null, null, 0, 10);
        out.put("recent_tasks", latest.stream().map(this::view).toList());
        out.put("task_total", tasks.count(null, null));
        out.put("file_objects", objects.totals());
        return out;
    }

    private static String normalizePrefix(String prefix) {
        String value = prefix == null ? "" : prefix.replace('\\', '/').trim();
        while (value.startsWith("/")) {
            value = value.substring(1);
        }
        if (!value.isEmpty() && !value.endsWith("/")) {
            value = value + "/";
        }
        return value;
    }

    private static String rootMessage(Throwable e) {
        Throwable cause = e;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        String message = cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage();
        return message.length() > 300 ? message.substring(0, 300) : message;
    }

    private interface Work {
        TaskResult run();
    }

    private static final class TaskResult {
        private int scanned;
        private int deleted;
        private int repaired;
        private int failed;
        private final Map<String, Object> details = new LinkedHashMap<>();
    }
}
