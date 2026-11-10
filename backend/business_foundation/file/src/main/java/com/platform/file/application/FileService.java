package com.platform.file.application;

import com.platform.file.config.AppProperties;
import com.platform.file.domain.model.FileObject;
import com.platform.file.domain.model.FileRecord;
import com.platform.file.domain.model.RecordSearchCriteria;
import com.platform.file.domain.model.StorageProviderRow;
import com.platform.file.domain.repository.FileObjectRepository;
import com.platform.file.domain.repository.FileRecordRepository;
import com.platform.file.domain.repository.StorageProviderRepository;
import com.platform.file.domain.storage.PresignedDownload;
import com.platform.file.domain.storage.StorageProvider;
import com.platform.file.domain.storage.StorageType;
import com.platform.file.infrastructure.metrics.FileMetrics;
import com.platform.file.infrastructure.security.DownloadTokenService;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.Db;
import com.platform.file.shared.Ids;
import com.platform.file.shared.LogContext;
import com.platform.file.shared.PageQuery;
import com.platform.file.shared.StatusMachines;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class FileService {
    private static final Logger log = LoggerFactory.getLogger(FileService.class);

    private final FileRecordRepository records;
    private final FileObjectRepository objects;
    private final StorageProviderRepository providers;
    private final StorageProviderRegistry registry;
    private final DownloadTokenService tokens;
    private final AppProperties props;
    private final FileMetrics metrics;
    private final OperationLogService operationLog;
    private final Db db;

    public FileService(FileRecordRepository records, FileObjectRepository objects,
                       StorageProviderRepository providers, StorageProviderRegistry registry,
                       DownloadTokenService tokens, AppProperties props, FileMetrics metrics,
                       OperationLogService operationLog, Db db) {
        this.records = records;
        this.objects = objects;
        this.providers = providers;
        this.registry = registry;
        this.tokens = tokens;
        this.props = props;
        this.metrics = metrics;
        this.operationLog = operationLog;
        this.db = db;
    }

    // ───────────────────────── 查询 ─────────────────────────

    public Map<String, Object> search(Map<String, String> query, PageQuery page) {
        RecordSearchCriteria criteria = criteria(query);
        List<FileRecord> found = records.search(criteria, page.offset(), page.size());
        long total = records.count(criteria);
        return Db.page(found.stream().map(Views::record).toList(), total, page.page(), page.size());
    }

    public Map<String, Object> bySource(String sourceType, String sourceId, PageQuery page) {
        if (sourceType == null || sourceType.isBlank()) {
            throw ApiException.validation("source_type", "来源类型不能为空");
        }
        Map<String, String> query = new LinkedHashMap<>();
        query.put("source_type", sourceType);
        if (sourceId != null) {
            query.put("source_id", sourceId);
        }
        return search(query, page);
    }

    public Map<String, Object> byBusiness(String businessId, PageQuery page) {
        if (businessId == null || businessId.isBlank()) {
            throw ApiException.validation("business_id", "业务标识不能为空");
        }
        Map<String, String> query = new LinkedHashMap<>();
        query.put("business_id", businessId);
        return search(query, page);
    }

    public List<Map<String, Object>> batch(Collection<UUID> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }
        List<FileRecord> found = records.findByIds(ids);
        Map<UUID, FileObject> objectMap = new LinkedHashMap<>();
        objects.findByIds(found.stream()
                        .map(FileRecord::fileObjectId)
                        .filter(java.util.Objects::nonNull)
                        .distinct()
                        .toList())
                .forEach(o -> objectMap.put(o.id(), o));
        List<Map<String, Object>> out = new ArrayList<>();
        for (FileRecord record : found) {
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("file", Views.record(record));
            FileObject object = objectMap.get(record.fileObjectId());
            if (object != null) {
                item.put("object", Views.object(object));
            }
            out.add(item);
        }
        return out;
    }

    public Map<String, Object> detail(UUID fileId) {
        FileRecord record = requireRecord(fileId);
        FileObject object = objects.findById(record.fileObjectId()).orElse(null);
        StorageProviderRow provider = providers.findById(record.storageProviderId()).orElse(null);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("file", Views.record(record));
        out.put("object", Views.object(object));
        out.put("storage_provider", Views.providerRef(provider));
        return out;
    }

    public Map<String, Object> stats() {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("objects", objects.totals());
        out.put("providers", objects.statsByProvider());
        out.put("active_records", records.countActive());
        return out;
    }

    public List<Map<String, Object>> sourceStats() {
        return records.sourceStats();
    }

    // ───────────────────────── 删除与状态 ─────────────────────────

    public Map<String, Object> delete(UUID fileId, String operator) {
        FileRecord record = records.findById(fileId, true)
                .orElseThrow(() -> ApiException.notFound("文件记录不存在"));
        if (record.deletedAt() != null) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("file_id", fileId.toString());
            out.put("deleted", false);
            out.put("already_deleted", true);
            out.put("references", 0);
            out.put("physical_delete_scheduled", false);
            return out;
        }
        UUID objectId = record.fileObjectId();
        Instant deleteAfter = Instant.now().plusSeconds(Math.max(1, props.cleanup.deleteGraceMinutes) * 60);
        boolean[] scheduled = {false};
        long[] references = {0};
        db.inTx(() -> {
            records.softDelete(fileId);
            if (objectId != null) {
                references[0] = records.countActiveByObject(objectId);
                if (references[0] == 0) {
                    scheduled[0] = objects.markPendingDelete(objectId, deleteAfter) > 0;
                }
            }
        });
        LogContext.open(Map.of(LogContext.FILE_ID, fileId));
        LogContext.operation("DELETE_FILE");
        operationLog.success("DELETE_FILE", record.storageProviderId(), objectId, fileId, null, null,
                record.fileSize(), 0, Map.of("operator", operator == null ? "" : operator,
                        "references", references[0]));
        LogContext.clear();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("file_id", fileId.toString());
        out.put("deleted", true);
        out.put("already_deleted", false);
        out.put("references", references[0]);
        out.put("physical_delete_scheduled", scheduled[0]);
        if (scheduled[0]) {
            out.put("delete_after", deleteAfter.toString());
        }
        return out;
    }

    public Map<String, Object> batchDelete(Collection<UUID> ids, String operator) {
        List<Map<String, Object>> results = new ArrayList<>();
        int deleted = 0;
        int scheduled = 0;
        int failed = 0;
        for (UUID id : ids == null ? List.<UUID>of() : ids) {
            try {
                Map<String, Object> result = delete(id, operator);
                results.add(result);
                if (Boolean.TRUE.equals(result.get("deleted"))) {
                    deleted++;
                }
                if (Boolean.TRUE.equals(result.get("physical_delete_scheduled"))) {
                    scheduled++;
                }
            } catch (ApiException e) {
                failed++;
                Map<String, Object> failure = new LinkedHashMap<>();
                failure.put("file_id", id == null ? null : id.toString());
                failure.put("error", e.getMessage());
                results.add(failure);
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("deleted", deleted);
        out.put("physical_delete_scheduled", scheduled);
        out.put("failed", failed);
        out.put("results", results);
        return out;
    }

    public Map<String, Object> updateStatus(UUID fileId, String status) {
        if (status == null || status.isBlank()) {
            throw ApiException.validation("status", "状态不能为空");
        }
        String target = status.trim().toUpperCase(java.util.Locale.ROOT);
        FileRecord record = requireRecord(fileId);
        if (record.status().equals(target)) {
            return detail(fileId);
        }
        if ("DELETED".equals(target)) {
            return delete(fileId, null);
        }
        if (!"ACTIVE".equals(target) && !"QUARANTINED".equals(target)) {
            throw ApiException.validation("status", "仅支持 ACTIVE、QUARANTINED、DELETED");
        }
        StatusMachines.requireRecord(record.status(), target);
        records.updateStatus(fileId, target);
        operationLog.success("UPDATE_FILE_STATUS", record.storageProviderId(), record.fileObjectId(), fileId,
                null, null, record.fileSize(), 0, Map.of("from", record.status(), "to", target));
        return detail(fileId);
    }

    // ───────────────────────── 下载 ─────────────────────────

    public Map<String, Object> downloadUrl(UUID fileId, Long ttlSeconds) {
        FileRecord record = requireActiveRecord(fileId);
        FileObject object = objects.findById(record.fileObjectId())
                .orElseThrow(() -> ApiException.conflict("文件对象不存在或已删除"));
        StorageProviderRow row = providers.findById(record.storageProviderId())
                .orElseThrow(() -> ApiException.unavailable("存储提供者不存在"));
        if (!row.enabled()) {
            throw ApiException.conflict("存储提供者已禁用: " + row.code());
        }
        if (!row.allowDownload()) {
            throw ApiException.conflict("存储提供者不允许下载: " + row.code());
        }
        long ttl = normalizeTtl(ttlSeconds);
        String filename = record.displayName() == null ? record.originalFilename() : record.displayName();
        if (row.type() == StorageType.LOCAL) {
            String token = tokens.issue(fileId, ttl);
            String base = props.publicBaseUrl == null || props.publicBaseUrl.isBlank()
                    ? "" : props.publicBaseUrl.replaceAll("/+$", "");
            String url = base + "/api/v1/public/files/" + fileId + "/content?token="
                    + URLEncoder.encode(token, StandardCharsets.UTF_8);
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("file_id", fileId.toString());
            out.put("type", "TOKEN");
            out.put("method", "GET");
            out.put("url", url);
            out.put("token", token);
            out.put("expires_at", Instant.now().plusSeconds(ttl).toString());
            out.put("filename", filename);
            metrics.downloadRequested();
            return out;
        }
        StorageProvider provider = registry.get(row);
        if (!provider.capabilities().presignDownload()) {
            throw ApiException.conflict("存储提供者不支持预签名下载: " + row.code());
        }
        PresignedDownload download = provider.presignDownload(object.objectKey(), filename,
                Duration.ofSeconds(ttl));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("file_id", fileId.toString());
        out.put("type", "PRE_SIGNED_URL");
        out.put("method", "GET");
        out.put("url", download.url());
        out.put("expires_at", download.expiresAt().toString());
        out.put("filename", filename);
        metrics.downloadRequested();
        return out;
    }

    public DownloadStream openContent(UUID fileId, String token) {
        UUID tokenFileId = tokens.validate(token);
        if (!tokenFileId.equals(fileId)) {
            throw ApiException.unauthorized("下载令牌与文件不匹配");
        }
        FileRecord record = requireActiveRecord(fileId);
        FileObject object = objects.findById(record.fileObjectId())
                .orElseThrow(() -> ApiException.conflict("文件对象不存在或已删除"));
        StorageProviderRow row = providers.findById(record.storageProviderId())
                .orElseThrow(() -> ApiException.unavailable("存储提供者不存在"));
        if (!row.enabled() || !row.allowDownload()) {
            throw ApiException.conflict("存储提供者不允许下载");
        }
        StorageProvider provider = registry.get(row);
        try {
            InputStream stream = provider.open(object.objectKey());
            metrics.downloadRequested();
            return new DownloadStream(record, stream);
        } catch (Exception e) {
            log.warn("打开文件内容失败 fileId={}: {}", fileId, e.getMessage());
            throw ApiException.storage("读取文件内容失败");
        }
    }

    // ───────────────────────── 内部辅助 ─────────────────────────

    private FileRecord requireRecord(UUID fileId) {
        return records.findById(fileId, false)
                .orElseThrow(() -> ApiException.notFound("文件记录不存在"));
    }

    private FileRecord requireActiveRecord(UUID fileId) {
        FileRecord record = requireRecord(fileId);
        if (!"ACTIVE".equals(record.status())) {
            throw ApiException.conflict("文件当前状态不可下载: " + record.status());
        }
        return record;
    }

    private long normalizeTtl(Long ttlSeconds) {
        long ttl = ttlSeconds == null ? Math.max(1, props.download.urlTtlSeconds) : ttlSeconds;
        if (ttl < 1) {
            throw ApiException.validation("ttl_seconds", "下载有效期必须大于 0");
        }
        return Math.min(ttl, 7L * 24 * 3600);
    }

    private RecordSearchCriteria criteria(Map<String, String> query) {
        return new RecordSearchCriteria(
                value(query, "status"),
                value(query, "source_type"),
                value(query, "source_id"),
                value(query, "business_id"),
                Ids.parse(value(query, "storage_provider_id")),
                value(query, "creator"),
                Ids.parse(value(query, "tenant_id")),
                value(query, "mime_type"),
                value(query, "filename"),
                instant(value(query, "created_from"), "created_from"),
                instant(value(query, "created_to"), "created_to"),
                value(query, "sort"));
    }

    private static String value(Map<String, String> query, String key) {
        String value = query == null ? null : query.get(key);
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static Instant instant(String value, String field) {
        if (value == null) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (RuntimeException e) {
            throw ApiException.validation(field, "时间格式必须为 ISO-8601 UTC，例如 2026-01-01T00:00:00Z");
        }
    }

    public record DownloadStream(FileRecord record, InputStream stream) {
    }
}
