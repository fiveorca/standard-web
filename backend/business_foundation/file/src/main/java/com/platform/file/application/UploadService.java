package com.platform.file.application;

import com.platform.file.application.command.CreateUploadCommand;
import com.platform.file.config.AppProperties;
import com.platform.file.domain.model.FileObject;
import com.platform.file.domain.model.FileRecord;
import com.platform.file.domain.model.StorageProviderRow;
import com.platform.file.domain.model.UploadSession;
import com.platform.file.domain.repository.FileObjectRepository;
import com.platform.file.domain.repository.FileRecordRepository;
import com.platform.file.domain.repository.StorageProviderRepository;
import com.platform.file.domain.repository.UploadSessionRepository;
import com.platform.file.domain.storage.MultipartHandle;
import com.platform.file.domain.storage.MultipartPart;
import com.platform.file.domain.storage.ObjectMetadata;
import com.platform.file.domain.storage.PartAuthorization;
import com.platform.file.domain.storage.PresignedUpload;
import com.platform.file.domain.storage.StorageProvider;
import com.platform.file.infrastructure.metrics.FileMetrics;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.BoundedInputStream;
import com.platform.file.shared.ContentTypes;
import com.platform.file.shared.Db;
import com.platform.file.shared.Hash;
import com.platform.file.shared.Ids;
import com.platform.file.shared.Json;
import com.platform.file.shared.LogContext;
import com.platform.file.shared.Names;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.DigestInputStream;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

@Service
public class UploadService {
    private static final Logger log = LoggerFactory.getLogger(UploadService.class);

    private final StorageProviderRepository providers;
    private final StorageProviderRegistry registry;
    private final UploadSessionRepository sessions;
    private final FileObjectRepository objects;
    private final FileRecordRepository records;
    private final AppProperties props;
    private final FileMetrics metrics;
    private final OperationLogService operationLog;
    private final Db db;

    public UploadService(StorageProviderRepository providers, StorageProviderRegistry registry,
                         UploadSessionRepository sessions, FileObjectRepository objects,
                         FileRecordRepository records, AppProperties props, FileMetrics metrics,
                         OperationLogService operationLog, Db db) {
        this.providers = providers;
        this.registry = registry;
        this.sessions = sessions;
        this.objects = objects;
        this.records = records;
        this.props = props;
        this.metrics = metrics;
        this.operationLog = operationLog;
        this.db = db;
    }

    // ───────────────────────── 创建上传任务 ─────────────────────────

    public Map<String, Object> createServerUpload(CreateUploadCommand command) {
        return create(command, "SERVER");
    }

    public Map<String, Object> createMultipartUpload(CreateUploadCommand command) {
        return create(command, "MULTIPART");
    }

    public Map<String, Object> createDirectUpload(CreateUploadCommand command, boolean multipart) {
        return create(command, multipart ? "DIRECT_MULTIPART" : "DIRECT");
    }

    private Map<String, Object> create(CreateUploadCommand command, String mode) {
        validateCreate(command);
        if (command.idempotencyKey() != null && !command.idempotencyKey().isBlank()) {
            UploadSession existing = sessions.findByIdempotencyKey(command.idempotencyKey().trim()).orElse(null);
            if (existing != null) {
                return detail(existing.id());
            }
        }
        StorageProviderRow row = providerRow(command.storageProviderId(), true);
        StorageProvider provider = registry.get(row);
        if (mode.startsWith("DIRECT") && !provider.capabilities().presignUpload()) {
            throw ApiException.validation("mode",
                    "存储提供者 " + row.code() + " 不支持客户端直传授权，请使用服务端上传");
        }

        UUID uploadId = Ids.uuidV7();
        UUID fileId = Ids.uuidV7();
        UUID objectId = Ids.uuidV7();
        String filename = Names.sanitize(command.filename());
        String extension = Names.extension(filename);
        String displayName = Names.displayName(
                command.displayName() == null || command.displayName().isBlank() ? filename : command.displayName(),
                filename);
        String mime = ContentTypes.validate(filename, command.contentType(), null, props.security);
        long declaredSize = command.size() == null ? 0 : command.size();

        String tempKey = normalizePrefix(props.storage.tempPrefix) + uploadId + "/" + randomName(extension);
        ZonedDateTime now = ZonedDateTime.now(ZoneOffset.UTC);
        String permanentKey = normalizePrefix(props.storage.permanentPrefix)
                + String.format(Locale.ROOT, "%04d/%02d/", now.getYear(), now.getMonthValue())
                + objectId + "/" + randomName(extension);

        Instant expiresAt = Instant.now().plusSeconds(Math.max(60, props.upload.expirySeconds));
        String idempotencyKey = command.idempotencyKey() == null || command.idempotencyKey().isBlank()
                ? null : command.idempotencyKey().trim();
        Map<String, Object> metadata = command.metadata() == null ? Map.of() : command.metadata();

        Object plan = mode.equals("MULTIPART") || mode.equals("DIRECT_MULTIPART")
                ? multipartPlan(command.size(), command.partSize()) : null;

        db.inTx(() -> {
            objects.insert(new FileObject(objectId, row.id(), permanentKey, tempKey, null, 0,
                    mime, extension, null, "PENDING_UPLOAD", null, 0, null, null,
                    metadata, null, null, null));
            records.insert(new FileRecord(fileId, objectId, row.id(), filename, displayName,
                    0, mime, extension, command.sourceType().trim(), blankToNull(command.sourceId()),
                    blankToNull(command.businessId()), blankToNull(command.creator()), command.tenantId(),
                    "PENDING_UPLOAD", null, metadata, null, null, null));
            sessions.insert(new UploadSession(uploadId, fileId, objectId, row.id(), mode, "CREATED",
                    permanentKey, tempKey, null, command.size(), 0, null,
                    plan == null ? null : ((Plan) plan).partsTotal(), 0, idempotencyKey, expiresAt,
                    null, null, null, metadata, null, null));
        });

        LogContext.open(Map.of(LogContext.UPLOAD_ID, uploadId, LogContext.FILE_ID, fileId,
                LogContext.OBJECT_ID, objectId, LogContext.PROVIDER_ID, row.id()));
        LogContext.operation("CREATE_UPLOAD");
        operationLog.success("CREATE_UPLOAD", row.id(), objectId, fileId, uploadId, null, null, 0,
                Map.of("mode", mode, "filename", filename));
        try {
            String multipartId = null;
            if (plan != null) {
                Plan multipartPlan = (Plan) plan;
                MultipartHandle handle = provider.createMultipart(tempKey, mime, Map.of());
                sessions.markMultipart(uploadId, handle.uploadId(), multipartPlan.partsTotal());
                multipartId = handle.uploadId();
            }
            if (mode.startsWith("DIRECT")) {
                Map<String, Object> authorization = mode.equals("DIRECT")
                        ? singleAuthorization(provider, tempKey, mime, command.size(), expiresAt)
                        : multipartAuthorization(provider, tempKey, multipartId,
                                ((Plan) plan).partsTotal(), expiresAt);
                Map<String, Object> out = detail(uploadId);
                out.put("authorization", authorization);
                return out;
            }
        } catch (RuntimeException e) {
            sessions.setFailed(uploadId, rootMessage(e));
            objects.markFailed(objectId, rootMessage(e));
            throw e instanceof ApiException api ? api : ApiException.storage(rootMessage(e));
        } finally {
            LogContext.clear();
        }
        return detail(uploadId);
    }

    // ───────────────────────── 服务端上传 ─────────────────────────

    public Map<String, Object> uploadContent(UUID uploadId, InputStream raw, long contentLength,
                                             String declaredContentType) {
        UploadSession session = requireSession(uploadId);
        if (!"SERVER".equals(session.mode())) {
            throw ApiException.conflict("当前上传任务不是服务端上传模式: " + session.mode());
        }
        ensureUploadable(session);
        long max = props.security.maxFileSize;
        if (session.expectedSize() != null) {
            max = Math.min(max, Math.max(1, session.expectedSize() + 1));
        }
        if (contentLength > 0 && contentLength > max) {
            throw ApiException.payloadTooLarge("文件超过允许的最大大小 " + max + " 字节");
        }

        LogContext.open(Map.of(LogContext.UPLOAD_ID, session.id(), LogContext.FILE_ID, session.fileId(),
                LogContext.OBJECT_ID, session.fileObjectId(), LogContext.PROVIDER_ID, session.storageProviderId()));
        LogContext.operation("UPLOAD_CONTENT");
        Path work = null;
        try {
            Path workDir = Path.of(props.storage.uploadWorkDir).toAbsolutePath();
            Files.createDirectories(workDir);
            work = Files.createTempFile(workDir, "upload-", ".tmp");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long size;
            try (InputStream bounded = new BoundedInputStream(raw, max);
                 DigestInputStream digesting = new DigestInputStream(bounded, digest);
                 OutputStream out = Files.newOutputStream(work)) {
                size = digesting.transferTo(out);
            }
            String sha = Hash.hex(digest.digest());

            if (session.expectedSize() != null && size != session.expectedSize()) {
                abortForFailure(session, "上传大小与声明不一致: 声明 " + session.expectedSize() + "，实际 " + size);
                throw ApiException.validation("size", "上传大小与声明不一致");
            }
            FileRecord record = records.findById(session.fileId(), true)
                    .orElseThrow(() -> ApiException.notFound("文件记录不存在"));
            byte[] head = readHead(work);
            String declared = declaredContentType != null && !declaredContentType.isBlank()
                    ? declaredContentType : record.mimeType();
            String mime = ContentTypes.validate(record.originalFilename(), declared, head, props.security);

            StorageProviderRow row = providerRow(session.storageProviderId(), true);
            StorageProvider provider = registry.get(row);
            ObjectMetadata stored;
            try (InputStream in = Files.newInputStream(work)) {
                stored = provider.put(session.tempKey(), in, size, mime, uploadMetadata(session));
            }
            sessions.markUploaded(session.id(), size, sha);
            objects.markTempUploaded(session.fileObjectId(), size, mime, stored.etag());
            records.updateUploadMeta(session.fileId(), size, mime, sha);
            return detail(session.id());
        } catch (ApiException e) {
            metrics.uploadFailed();
            operationLog.failure("UPLOAD_CONTENT", session.storageProviderId(), session.fileObjectId(),
                    session.fileId(), session.id(), null, null, 0, Map.of(), e.getMessage());
            throw e;
        } catch (Exception e) {
            metrics.uploadFailed();
            sessions.setFailed(session.id(), rootMessage(e));
            operationLog.failure("UPLOAD_CONTENT", session.storageProviderId(), session.fileObjectId(),
                    session.fileId(), session.id(), null, null, 0, Map.of(), rootMessage(e));
            throw ApiException.storage("文件上传失败: " + rootMessage(e));
        } finally {
            if (work != null) {
                try {
                    Files.deleteIfExists(work);
                } catch (IOException ignored) {
                    // 临时工作文件删除失败不影响业务结果。
                }
            }
            LogContext.clear();
        }
    }

    public Map<String, Object> uploadPart(UUID uploadId, int partNumber, InputStream raw, long size) {
        UploadSession session = requireSession(uploadId);
        if (!"MULTIPART".equals(session.mode())) {
            throw ApiException.conflict("当前上传任务不是服务端分片上传模式: " + session.mode());
        }
        ensureUploadable(session);
        if (session.multipartId() == null) {
            throw ApiException.conflict("分片上传任务尚未初始化");
        }
        int partsTotal = session.partsTotal() == null ? 0 : session.partsTotal();
        if (partNumber < 1 || partNumber > partsTotal) {
            throw ApiException.validation("part_number", "分片编号必须在 1-" + partsTotal + " 之间");
        }
        if (size < 0) {
            throw ApiException.validation("size", "必须提供分片大小");
        }
        if (size > props.upload.maxPartSize) {
            throw ApiException.payloadTooLarge("分片大小超过限制 " + props.upload.maxPartSize + " 字节");
        }
        if (partNumber < partsTotal && size < props.upload.minPartSize) {
            throw ApiException.validation("size", "除最后一片外，分片大小不能小于 " + props.upload.minPartSize + " 字节");
        }
        LogContext.open(Map.of(LogContext.UPLOAD_ID, session.id(), LogContext.FILE_ID, session.fileId(),
                LogContext.OBJECT_ID, session.fileObjectId(), LogContext.PROVIDER_ID, session.storageProviderId()));
        LogContext.operation("UPLOAD_PART");
        try {
            StorageProviderRow row = providerRow(session.storageProviderId(), true);
            StorageProvider provider = registry.get(row);
            MultipartPart part = provider.uploadPart(session.tempKey(), session.multipartId(),
                    partNumber, raw, size);
            sessions.upsertPart(session.id(), partNumber, size, part.etag(), null);
            refreshPartAggregates(session.id());
            return detail(session.id());
        } catch (ApiException e) {
            metrics.uploadFailed();
            throw e;
        } catch (Exception e) {
            metrics.uploadFailed();
            operationLog.failure("UPLOAD_PART", session.storageProviderId(), session.fileObjectId(),
                    session.fileId(), session.id(), null, size, 0,
                    Map.of("part_number", partNumber), rootMessage(e));
            throw ApiException.storage("分片上传失败: " + rootMessage(e));
        } finally {
            LogContext.clear();
        }
    }

    public Map<String, Object> completeMultipart(UUID uploadId) {
        UploadSession session = requireSession(uploadId);
        if (!"MULTIPART".equals(session.mode())) {
            throw ApiException.conflict("当前上传任务不是服务端分片上传模式: " + session.mode());
        }
        if ("UPLOADED".equals(session.status()) || "CONFIRMED".equals(session.status())) {
            return detail(uploadId);
        }
        ensureUploadable(session);
        int partsTotal = session.partsTotal() == null ? 0 : session.partsTotal();
        List<MultipartPart> parts = sessions.listParts(uploadId);
        if (parts.size() != partsTotal) {
            throw ApiException.conflict("分片未全部上传完成: 已上传 " + parts.size() + "/" + partsTotal);
        }
        for (int i = 0; i < parts.size(); i++) {
            if (parts.get(i).partNumber() != i + 1) {
                throw ApiException.conflict("分片编号不连续，缺少第 " + (i + 1) + " 片");
            }
        }
        LogContext.open(Map.of(LogContext.UPLOAD_ID, session.id(), LogContext.FILE_ID, session.fileId(),
                LogContext.OBJECT_ID, session.fileObjectId(), LogContext.PROVIDER_ID, session.storageProviderId()));
        LogContext.operation("COMPLETE_MULTIPART");
        try {
            StorageProviderRow row = providerRow(session.storageProviderId(), true);
            StorageProvider provider = registry.get(row);
            MultipartPart merged = provider.completeMultipart(session.tempKey(), session.multipartId(), parts);
            ObjectMetadata metadata = provider.stat(session.tempKey());
            long size = metadata.size() > 0 ? metadata.size() : merged.size();
            String sha;
            try (InputStream in = provider.open(session.tempKey())) {
                sha = Hash.sha256(in);
            }
            FileRecord record = records.findById(session.fileId(), true).orElseThrow();
            String mime = record.mimeType() == null ? ContentTypes.guess(record.originalFilename()) : record.mimeType();
            sessions.markUploaded(session.id(), size, sha);
            objects.markTempUploaded(session.fileObjectId(), size, mime, metadata.etag());
            records.updateUploadMeta(session.fileId(), size, mime, sha);
            operationLog.success("COMPLETE_MULTIPART", session.storageProviderId(), session.fileObjectId(),
                    session.fileId(), session.id(), null, size, 0, Map.of("parts", partsTotal));
            return detail(uploadId);
        } catch (ApiException e) {
            metrics.uploadFailed();
            throw e;
        } catch (Exception e) {
            metrics.uploadFailed();
            sessions.setFailed(uploadId, rootMessage(e));
            operationLog.failure("COMPLETE_MULTIPART", session.storageProviderId(), session.fileObjectId(),
                    session.fileId(), session.id(), null, null, 0, Map.of(), rootMessage(e));
            throw ApiException.storage("分片合并失败: " + rootMessage(e));
        } finally {
            LogContext.clear();
        }
    }

    // ───────────────────────── 客户端直传 ─────────────────────────

    public Map<String, Object> authorizeParts(UUID uploadId, List<Integer> partNumbers) {
        UploadSession session = requireSession(uploadId);
        if (!"DIRECT_MULTIPART".equals(session.mode())) {
            throw ApiException.conflict("当前上传任务不是分片直传模式");
        }
        ensureUploadable(session);
        if (session.multipartId() == null) {
            throw ApiException.conflict("分片上传任务尚未初始化");
        }
        int partsTotal = session.partsTotal() == null ? 0 : session.partsTotal();
        StorageProviderRow row = providerRow(session.storageProviderId(), true);
        StorageProvider provider = registry.get(row);
        Duration ttl = Duration.ofSeconds(Math.max(60, props.upload.expirySeconds));
        List<Map<String, Object>> result = new ArrayList<>();
        for (Integer number : partNumbers == null ? List.<Integer>of() : partNumbers) {
            if (number == null || number < 1 || number > partsTotal) {
                throw ApiException.validation("part_numbers", "分片编号必须在 1-" + partsTotal + " 之间");
            }
            PartAuthorization authorization = provider.presignPart(session.tempKey(), session.multipartId(),
                    number, ttl);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("part_number", number);
            item.put("url", authorization.url());
            item.put("method", authorization.method());
            item.put("headers", authorization.headers());
            item.put("expires_at", authorization.expiresAt().toString());
            result.add(item);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("upload_id", uploadId.toString());
        out.put("parts", result);
        return out;
    }

    public Map<String, Object> completeDirect(UUID uploadId, List<MultipartPart> parts, String providedSha) {
        UploadSession session = requireSession(uploadId);
        if (!"DIRECT".equals(session.mode()) && !"DIRECT_MULTIPART".equals(session.mode())) {
            throw ApiException.conflict("当前上传任务不是客户端直传模式: " + session.mode());
        }
        if ("UPLOADED".equals(session.status()) || "CONFIRMED".equals(session.status())) {
            return detail(uploadId);
        }
        ensureUploadable(session);
        LogContext.open(Map.of(LogContext.UPLOAD_ID, session.id(), LogContext.FILE_ID, session.fileId(),
                LogContext.OBJECT_ID, session.fileObjectId(), LogContext.PROVIDER_ID, session.storageProviderId()));
        LogContext.operation("COMPLETE_DIRECT_UPLOAD");
        try {
            StorageProviderRow row = providerRow(session.storageProviderId(), true);
            StorageProvider provider = registry.get(row);
            long size;
            if ("DIRECT_MULTIPART".equals(session.mode())) {
                int partsTotal = session.partsTotal() == null ? 0 : session.partsTotal();
                List<MultipartPart> completed = parts == null ? List.of() : parts;
                if (completed.size() != partsTotal) {
                    throw ApiException.conflict("分片直传完成时必须提交全部 " + partsTotal + " 个分片及 ETag");
                }
                List<MultipartPart> ordered = new ArrayList<>(completed);
                ordered.sort((a, b) -> Integer.compare(a.partNumber(), b.partNumber()));
                for (int i = 0; i < ordered.size(); i++) {
                    if (ordered.get(i).partNumber() != i + 1) {
                        throw ApiException.conflict("分片编号不连续，缺少第 " + (i + 1) + " 片");
                    }
                    if (ordered.get(i).etag() == null || ordered.get(i).etag().isBlank()) {
                        throw ApiException.validation("parts", "第 " + ordered.get(i).partNumber() + " 片缺少 ETag");
                    }
                    sessions.upsertPart(uploadId, ordered.get(i).partNumber(), ordered.get(i).size(),
                            ordered.get(i).etag(), null);
                }
                MultipartPart merged = provider.completeMultipart(session.tempKey(),
                        session.multipartId(), ordered);
                size = merged.size() > 0 ? merged.size() : provider.stat(session.tempKey()).size();
            } else {
                if (!provider.exists(session.tempKey())) {
                    throw ApiException.conflict("对象存储中尚未检测到上传对象，请确认客户端已上传完成");
                }
                size = provider.stat(session.tempKey()).size();
            }
            String sha;
            try (InputStream in = provider.open(session.tempKey())) {
                sha = Hash.sha256(in);
            }
            if (providedSha != null && !providedSha.isBlank() && !Hash.equalsHash(providedSha, sha)) {
                abortForFailure(session, "客户端声明的 SHA-256 与服务端计算结果不一致");
                throw ApiException.validation("sha256", "客户端声明的 SHA-256 与服务端计算结果不一致");
            }
            if (session.expectedSize() != null && size != session.expectedSize()) {
                abortForFailure(session, "上传对象大小与声明不一致");
                throw ApiException.validation("size", "上传对象大小与声明不一致");
            }
            FileRecord record = records.findById(session.fileId(), true).orElseThrow();
            String mime = record.mimeType() == null ? ContentTypes.guess(record.originalFilename()) : record.mimeType();
            sessions.markUploaded(session.id(), size, sha);
            objects.markTempUploaded(session.fileObjectId(), size, mime, null);
            records.updateUploadMeta(session.fileId(), size, mime, sha);
            return detail(uploadId);
        } catch (ApiException e) {
            metrics.uploadFailed();
            throw e;
        } catch (Exception e) {
            metrics.uploadFailed();
            sessions.setFailed(uploadId, rootMessage(e));
            operationLog.failure("COMPLETE_DIRECT_UPLOAD", session.storageProviderId(), session.fileObjectId(),
                    session.fileId(), session.id(), null, null, 0, Map.of(), rootMessage(e));
            throw ApiException.storage("直传完成确认失败: " + rootMessage(e));
        } finally {
            LogContext.clear();
        }
    }

    // ───────────────────────── 确认、去重与迁移 ─────────────────────────

    public Map<String, Object> confirm(UUID uploadId, String providedSha) {
        UploadSession session = requireSession(uploadId);
        if ("CONFIRMED".equals(session.status())) {
            return detail(uploadId);
        }
        if ("CANCELLED".equals(session.status()) || "EXPIRED".equals(session.status())) {
            throw ApiException.expired("上传任务已取消或过期，无法确认");
        }
        if (!"UPLOADED".equals(session.status()) && !"FAILED".equals(session.status())
                && !"CONFIRMING".equals(session.status())) {
            throw ApiException.conflict("上传尚未完成，当前状态: " + session.status());
        }
        if (session.expiresAt() != null && session.expiresAt().isBefore(Instant.now())) {
            expireSession(session);
            metrics.uploadFailed();
            throw ApiException.expired("上传任务已过期");
        }
        int changed = sessions.setConfirming(uploadId);
        if (changed == 0) {
            UploadSession current = requireSession(uploadId);
            if ("CONFIRMED".equals(current.status())) {
                return detail(uploadId);
            }
            if (!"CONFIRMING".equals(current.status())) {
                throw ApiException.conflict("上传任务状态已变更，当前状态: " + current.status());
            }
            session = current;
        }

        LogContext.open(Map.of(LogContext.UPLOAD_ID, session.id(), LogContext.FILE_ID, session.fileId(),
                LogContext.OBJECT_ID, session.fileObjectId(), LogContext.PROVIDER_ID, session.storageProviderId()));
        LogContext.operation("CONFIRM_UPLOAD");
        long start = System.nanoTime();
        try {
            Map<String, Object> result = doConfirm(session, providedSha, start);
            return result;
        } catch (ApiException e) {
            metrics.uploadFailed();
            throw e;
        } catch (Exception e) {
            metrics.uploadFailed();
            sessions.setFailed(uploadId, rootMessage(e));
            operationLog.failure("CONFIRM_UPLOAD", session.storageProviderId(), session.fileObjectId(),
                    session.fileId(), session.id(), null, null, elapsedMs(start), Map.of(), rootMessage(e));
            throw ApiException.storage("确认上传失败: " + rootMessage(e));
        } finally {
            LogContext.clear();
        }
    }

    private Map<String, Object> doConfirm(UploadSession session, String providedSha, long start) {
        StorageProviderRow row = providerRow(session.storageProviderId(), false);
        StorageProvider provider = registry.get(row);
        FileObject own = objects.findById(session.fileObjectId())
                .orElseThrow(() -> ApiException.notFound("文件对象不存在"));

        boolean tempExists;
        boolean permanentExists;
        try {
            tempExists = provider.exists(session.tempKey());
            permanentExists = provider.exists(own.objectKey());
        } catch (Exception e) {
            throw ApiException.storage("检查存储对象失败: " + rootMessage(e));
        }
        if (!tempExists && !permanentExists) {
            sessions.setFailed(session.id(), "临时文件不存在，无法确认");
            objects.markFailed(own.id(), "临时文件不存在");
            throw ApiException.conflict("临时文件不存在，无法确认上传");
        }

        String hashKey = tempExists ? session.tempKey() : own.objectKey();
        ObjectMetadata metadata;
        String actualSha;
        try {
            metadata = provider.stat(hashKey);
            try (InputStream in = provider.open(hashKey)) {
                actualSha = Hash.sha256(in);
            }
        } catch (Exception e) {
            throw ApiException.storage("读取待确认对象失败: " + rootMessage(e));
        }
        long size = metadata.size();
        if (providedSha != null && !providedSha.isBlank() && !Hash.equalsHash(providedSha, actualSha)) {
            abortForFailure(session, "客户端声明的 SHA-256 与服务端计算结果不一致");
            throw ApiException.validation("sha256", "客户端声明的 SHA-256 与服务端计算结果不一致");
        }
        if (session.expectedSize() != null && size != session.expectedSize()) {
            abortForFailure(session, "文件大小与声明不一致");
            throw ApiException.validation("size", "文件大小与声明不一致");
        }

        FileRecord record = records.findById(session.fileId(), true)
                .orElseThrow(() -> ApiException.notFound("文件记录不存在"));
        String declaredMime = record.mimeType() == null ? ContentTypes.guess(record.originalFilename())
                : record.mimeType();
        String mime;
        try (InputStream in = provider.open(hashKey)) {
            byte[] head = in.readNBytes(16);
            mime = ContentTypes.validate(record.originalFilename(), declaredMime, head, props.security);
        } catch (ApiException e) {
            abortForFailure(session, e.getMessage());
            throw e;
        } catch (Exception e) {
            mime = declaredMime == null ? "application/octet-stream" : declaredMime;
        }

        FileObject reusable = objects.findReusableByHash(session.storageProviderId(), actualSha).orElse(null);
        if (reusable != null && !reusable.id().equals(own.id())
                && ("ACTIVE".equals(reusable.status()) || "PENDING_DELETE".equals(reusable.status()))) {
            return reuseExisting(session, own, reusable, size, mime, actualSha, provider, start);
        }

        int claimed;
        try {
            claimed = objects.claimHash(own.id(), actualSha, mime, size, metadata.etag());
        } catch (DuplicateKeyException e) {
            FileObject other = objects.findReusableByHash(session.storageProviderId(), actualSha).orElse(null);
            if (other != null && !other.id().equals(own.id())
                    && ("ACTIVE".equals(other.status()) || "PENDING_DELETE".equals(other.status()))) {
                return reuseExisting(session, own, other, size, mime, actualSha, provider, start);
            }
            sessions.setFailed(session.id(), "相同内容正在被其他上传任务处理，请稍后重试");
            throw ApiException.conflict("相同内容正在被其他上传任务处理，请稍后重试");
        }
        if (claimed == 0) {
            FileObject current = objects.findById(own.id()).orElseThrow();
            if (current.sha256() == null || !Hash.equalsHash(current.sha256(), actualSha)) {
                FileObject other = objects.findReusableByHash(session.storageProviderId(), actualSha).orElse(null);
                if (other != null && !other.id().equals(own.id()) && "ACTIVE".equals(other.status())) {
                    return reuseExisting(session, own, other, size, mime, actualSha, provider, start);
                }
                sessions.setFailed(session.id(), "文件对象状态不允许确认");
                throw ApiException.conflict("文件对象状态已变更，无法确认，请重试");
            }
        }

        if (!permanentExists) {
            try {
                provider.copy(session.tempKey(), own.objectKey());
            } catch (Exception e) {
                String message = "迁移到永久存储失败: " + rootMessage(e);
                objects.markFailed(own.id(), message);
                sessions.setFailed(session.id(), message);
                operationLog.failure("MIGRATE_OBJECT", session.storageProviderId(), own.id(), session.fileId(),
                        session.id(), own.objectKey(), size, elapsedMs(start), Map.of(), message);
                throw ApiException.storage(message + "（临时文件已保留，可重试确认）");
            }
        }
        ObjectMetadata stored;
        try {
            stored = provider.stat(own.objectKey());
        } catch (Exception e) {
            String message = "校验永久对象失败: " + rootMessage(e);
            objects.markFailed(own.id(), message);
            sessions.setFailed(session.id(), message);
            throw ApiException.storage(message + "（可重试确认）");
        }
        if (stored.size() != size) {
            String message = "永久对象大小校验失败: 期望 " + size + "，实际 " + stored.size();
            objects.markFailed(own.id(), message);
            sessions.setFailed(session.id(), message);
            throw ApiException.storage(message);
        }
        String etag = stored.etag() == null ? metadata.etag() : stored.etag();
        String finalMime = mime;
        db.inTx(() -> {
            objects.activate(own.id(), size, finalMime, etag);
            records.activate(session.fileId(), own.id(), size, finalMime, actualSha);
            sessions.setConfirmed(session.id());
        });
        cleanupTemp(session, provider);
        sessions.deleteParts(session.id());
        metrics.uploadSucceeded(System.nanoTime() - start);
        operationLog.success("CONFIRM_UPLOAD", session.storageProviderId(), own.id(), session.fileId(),
                session.id(), own.objectKey(), size, elapsedMs(start),
                Map.of("sha256", actualSha, "deduplicated", false));
        return detail(session.id());
    }

    private Map<String, Object> reuseExisting(UploadSession session, FileObject own, FileObject reusable,
                                              long size, String mime, String sha, StorageProvider provider,
                                              long start) {
        if ("PENDING_DELETE".equals(reusable.status())) {
            objects.activate(reusable.id(), Math.max(reusable.fileSize(), size),
                    reusable.mimeType() == null ? mime : reusable.mimeType(), reusable.etag());
        }
        if (!reusable.id().equals(own.id())) {
            db.inTx(() -> {
                records.activate(session.fileId(), reusable.id(), size, mime, sha);
                objects.markDeleted(own.id());
                sessions.setConfirmed(session.id());
            });
        } else {
            db.inTx(() -> {
                records.activate(session.fileId(), reusable.id(), size, mime, sha);
                sessions.setConfirmed(session.id());
            });
        }
        cleanupTemp(session, provider);
        sessions.deleteParts(session.id());
        metrics.dedupHit();
        metrics.uploadSucceeded(System.nanoTime() - start);
        operationLog.success("CONFIRM_UPLOAD", session.storageProviderId(), reusable.id(), session.fileId(),
                session.id(), reusable.objectKey(), size, elapsedMs(start),
                Map.of("sha256", sha, "deduplicated", true));
        return detail(session.id());
    }

    // ───────────────────────── 查询与取消 ─────────────────────────

    public Map<String, Object> detail(UUID uploadId) {
        UploadSession session = requireSession(uploadId);
        FileRecord record = records.findById(session.fileId(), true).orElse(null);
        FileObject object = objects.findById(session.fileObjectId()).orElse(null);
        Map<String, Object> out = Views.uploadDetail(session, record, object);
        out.put("storage_provider", Views.providerRef(providers.findById(session.storageProviderId()).orElse(null)));
        return out;
    }

    public Map<String, Object> cancel(UUID uploadId) {
        UploadSession session = requireSession(uploadId);
        if ("CONFIRMED".equals(session.status())) {
            throw ApiException.conflict("已确认的上传任务不能取消");
        }
        if ("CANCELLED".equals(session.status())) {
            return detail(uploadId);
        }
        LogContext.open(Map.of(LogContext.UPLOAD_ID, session.id(), LogContext.FILE_ID, session.fileId(),
                LogContext.OBJECT_ID, session.fileObjectId(), LogContext.PROVIDER_ID, session.storageProviderId()));
        LogContext.operation("CANCEL_UPLOAD");
        try {
            StorageProvider provider = null;
            try {
                StorageProviderRow row = providerRow(session.storageProviderId(), false);
                provider = registry.get(row);
            } catch (RuntimeException e) {
                log.warn("取消上传时无法获取存储提供者，仅更新数据库状态: {}", e.getMessage());
            }
            if (provider != null && session.multipartId() != null) {
                try {
                    provider.abortMultipart(session.tempKey(), session.multipartId());
                } catch (Exception e) {
                    log.warn("取消分片上传失败 uploadId={}: {}", session.id(), e.getMessage());
                }
            }
            if (provider != null) {
                try {
                    provider.delete(session.tempKey());
                } catch (Exception e) {
                    log.warn("删除临时对象失败 uploadId={}: {}", session.id(), e.getMessage());
                }
            }
            db.inTx(() -> {
                db.update("""
                        UPDATE upload_session SET status = 'CANCELLED', cancelled_at = now(),
                            error_message = :error, updated_at = now() WHERE id = :id
                        """, Db.params("id", session.id(), "error", "上传任务已取消"));
                objects.markDeleted(session.fileObjectId());
                records.updateStatus(session.fileId(), "DELETED");
                records.softDelete(session.fileId());
            });
            sessions.deleteParts(session.id());
            operationLog.success("CANCEL_UPLOAD", session.storageProviderId(), session.fileObjectId(),
                    session.fileId(), session.id(), null, null, 0, Map.of());
            return detail(uploadId);
        } finally {
            LogContext.clear();
        }
    }

    public int expireDueSessions(int limit) {
        List<UploadSession> expired = sessions.findExpired(Instant.now(), limit);
        int count = 0;
        for (UploadSession session : expired) {
            try {
                expireSession(session);
                count++;
            } catch (Exception e) {
                log.warn("回收过期上传任务失败 uploadId={}: {}", session.id(), e.getMessage());
            }
        }
        return count;
    }

    public void expireSession(UploadSession session) {
        LogContext.open(Map.of(LogContext.UPLOAD_ID, session.id(), LogContext.FILE_ID, session.fileId(),
                LogContext.OBJECT_ID, session.fileObjectId(), LogContext.PROVIDER_ID, session.storageProviderId()));
        LogContext.operation("EXPIRE_UPLOAD");
        try {
            StorageProvider provider = null;
            try {
                StorageProviderRow row = providerRow(session.storageProviderId(), false);
                provider = registry.get(row);
            } catch (RuntimeException e) {
                log.warn("过期上传任务无法获取存储提供者，仅更新数据库状态: {}", e.getMessage());
            }
            if (provider != null && session.multipartId() != null) {
                try {
                    provider.abortMultipart(session.tempKey(), session.multipartId());
                } catch (Exception e) {
                    log.warn("过期上传任务取消分片失败 uploadId={}: {}", session.id(), e.getMessage());
                }
            }
            if (provider != null) {
                try {
                    provider.delete(session.tempKey());
                } catch (Exception e) {
                    log.warn("过期上传任务删除临时对象失败 uploadId={}: {}", session.id(), e.getMessage());
                }
            }
            sessions.updateStatus(session.id(), null, "EXPIRED", "上传任务已过期");
            objects.markDeleted(session.fileObjectId());
            records.updateStatus(session.fileId(), "EXPIRED");
            sessions.deleteParts(session.id());
            operationLog.success("EXPIRE_UPLOAD", session.storageProviderId(), session.fileObjectId(),
                    session.fileId(), session.id(), null, null, 0, Map.of());
        } finally {
            LogContext.clear();
        }
    }

    // ───────────────────────── 内部辅助 ─────────────────────────

    private UploadSession requireSession(UUID id) {
        return sessions.findById(id).orElseThrow(() -> ApiException.notFound("上传任务不存在"));
    }

    private void ensureUploadable(UploadSession session) {
        if (session.expiresAt() != null && session.expiresAt().isBefore(Instant.now())) {
            expireSession(session);
            throw ApiException.expired("上传任务已过期");
        }
        switch (session.status()) {
            case "CANCELLED" -> throw ApiException.expired("上传任务已取消");
            case "EXPIRED" -> throw ApiException.expired("上传任务已过期");
            case "CONFIRMED" -> throw ApiException.conflict("上传任务已确认");
            case "CONFIRMING" -> throw ApiException.conflict("上传任务正在确认中");
            default -> {
            }
        }
    }

    private StorageProviderRow providerRow(UUID id, boolean forUpload) {
        StorageProviderRow row;
        if (id == null) {
            row = providers.findDefault()
                    .or(() -> providers.findAll(false).stream().findFirst())
                    .orElseThrow(() -> ApiException.unavailable("没有可用的存储提供者，请先创建存储配置"));
        } else {
            row = providers.findById(id)
                    .orElseThrow(() -> ApiException.notFound("存储提供者不存在"));
        }
        if (!row.enabled()) {
            throw ApiException.conflict("存储提供者已禁用: " + row.code());
        }
        if (forUpload && !row.allowUpload()) {
            throw ApiException.conflict("存储提供者不允许上传: " + row.code());
        }
        return row;
    }

    private void validateCreate(CreateUploadCommand command) {
        if (command.filename() == null || command.filename().isBlank()) {
            throw ApiException.validation("filename", "文件名不能为空");
        }
        if (command.sourceType() == null || command.sourceType().isBlank()) {
            throw ApiException.validation("source_type", "来源类型不能为空");
        }
        if (command.size() != null && command.size() < 0) {
            throw ApiException.validation("size", "文件大小不能为负数");
        }
        if (command.size() != null && command.size() > props.security.maxFileSize) {
            throw ApiException.payloadTooLarge("文件超过允许的最大大小 " + props.security.maxFileSize + " 字节");
        }
    }

    private Plan multipartPlan(Long size, Long requestedPartSize) {
        if (size == null || size <= 0) {
            throw ApiException.validation("size", "分片上传必须提供大于 0 的文件大小");
        }
        long partSize = requestedPartSize == null ? props.upload.maxPartSize : requestedPartSize;
        if (partSize <= 0) {
            throw ApiException.validation("part_size", "分片大小必须大于 0");
        }
        if (partSize > props.upload.maxPartSize) {
            throw ApiException.validation("part_size", "分片大小不能超过 " + props.upload.maxPartSize + " 字节");
        }
        if (partSize < props.upload.minPartSize) {
            throw ApiException.validation("part_size", "分片大小不能小于 " + props.upload.minPartSize + " 字节");
        }
        int parts = (int) ((size + partSize - 1) / partSize);
        if (parts > props.upload.maxParts) {
            throw ApiException.validation("part_size",
                    "分片数量超过限制 " + props.upload.maxParts + "，请增大分片大小");
        }
        return new Plan(parts);
    }

    private Map<String, Object> singleAuthorization(StorageProvider provider, String tempKey, String mime,
                                                   Long size, Instant expiresAt) {
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        if (ttl.isNegative() || ttl.isZero()) {
            ttl = Duration.ofSeconds(60);
        }
        PresignedUpload upload = provider.presignUpload(tempKey, mime,
                size == null ? -1 : size, ttl);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("type", "PRE_SIGNED_PUT");
        out.put("url", upload.url());
        out.put("method", upload.method());
        out.put("headers", upload.headers());
        out.put("expires_at", upload.expiresAt().toString());
        out.put("extra", upload.extra());
        return out;
    }

    private Map<String, Object> multipartAuthorization(StorageProvider provider, String tempKey,
                                                       String multipartId, int partsTotal, Instant expiresAt) {
        Duration ttl = Duration.between(Instant.now(), expiresAt);
        if (ttl.isNegative() || ttl.isZero()) {
            ttl = Duration.ofSeconds(60);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("type", "PRE_SIGNED_MULTIPART");
        out.put("method", "PUT");
        out.put("multipart_id", multipartId);
        List<Map<String, Object>> parts = new ArrayList<>();
        for (int number = 1; number <= partsTotal; number++) {
            PartAuthorization authorization = provider.presignPart(tempKey, multipartId, number, ttl);
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("part_number", number);
            item.put("url", authorization.url());
            item.put("method", authorization.method());
            item.put("headers", authorization.headers());
            item.put("expires_at", authorization.expiresAt().toString());
            parts.add(item);
        }
        out.put("parts", parts);
        out.put("expires_at", expiresAt.toString());
        return out;
    }

    private Map<String, String> uploadMetadata(UploadSession session) {
        Map<String, String> metadata = new LinkedHashMap<>();
        metadata.put("upload-id", session.id().toString());
        metadata.put("file-id", session.fileId().toString());
        return metadata;
    }

    private void refreshPartAggregates(UUID uploadId) {
        Map<String, Object> aggregate = db.one("""
                SELECT COALESCE(sum(file_size), 0) AS total, count(*) AS parts
                FROM upload_part WHERE upload_id = :id
                """, Db.params("id", uploadId));
        long total = ((Number) aggregate.get("total")).longValue();
        int count = ((Number) aggregate.get("parts")).intValue();
        sessions.updateReceived(uploadId, total);
        sessions.setPartsCompleted(uploadId, count);
    }

    private void cleanupTemp(UploadSession session, StorageProvider provider) {
        try {
            provider.delete(session.tempKey());
        } catch (Exception e) {
            log.warn("删除临时对象失败 uploadId={} key={}: {}", session.id(), session.tempKey(), e.getMessage());
        }
    }

    private void abortForFailure(UploadSession session, String message) {
        try {
            StorageProviderRow row = providerRow(session.storageProviderId(), false);
            StorageProvider provider = registry.get(row);
            if (session.multipartId() != null) {
                try {
                    provider.abortMultipart(session.tempKey(), session.multipartId());
                } catch (Exception ignored) {
                    // 分片清理失败由过期任务兜底。
                }
            }
            try {
                provider.delete(session.tempKey());
            } catch (Exception ignored) {
                // 临时对象删除失败由运维清理任务兜底。
            }
        } catch (RuntimeException e) {
            log.debug("清理失败上传的临时对象时无法访问存储: {}", e.getMessage());
        }
        sessions.setFailed(session.id(), message);
        objects.markDeleted(session.fileObjectId());
        records.updateStatus(session.fileId(), "FAILED");
        sessions.deleteParts(session.id());
    }

    private static byte[] readHead(Path path) {
        try (InputStream in = Files.newInputStream(path)) {
            return in.readNBytes(16);
        } catch (IOException e) {
            return new byte[0];
        }
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

    private static String randomName(String extension) {
        String base = UUID.randomUUID().toString().replace("-", "");
        return extension == null || extension.isBlank() ? base : base + "." + extension;
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static long elapsedMs(long startNanos) {
        return (System.nanoTime() - startNanos) / 1_000_000;
    }

    private static String rootMessage(Throwable e) {
        Throwable cause = e;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        String text = cause.getMessage() == null ? cause.getClass().getSimpleName() : cause.getMessage();
        return text.length() > 300 ? text.substring(0, 300) : text;
    }

    private record Plan(int partsTotal) {
    }
}
