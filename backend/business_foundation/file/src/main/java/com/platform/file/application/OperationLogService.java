package com.platform.file.application;

import com.platform.file.domain.model.OperationLog;
import com.platform.file.domain.repository.OperationLogRepository;
import com.platform.file.shared.Ids;
import com.platform.file.shared.LogContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
public class OperationLogService {
    private static final Logger log = LoggerFactory.getLogger(OperationLogService.class);

    private final OperationLogRepository repository;

    public OperationLogService(OperationLogRepository repository) {
        this.repository = repository;
    }

    public void success(String operation, UUID providerId, UUID objectId, UUID fileId, UUID uploadId,
                        String objectKey, Long bytes, long durationMs, Map<String, Object> detail) {
        write(operation, "SUCCESS", providerId, objectId, fileId, uploadId, objectKey, bytes,
                durationMs, detail, null);
    }

    public void failure(String operation, UUID providerId, UUID objectId, UUID fileId, UUID uploadId,
                        String objectKey, Long bytes, long durationMs, Map<String, Object> detail,
                        String error) {
        write(operation, "FAILED", providerId, objectId, fileId, uploadId, objectKey, bytes,
                durationMs, detail, error);
    }

    public void skipped(String operation, UUID providerId, UUID objectId, UUID fileId, UUID uploadId,
                        String objectKey, Map<String, Object> detail) {
        write(operation, "SKIPPED", providerId, objectId, fileId, uploadId, objectKey, null,
                0, detail, null);
    }

    private void write(String operation, String status, UUID providerId, UUID objectId, UUID fileId,
                       UUID uploadId, String objectKey, Long bytes, long durationMs,
                       Map<String, Object> detail, String error) {
        try {
            repository.insert(new OperationLog(Ids.uuidV7(), operation, status, providerId, objectId,
                    fileId, uploadId, objectKey, bytes, durationMs, LogContext.traceId(),
                    detail == null ? Map.of() : detail, error, Instant.now()));
        } catch (Exception e) {
            log.error("写入存储操作日志失败 operation={} status={}", operation, status, e);
        }
    }
}
