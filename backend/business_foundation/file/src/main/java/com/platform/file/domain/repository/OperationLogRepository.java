package com.platform.file.domain.repository;

import com.platform.file.domain.model.OperationLog;

import java.util.List;
import java.util.Map;

public interface OperationLogRepository {
    void insert(OperationLog log);

    List<Map<String, Object>> search(String operation, String status, String fileId, int offset, int limit);

    long count(String operation, String status, String fileId);
}
