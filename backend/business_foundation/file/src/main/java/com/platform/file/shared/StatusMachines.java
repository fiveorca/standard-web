package com.platform.file.shared;

import java.util.Map;
import java.util.Set;

public final class StatusMachines {
    private StatusMachines() {
    }

    private static final Map<String, Set<String>> UPLOAD = Map.of(
            "CREATED", Set.of("UPLOADING", "UPLOADED", "CANCELLED", "EXPIRED", "FAILED", "CONFIRMING"),
            "UPLOADING", Set.of("UPLOADING", "UPLOADED", "CANCELLED", "EXPIRED", "FAILED"),
            "UPLOADED", Set.of("CONFIRMING", "UPLOADED", "CANCELLED", "EXPIRED", "FAILED"),
            "CONFIRMING", Set.of("CONFIRMED", "FAILED", "UPLOADED"),
            "CONFIRMED", Set.of("CONFIRMED"),
            "FAILED", Set.of("CONFIRMING", "UPLOADED", "FAILED", "CANCELLED", "EXPIRED"),
            "CANCELLED", Set.of("CANCELLED"),
            "EXPIRED", Set.of("EXPIRED"));

    private static final Map<String, Set<String>> OBJECT = Map.of(
            "PENDING_UPLOAD", Set.of("PENDING_UPLOAD", "TEMP_UPLOADED", "MIGRATING", "DELETED", "FAILED", "QUARANTINED"),
            "TEMP_UPLOADED", Set.of("TEMP_UPLOADED", "MIGRATING", "DELETED", "FAILED", "QUARANTINED"),
            "MIGRATING", Set.of("MIGRATING", "ACTIVE", "FAILED", "QUARANTINED"),
            "ACTIVE", Set.of("ACTIVE", "PENDING_DELETE", "FAILED", "QUARANTINED"),
            "PENDING_DELETE", Set.of("PENDING_DELETE", "ACTIVE", "DELETED", "FAILED"),
            "DELETED", Set.of("DELETED"),
            "FAILED", Set.of("FAILED", "MIGRATING", "ACTIVE", "DELETED", "PENDING_DELETE", "QUARANTINED"),
            "QUARANTINED", Set.of("QUARANTINED", "ACTIVE", "FAILED", "DELETED", "PENDING_DELETE"));

    private static final Map<String, Set<String>> RECORD = Map.of(
            "PENDING_UPLOAD", Set.of("PENDING_UPLOAD", "ACTIVE", "DELETED", "EXPIRED", "FAILED", "QUARANTINED"),
            "ACTIVE", Set.of("ACTIVE", "DELETED", "QUARANTINED"),
            "DELETED", Set.of("DELETED"),
            "EXPIRED", Set.of("EXPIRED", "DELETED"),
            "FAILED", Set.of("FAILED", "PENDING_UPLOAD", "DELETED", "QUARANTINED"),
            "QUARANTINED", Set.of("QUARANTINED", "ACTIVE", "DELETED"));

    public static void requireUpload(String from, String to) {
        require(UPLOAD, "上传任务", from, to);
    }

    public static void requireObject(String from, String to) {
        require(OBJECT, "文件对象", from, to);
    }

    public static void requireRecord(String from, String to) {
        require(RECORD, "文件记录", from, to);
    }

    private static void require(Map<String, Set<String>> machine, String label, String from, String to) {
        if (from != null && from.equals(to)) {
            return;
        }
        Set<String> allowed = machine.get(from);
        if (allowed == null || !allowed.contains(to)) {
            throw ApiException.conflict(label + "状态不允许从 " + from + " 变更为 " + to);
        }
    }
}
