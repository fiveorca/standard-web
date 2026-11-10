package com.platform.file.application;

import com.platform.file.domain.model.FileObject;
import com.platform.file.domain.model.FileRecord;
import com.platform.file.domain.model.StorageProviderRow;
import com.platform.file.domain.model.UploadSession;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 对外视图映射。所有 API 只返回视图，不直接暴露数据库实体与物理存储路径。
 */
public final class Views {
    private Views() {
    }

    public static Map<String, Object> record(FileRecord r) {
        if (r == null) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("file_id", text(r.id()));
        out.put("file_object_id", text(r.fileObjectId()));
        out.put("storage_provider_id", text(r.storageProviderId()));
        out.put("original_filename", r.originalFilename());
        out.put("display_name", r.displayName());
        out.put("file_size", r.fileSize());
        out.put("mime_type", r.mimeType());
        out.put("extension", r.extension());
        out.put("source_type", r.sourceType());
        out.put("source_id", r.sourceId());
        out.put("business_id", r.businessId());
        out.put("creator", r.creator());
        out.put("tenant_id", text(r.tenantId()));
        out.put("status", r.status());
        out.put("sha256", r.sha256());
        out.put("metadata", r.metadata() == null ? Map.of() : r.metadata());
        out.put("created_at", instant(r.createdAt()));
        out.put("updated_at", instant(r.updatedAt()));
        out.put("deleted_at", instant(r.deletedAt()));
        return out;
    }

    public static Map<String, Object> object(FileObject o) {
        if (o == null) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("file_object_id", text(o.id()));
        out.put("storage_provider_id", text(o.storageProviderId()));
        out.put("sha256", o.sha256());
        out.put("file_size", o.fileSize());
        out.put("mime_type", o.mimeType());
        out.put("extension", o.extension());
        out.put("etag", o.etag());
        out.put("status", o.status());
        out.put("delete_after", instant(o.deleteAfter()));
        out.put("delete_attempts", o.deleteAttempts());
        out.put("last_error", o.lastError());
        out.put("verified_at", instant(o.verifiedAt()));
        out.put("created_at", instant(o.createdAt()));
        out.put("updated_at", instant(o.updatedAt()));
        return out;
    }

    public static Map<String, Object> providerRef(StorageProviderRow row) {
        if (row == null) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", text(row.id()));
        out.put("code", row.code());
        out.put("name", row.name());
        out.put("type", row.type() == null ? null : row.type().name());
        return out;
    }

    public static Map<String, Object> upload(UploadSession s) {
        if (s == null) {
            return null;
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("upload_id", text(s.id()));
        out.put("file_id", text(s.fileId()));
        out.put("file_object_id", text(s.fileObjectId()));
        out.put("storage_provider_id", text(s.storageProviderId()));
        out.put("mode", s.mode());
        out.put("status", s.status());
        out.put("expected_size", s.expectedSize());
        out.put("received_size", s.receivedSize());
        out.put("sha256", s.sha256());
        out.put("parts_total", s.partsTotal());
        out.put("parts_completed", s.partsCompleted());
        out.put("expires_at", instant(s.expiresAt()));
        out.put("confirmed_at", instant(s.confirmedAt()));
        out.put("cancelled_at", instant(s.cancelledAt()));
        out.put("error", s.errorMessage());
        out.put("metadata", s.metadata() == null ? Map.of() : s.metadata());
        out.put("created_at", instant(s.createdAt()));
        out.put("updated_at", instant(s.updatedAt()));
        return out;
    }

    public static Map<String, Object> uploadDetail(UploadSession s, FileRecord r, FileObject o) {
        Map<String, Object> out = upload(s);
        out.put("file", record(r));
        out.put("object", object(o));
        return out;
    }

    private static String text(Object value) {
        return value == null ? null : value.toString();
    }

    private static String instant(Instant value) {
        return value == null ? null : value.toString();
    }
}
