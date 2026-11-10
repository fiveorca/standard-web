package com.platform.file.interfaces.dto;

import java.util.List;
import java.util.Map;

/**
 * HTTP 请求体定义。字段使用 snake_case 与 API 文档保持一致，避免直接暴露领域实体。
 */
public final class Requests {
    private Requests() {
    }

    public record CreateUpload(
            String mode,
            String storage_provider_id,
            String filename,
            String display_name,
            String content_type,
            Long size,
            String source_type,
            String source_id,
            String business_id,
            String creator,
            String tenant_id,
            Map<String, Object> metadata,
            String idempotency_key,
            Long part_size) {
    }

    public record ConfirmUpload(String sha256) {
    }

    public record PartInput(Integer part_number, String etag, Long size) {
    }

    public record CompleteDirect(String sha256, List<PartInput> parts) {
    }

    public record AuthorizeParts(List<Integer> part_numbers) {
    }

    public record StorageProvider(
            String code,
            String name,
            String type,
            String endpoint,
            String region,
            String bucket,
            String root_path,
            String access_key,
            String secret_key,
            String access_key_env,
            String secret_key_env,
            Boolean enabled,
            Boolean default_provider,
            Boolean allow_upload,
            Boolean allow_download,
            Boolean allow_delete,
            Map<String, Object> options) {
    }

    public record Enabled(Boolean enabled) {
    }

    public record FileSource(String code, String name, String description, Boolean enabled) {
    }

    public record Status(String status) {
    }

    public record Ids(List<String> ids) {
    }
}
