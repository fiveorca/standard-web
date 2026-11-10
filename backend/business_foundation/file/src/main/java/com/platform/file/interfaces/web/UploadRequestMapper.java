package com.platform.file.interfaces.web;

import com.platform.file.application.command.CreateUploadCommand;
import com.platform.file.interfaces.dto.Requests;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.Ids;

import java.util.UUID;

final class UploadRequestMapper {
    private UploadRequestMapper() {
    }

    static CreateUploadCommand command(Requests.CreateUpload request) {
        if (request == null) {
            throw ApiException.validation("body", "请求体不能为空");
        }
        return new CreateUploadCommand(
                optionalUuid(request.storage_provider_id(), "storage_provider_id"),
                request.filename(),
                request.display_name(),
                request.content_type(),
                request.size(),
                request.source_type(),
                request.source_id(),
                request.business_id(),
                request.creator(),
                optionalUuid(request.tenant_id(), "tenant_id"),
                request.metadata(),
                request.idempotency_key(),
                request.part_size());
    }

    static UUID optionalUuid(String value, String field) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return Ids.required(value, field);
    }
}
