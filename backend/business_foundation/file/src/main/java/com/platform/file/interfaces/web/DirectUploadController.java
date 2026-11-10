package com.platform.file.interfaces.web;

import com.platform.file.application.UploadService;
import com.platform.file.application.command.CreateUploadCommand;
import com.platform.file.domain.storage.MultipartPart;
import com.platform.file.interfaces.dto.Requests;
import com.platform.file.shared.Api;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.Ids;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/direct-uploads")
public class DirectUploadController {
    private final UploadService uploads;

    public DirectUploadController(UploadService uploads) {
        this.uploads = uploads;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> create(@RequestBody Requests.CreateUpload request) {
        CreateUploadCommand command = UploadRequestMapper.command(request);
        String mode = request.mode() == null || request.mode().isBlank()
                ? "DIRECT" : request.mode().trim().toUpperCase(Locale.ROOT);
        Map<String, Object> created = switch (mode) {
            case "DIRECT" -> uploads.createDirectUpload(command, false);
            case "DIRECT_MULTIPART" -> uploads.createDirectUpload(command, true);
            default -> throw ApiException.validation("mode", "直传模式仅支持 DIRECT 或 DIRECT_MULTIPART");
        };
        return ResponseEntity.created(URI.create("/api/v1/direct-uploads/" + created.get("upload_id")))
                .body(Api.ok(created));
    }

    @PostMapping("/{uploadId}/parts/authorize")
    public Map<String, Object> authorizeParts(@PathVariable String uploadId,
                                              @RequestBody Requests.AuthorizeParts request) {
        return Api.ok(uploads.authorizeParts(Ids.required(uploadId, "upload_id"),
                request == null ? List.of() : request.part_numbers()));
    }

    @PostMapping("/{uploadId}/complete")
    public Map<String, Object> complete(@PathVariable String uploadId,
                                        @RequestBody(required = false) Requests.CompleteDirect request) {
        List<MultipartPart> parts = request == null || request.parts() == null
                ? List.of()
                : request.parts().stream()
                .filter(part -> part != null && part.part_number() != null)
                .map(part -> new MultipartPart(part.part_number(), part.etag(),
                        part.size() == null ? 0 : part.size()))
                .toList();
        String sha = request == null ? null : request.sha256();
        return Api.ok(uploads.completeDirect(Ids.required(uploadId, "upload_id"), parts, sha));
    }

    @GetMapping("/{uploadId}")
    public Map<String, Object> detail(@PathVariable String uploadId) {
        return Api.ok(uploads.detail(Ids.required(uploadId, "upload_id")));
    }

    @PostMapping("/{uploadId}/cancel")
    public Map<String, Object> cancel(@PathVariable String uploadId) {
        return Api.ok(uploads.cancel(Ids.required(uploadId, "upload_id")));
    }
}
