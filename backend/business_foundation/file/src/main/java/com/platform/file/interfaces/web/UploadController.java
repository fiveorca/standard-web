package com.platform.file.interfaces.web;

import com.platform.file.application.UploadService;
import com.platform.file.application.command.CreateUploadCommand;
import com.platform.file.interfaces.dto.Requests;
import com.platform.file.shared.Api;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.Ids;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URI;
import java.util.Locale;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/uploads")
public class UploadController {
    private final UploadService uploads;

    public UploadController(UploadService uploads) {
        this.uploads = uploads;
    }

    @PostMapping
    public ResponseEntity<Map<String, Object>> create(@RequestBody Requests.CreateUpload request) {
        CreateUploadCommand command = UploadRequestMapper.command(request);
        String mode = request.mode() == null || request.mode().isBlank()
                ? "SERVER" : request.mode().trim().toUpperCase(Locale.ROOT);
        Map<String, Object> created = switch (mode) {
            case "SERVER" -> uploads.createServerUpload(command);
            case "MULTIPART" -> uploads.createMultipartUpload(command);
            case "DIRECT", "DIRECT_MULTIPART" ->
                    throw ApiException.validation("mode", "客户端直传请使用 /api/v1/direct-uploads");
            default -> throw ApiException.validation("mode", "不支持的上传模式: " + request.mode());
        };
        Object uploadId = created.get("upload_id");
        return ResponseEntity.created(URI.create("/api/v1/uploads/" + uploadId)).body(Api.ok(created));
    }

    @PostMapping(value = "/{uploadId}/content", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Map<String, Object> uploadMultipart(@PathVariable String uploadId,
                                               @RequestParam("file") MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw ApiException.validation("file", "上传文件不能为空");
        }
        return Api.ok(uploads.uploadContent(Ids.required(uploadId, "upload_id"),
                file.getInputStream(), file.getSize(), file.getContentType()));
    }

    @PostMapping(value = "/{uploadId}/content", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public Map<String, Object> uploadRaw(@PathVariable String uploadId, HttpServletRequest request)
            throws IOException {
        return Api.ok(uploads.uploadContent(Ids.required(uploadId, "upload_id"),
                request.getInputStream(), request.getContentLengthLong(), null));
    }

    @PostMapping(value = "/{uploadId}/parts/{partNumber}", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public Map<String, Object> uploadPart(@PathVariable String uploadId,
                                          @PathVariable int partNumber,
                                          @RequestParam("file") MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw ApiException.validation("file", "分片内容不能为空");
        }
        return Api.ok(uploads.uploadPart(Ids.required(uploadId, "upload_id"), partNumber,
                file.getInputStream(), file.getSize()));
    }

    @PostMapping(value = "/{uploadId}/parts/{partNumber}", consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public Map<String, Object> uploadPartRaw(@PathVariable String uploadId,
                                             @PathVariable int partNumber,
                                             HttpServletRequest request) throws IOException {
        long size = request.getContentLengthLong();
        if (size <= 0) {
            throw ApiException.validation("content_length", "分片上传必须提供 Content-Length");
        }
        return Api.ok(uploads.uploadPart(Ids.required(uploadId, "upload_id"), partNumber,
                request.getInputStream(), size));
    }

    @PostMapping("/{uploadId}/complete-multipart")
    public Map<String, Object> completeMultipart(@PathVariable String uploadId) {
        return Api.ok(uploads.completeMultipart(Ids.required(uploadId, "upload_id")));
    }

    @PostMapping("/{uploadId}/confirm")
    public Map<String, Object> confirm(@PathVariable String uploadId,
                                       @RequestBody(required = false) Requests.ConfirmUpload request) {
        String sha = request == null ? null : request.sha256();
        return Api.ok(uploads.confirm(Ids.required(uploadId, "upload_id"), sha));
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
