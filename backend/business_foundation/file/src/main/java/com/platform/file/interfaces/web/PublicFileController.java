package com.platform.file.interfaces.web;

import com.platform.file.application.FileService;
import com.platform.file.shared.Ids;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api/v1/public/files")
public class PublicFileController {
    private final FileService files;

    public PublicFileController(FileService files) {
        this.files = files;
    }

    @GetMapping("/{fileId}/content")
    public ResponseEntity<StreamingResponseBody> content(@PathVariable String fileId,
                                                         @RequestParam("token") String token) {
        FileService.DownloadStream download = files.openContent(Ids.required(fileId, "file_id"), token);
        String filename = download.record().displayName() == null
                ? download.record().originalFilename() : download.record().displayName();
        MediaType mediaType = MediaType.APPLICATION_OCTET_STREAM;
        if (download.record().mimeType() != null) {
            try {
                mediaType = MediaType.parseMediaType(download.record().mimeType());
            } catch (RuntimeException ignored) {
                // 非法 MIME 时使用二进制流。
            }
        }
        StreamingResponseBody body = output -> {
            try (InputStream input = download.stream()) {
                input.transferTo(output);
            }
        };
        return ResponseEntity.ok()
                .contentType(mediaType)
                .contentLength(download.record().fileSize())
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        ContentDisposition.attachment()
                                .filename(filename == null ? "download" : filename, StandardCharsets.UTF_8)
                                .build().toString())
                .header(HttpHeaders.CACHE_CONTROL, "private, max-age=60")
                .body(body);
    }
}
