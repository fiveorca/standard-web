package com.platform.file.interfaces.web;

import com.platform.file.application.FileService;
import com.platform.file.interfaces.dto.Requests;
import com.platform.file.shared.Api;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.Ids;
import com.platform.file.shared.PageQuery;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/files")
public class FileController {
    private final FileService files;

    public FileController(FileService files) {
        this.files = files;
    }

    @GetMapping
    public Map<String, Object> search(@RequestParam Map<String, String> query) {
        return Api.ok(files.search(query, PageQuery.of(query)));
    }

    @GetMapping("/{fileId}")
    public Map<String, Object> detail(@PathVariable String fileId) {
        return Api.ok(files.detail(Ids.required(fileId, "file_id")));
    }

    @GetMapping("/by-source")
    public Map<String, Object> bySource(@RequestParam Map<String, String> query) {
        return Api.ok(files.bySource(query.get("source_type"), query.get("source_id"),
                PageQuery.of(query)));
    }

    @GetMapping("/by-business")
    public Map<String, Object> byBusiness(@RequestParam Map<String, String> query) {
        return Api.ok(files.byBusiness(query.get("business_id"), PageQuery.of(query)));
    }

    @PostMapping("/batch-query")
    public Map<String, Object> batch(@RequestBody Requests.Ids request) {
        List<UUID> ids = parseIds(request);
        return Api.ok(files.batch(ids));
    }

    @DeleteMapping("/{fileId}")
    public Map<String, Object> delete(@PathVariable String fileId,
                                      @RequestParam(required = false) String operator) {
        return Api.ok(files.delete(Ids.required(fileId, "file_id"), operator));
    }

    @PostMapping("/batch-delete")
    public Map<String, Object> batchDelete(@RequestBody Requests.Ids request,
                                           @RequestParam(required = false) String operator) {
        return Api.ok(files.batchDelete(parseIds(request), operator));
    }

    @PatchMapping("/{fileId}/status")
    public Map<String, Object> updateStatus(@PathVariable String fileId,
                                            @RequestBody Requests.Status request) {
        if (request == null) {
            throw ApiException.validation("body", "请求体不能为空");
        }
        return Api.ok(files.updateStatus(Ids.required(fileId, "file_id"), request.status()));
    }

    @GetMapping("/{fileId}/download-url")
    public Map<String, Object> downloadUrl(@PathVariable String fileId,
                                           @RequestParam(required = false) Long ttl_seconds) {
        return Api.ok(files.downloadUrl(Ids.required(fileId, "file_id"), ttl_seconds));
    }

    @GetMapping("/{fileId}/download-token")
    public Map<String, Object> downloadToken(@PathVariable String fileId,
                                             @RequestParam(required = false) Long ttl_seconds) {
        return Api.ok(files.downloadUrl(Ids.required(fileId, "file_id"), ttl_seconds));
    }

    @GetMapping("/stats")
    public Map<String, Object> stats() {
        return Api.ok(files.stats());
    }

    @GetMapping("/source-stats")
    public Map<String, Object> sourceStats() {
        return Api.ok(files.sourceStats());
    }

    private static List<UUID> parseIds(Requests.Ids request) {
        if (request == null || request.ids() == null) {
            return List.of();
        }
        List<UUID> ids = new ArrayList<>();
        for (String id : request.ids()) {
            ids.add(Ids.required(id, "ids"));
        }
        return ids;
    }
}
