package com.platform.file.interfaces.web;

import com.platform.file.application.CleanupService;
import com.platform.file.application.FileService;
import com.platform.file.domain.repository.OperationLogRepository;
import com.platform.file.shared.Api;
import com.platform.file.shared.Ids;
import com.platform.file.shared.PageQuery;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/ops")
public class OpsController {
    private final CleanupService cleanup;
    private final FileService files;
    private final OperationLogRepository logs;

    public OpsController(CleanupService cleanup, FileService files, OperationLogRepository logs) {
        this.cleanup = cleanup;
        this.files = files;
        this.logs = logs;
    }

    @PostMapping("/scan")
    public Map<String, Object> scan(@RequestParam(required = false) String provider_id,
                                    @RequestParam(defaultValue = "false") boolean dry_run) {
        return Api.ok(cleanup.scanOrphans(UploadRequestMapper.optionalUuid(provider_id, "provider_id"), dry_run));
    }

    @PostMapping("/cleanup")
    public Map<String, Object> cleanup(@RequestParam(required = false) String provider_id,
                                       @RequestParam(defaultValue = "false") boolean dry_run) {
        return Api.ok(cleanup.manualCleanup(
                UploadRequestMapper.optionalUuid(provider_id, "provider_id"), dry_run));
    }

    @PostMapping("/consistency")
    public Map<String, Object> consistency(@RequestParam(defaultValue = "false") boolean dry_run) {
        return Api.ok(cleanup.consistencyCheck(dry_run));
    }

    @PostMapping("/upload-expiry")
    public Map<String, Object> uploadExpiry() {
        return Api.ok(cleanup.uploadExpiry());
    }

    @GetMapping("/cleanup-tasks")
    public Map<String, Object> tasks(@RequestParam(required = false) String type,
                                     @RequestParam(required = false) String status,
                                     @RequestParam Map<String, String> query) {
        return Api.ok(cleanup.tasks(type, status, PageQuery.of(query)));
    }

    @GetMapping("/cleanup-tasks/{id}")
    public Map<String, Object> task(@PathVariable String id) {
        return Api.ok(cleanup.task(Ids.required(id, "task_id")));
    }

    @GetMapping("/summary")
    public Map<String, Object> summary() {
        return Api.ok(cleanup.summary());
    }

    @GetMapping("/operation-logs")
    public Map<String, Object> operationLogs(@RequestParam(required = false) String operation,
                                             @RequestParam(required = false) String status,
                                             @RequestParam(required = false) String file_id,
                                             @RequestParam Map<String, String> query) {
        PageQuery page = PageQuery.of(query);
        return Api.page(logs.search(operation, status, file_id, page.offset(), page.size()),
                logs.count(operation, status, file_id), page.page(), page.size());
    }

    @GetMapping("/file-stats")
    public Map<String, Object> fileStats() {
        return Api.ok(files.stats());
    }

    @GetMapping("/source-stats")
    public Map<String, Object> sourceStats() {
        return Api.ok(files.sourceStats());
    }

    @GetMapping("/storage-usage")
    public Map<String, Object> storageUsage() {
        Map<String, Object> stats = files.stats();
        return Api.ok(Map.of("providers", stats.get("providers"), "objects", stats.get("objects")));
    }
}
