package com.platform.im.web.admin;

import com.platform.im.application.EmailSendService;
import com.platform.im.domain.email.EmailTaskStatus;
import com.platform.im.shared.Api;
import com.platform.im.shared.Ids;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/email")
public class AdminEmailTasksController {
    private final EmailSendService service;

    public AdminEmailTasksController(EmailSendService service) {
        this.service = service;
    }

    @GetMapping("/tasks")
    public Map<String, Object> listTasks(@RequestParam(required = false) Integer page,
                                         @RequestParam(required = false) Integer size,
                                         @RequestParam(required = false) String tenantId,
                                         @RequestParam(required = false) String senderId,
                                         @RequestParam(required = false) EmailTaskStatus status) {
        return Api.page(service.list(page, size, Ids.parseUuid(tenantId, "tenant_id"),
                Ids.parseUuid(senderId, "sender_id"), status));
    }

    @GetMapping("/tasks/status")
    public Map<String, Object> status(@RequestParam(required = false) String taskId,
                                      @RequestParam(required = false) String requestId,
                                      @RequestParam(required = false) String tenantId) {
        return Api.ok(service.status(Ids.parseUuid(tenantId, "tenant_id"),
                Ids.parseUuid(taskId, "task_id"), requestId));
    }

    @GetMapping("/tasks/{id}")
    public Map<String, Object> detail(@PathVariable UUID id,
                                      @RequestParam(required = false) String tenantId) {
        return Api.ok(service.detail(Ids.parseUuid(tenantId, "tenant_id"), id));
    }

    @PostMapping("/tasks/{id}/retry")
    public Map<String, Object> retry(@PathVariable UUID id) {
        return Api.ok(service.retry(id));
    }

    @GetMapping("/tasks/{id}/records")
    public Map<String, Object> taskRecords(@PathVariable UUID id,
                                           @RequestParam(required = false) Integer page,
                                           @RequestParam(required = false) Integer size) {
        return Api.page(service.listRecords(page, size, null, id, null));
    }

    @GetMapping("/records")
    public Map<String, Object> records(@RequestParam(required = false) Integer page,
                                       @RequestParam(required = false) Integer size,
                                       @RequestParam(required = false) String tenantId,
                                       @RequestParam(required = false) String senderId) {
        return Api.page(service.listRecords(page, size, Ids.parseUuid(tenantId, "tenant_id"),
                null, Ids.parseUuid(senderId, "sender_id")));
    }
}
