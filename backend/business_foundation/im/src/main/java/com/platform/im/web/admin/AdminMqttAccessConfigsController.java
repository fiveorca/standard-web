package com.platform.im.web.admin;

import com.platform.im.application.MqttAccessConfigService;
import com.platform.im.shared.Api;
import com.platform.im.web.dto.MqttDtos;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/mqtt/access-configs")
public class AdminMqttAccessConfigsController {
    private final MqttAccessConfigService service;

    public AdminMqttAccessConfigsController(MqttAccessConfigService service) {
        this.service = service;
    }

    @GetMapping
    public Map<String, Object> list(@RequestParam(required = false) Integer page,
                                    @RequestParam(required = false) Integer size,
                                    @RequestParam(required = false) String q,
                                    @RequestParam(required = false) String tenantId) {
        return Api.page(service.list(page, size, q, tenantId));
    }

    @PostMapping
    public Map<String, Object> create(@Valid @RequestBody MqttDtos.AccessConfigRequest request) {
        return Api.ok(service.create(request));
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable UUID id) {
        return Api.ok(service.get(id));
    }

    @PutMapping("/{id}")
    public Map<String, Object> update(@PathVariable UUID id,
                                      @Valid @RequestBody MqttDtos.AccessConfigRequest request) {
        return Api.ok(service.update(id, request));
    }

    @DeleteMapping("/{id}")
    public Map<String, Object> delete(@PathVariable UUID id) {
        service.delete(id);
        return Api.ok();
    }

    @PostMapping("/{id}/enable")
    public Map<String, Object> enable(@PathVariable UUID id) {
        return Api.ok(service.setEnabled(id, true));
    }

    @PostMapping("/{id}/disable")
    public Map<String, Object> disable(@PathVariable UUID id) {
        return Api.ok(service.setEnabled(id, false));
    }

    @PostMapping("/{id}/default")
    public Map<String, Object> setDefault(@PathVariable UUID id) {
        return Api.ok(service.setDefault(id));
    }

    @GetMapping("/{id}/acls")
    public Map<String, Object> listAcls(@PathVariable UUID id) {
        return Api.ok(service.listAcls(id));
    }

    @PostMapping("/{id}/acls")
    public Map<String, Object> addAcl(@PathVariable UUID id,
                                      @Valid @RequestBody MqttDtos.TopicAclRequest request) {
        return Api.ok(service.addAcl(id, request));
    }

    @DeleteMapping("/{id}/acls/{aclId}")
    public Map<String, Object> deleteAcl(@PathVariable UUID id, @PathVariable UUID aclId) {
        service.deleteAcl(id, aclId);
        return Api.ok();
    }
}
