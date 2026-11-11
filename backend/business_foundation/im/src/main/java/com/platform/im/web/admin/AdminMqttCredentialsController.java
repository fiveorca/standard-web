package com.platform.im.web.admin;

import com.platform.im.application.MqttDeviceCredentialService;
import com.platform.im.shared.Api;
import com.platform.im.web.dto.MqttDtos;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/mqtt/credentials")
public class AdminMqttCredentialsController {
    private final MqttDeviceCredentialService service;

    public AdminMqttCredentialsController(MqttDeviceCredentialService service) {
        this.service = service;
    }

    @GetMapping
    public Map<String, Object> list(@RequestParam(required = false) Integer page,
                                    @RequestParam(required = false) Integer size,
                                    @RequestParam(required = false) String tenantId,
                                    @RequestParam(required = false) String deviceId) {
        return Api.page(service.list(page, size, tenantId, deviceId));
    }

    @PostMapping
    public Map<String, Object> create(@Valid @RequestBody MqttDtos.CredentialCreateRequest request) {
        return Api.ok(service.create(request));
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable UUID id) {
        return Api.ok(service.get(id));
    }

    @PostMapping("/{id}/rotate")
    public Map<String, Object> rotate(@PathVariable UUID id) {
        return Api.ok(service.rotate(id));
    }

    @PostMapping("/{id}/disable")
    public Map<String, Object> disable(@PathVariable UUID id,
                                       @RequestParam(required = false) String reason) {
        return Api.ok(service.disable(id, reason));
    }

    @PostMapping("/{id}/revoke")
    public Map<String, Object> revoke(@PathVariable UUID id,
                                      @RequestParam(required = false) String reason) {
        return Api.ok(service.revoke(id, reason));
    }

    @GetMapping("/version")
    public Map<String, Object> version(@RequestParam(required = false) String tenantId,
                                       @RequestParam String deviceId) {
        return Api.ok(Map.of("configVersion", service.currentVersion(tenantId, deviceId)));
    }
}
