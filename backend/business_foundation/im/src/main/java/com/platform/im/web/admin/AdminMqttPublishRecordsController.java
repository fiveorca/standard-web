package com.platform.im.web.admin;

import com.platform.im.application.MqttPublishService;
import com.platform.im.domain.mqtt.PublishStatus;
import com.platform.im.shared.Api;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin/mqtt/publish-records")
public class AdminMqttPublishRecordsController {
    private final MqttPublishService service;

    public AdminMqttPublishRecordsController(MqttPublishService service) {
        this.service = service;
    }

    @GetMapping
    public Map<String, Object> list(@RequestParam(required = false) Integer page,
                                    @RequestParam(required = false) Integer size,
                                    @RequestParam(required = false) String tenantId,
                                    @RequestParam(required = false) String deviceId,
                                    @RequestParam(required = false) PublishStatus status) {
        return Api.page(service.list(page, size, tenantId, deviceId, status));
    }

    @GetMapping("/{id}")
    public Map<String, Object> get(@PathVariable UUID id,
                                   @RequestParam(required = false) String tenantId) {
        return Api.ok(service.get(id, tenantId));
    }
}
