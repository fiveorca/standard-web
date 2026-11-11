package com.platform.im.web.device;

import com.platform.im.application.MqttDeviceCredentialService;
import com.platform.im.security.RequestContext;
import com.platform.im.shared.Api;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/device/mqtt")
public class DeviceMqttConfigController {
    private final MqttDeviceCredentialService service;

    public DeviceMqttConfigController(MqttDeviceCredentialService service) {
        this.service = service;
    }

    @GetMapping("/config")
    public Map<String, Object> config(HttpServletRequest request) {
        UUID tenantId = RequestContext.tenantId(request);
        String deviceId = RequestContext.deviceId(request);
        return Api.ok(service.deviceConfig(tenantId, deviceId));
    }

    @GetMapping("/config/version")
    public Map<String, Object> version(HttpServletRequest request) {
        UUID tenantId = RequestContext.tenantId(request);
        String deviceId = RequestContext.deviceId(request);
        return Api.ok(Map.of("configVersion", service.currentVersion(
                tenantId == null ? null : tenantId.toString(), deviceId)));
    }
}
