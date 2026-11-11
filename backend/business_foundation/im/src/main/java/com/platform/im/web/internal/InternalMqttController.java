package com.platform.im.web.internal;

import com.platform.im.application.MqttDeviceCredentialService;
import com.platform.im.web.dto.MqttDtos;
import jakarta.validation.Valid;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * EMQX 5 HTTP 认证/授权回调。响应格式遵循 EMQX HTTP 数据源协议：
 * {"result":"allow"|"deny","is_superuser":false}。
 *
 * <p>EMQX 的 HTTP 认证后端发送 JSON，HTTP 授权后端发送
 * {@code application/x-www-form-urlencoded}，因此两类回调同时支持这两种 Content-Type。</p>
 */
@RestController
@RequestMapping("/api/v1/internal/mqtt")
public class InternalMqttController {
    private final MqttDeviceCredentialService credentialService;

    public InternalMqttController(MqttDeviceCredentialService credentialService) {
        this.credentialService = credentialService;
    }

    @PostMapping(value = "/auth", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> auth(@Valid @RequestBody MqttDtos.MqttAuthRequest request) {
        boolean allowed = credentialService.authenticateMqttUser(request.username(), request.password());
        return decision(allowed);
    }

    @PostMapping(value = "/auth", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> authForm(@RequestParam("username") String username,
                                        @RequestParam("password") String password) {
        boolean allowed = credentialService.authenticateMqttUser(username, password);
        return decision(allowed);
    }

    @PostMapping(value = "/acl", consumes = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> acl(@Valid @RequestBody MqttDtos.MqttAclRequest request) {
        boolean allowed = credentialService.authorizeTopic(request.username(), request.topic(), request.action());
        return decision(allowed);
    }

    @PostMapping(value = "/acl", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public Map<String, Object> aclForm(@RequestParam("username") String username,
                                       @RequestParam("topic") String topic,
                                       @RequestParam("action") String action) {
        boolean allowed = credentialService.authorizeTopic(username, topic, action);
        return decision(allowed);
    }

    private static Map<String, Object> decision(boolean allowed) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("result", allowed ? "allow" : "deny");
        body.put("is_superuser", false);
        return body;
    }
}
