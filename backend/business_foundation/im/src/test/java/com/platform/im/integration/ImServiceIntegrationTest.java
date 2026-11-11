package com.platform.im.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 端到端集成测试（需 Docker）：Flyway 建表、管理端创建设备凭证、
 * 设备配置获取、EMQX HTTP 认证/ACL 回调与租户隔离。
 */
@Tag("docker")
@Testcontainers
@AutoConfigureMockMvc
@SpringBootTest(properties = {
        "im.grpc.port=0",
        "im.email.worker-enabled=false",
        "im.seed.enabled=true",
        "im.security.admin-api-key=test-admin-key",
        "im.security.internal-token=test-internal-token",
        "im.mqtt.status-check-interval-ms=600000"
})
class ImServiceIntegrationTest {
    @Container
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
    }

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @Test
    void deviceCredentialFlowAndEmqxCallbacksWork() throws Exception {
        String created = mockMvc.perform(post("/api/v1/admin/mqtt/credentials")
                        .header("X-API-Key", "test-admin-key")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("deviceId", "device-it-1"))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode data = JSON.readTree(created).get("data");
        String username = data.get("credential").get("username").asText();
        String password = data.get("password").asText();
        assertFalse(username.isBlank());
        assertFalse(password.isBlank());

        String configBody = mockMvc.perform(get("/api/v1/device/mqtt/config")
                        .header("X-Device-Id", "device-it-1")
                        .header("X-Device-Token", password))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        JsonNode config = JSON.readTree(configBody).get("data");
        assertEquals("devices/device-it-1/up", config.get("publishTopic").asText());
        assertEquals("devices/device-it-1/down", config.get("subscribeTopic").asText());

        String authBody = mockMvc.perform(post("/api/v1/internal/mqtt/auth")
                        .header("X-Internal-Token", "test-internal-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", username, "password", password))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertEquals("allow", JSON.readTree(authBody).get("result").asText());

        String wrongAuth = mockMvc.perform(post("/api/v1/internal/mqtt/auth")
                        .header("X-Internal-Token", "test-internal-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", username, "password", "wrong"))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertEquals("deny", JSON.readTree(wrongAuth).get("result").asText());

        String allowAcl = mockMvc.perform(post("/api/v1/internal/mqtt/acl")
                        .header("X-Internal-Token", "test-internal-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", username, "topic", "devices/device-it-1/up",
                                "action", "publish"))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertEquals("allow", JSON.readTree(allowAcl).get("result").asText());

        String denyAcl = mockMvc.perform(post("/api/v1/internal/mqtt/acl")
                        .header("X-Internal-Token", "test-internal-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", username, "topic", "devices/other/up",
                                "action", "publish"))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertEquals("deny", JSON.readTree(denyAcl).get("result").asText());

        String subscribe = mockMvc.perform(post("/api/v1/internal/mqtt/acl")
                        .header("X-Internal-Token", "test-internal-token")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of(
                                "username", username, "topic", "devices/device-it-1/down",
                                "action", "subscribe"))))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        assertEquals("allow", JSON.readTree(subscribe).get("result").asText());

        mockMvc.perform(get("/api/v1/device/mqtt/config")
                        .header("X-Device-Id", "device-it-1")
                        .header("X-Device-Token", "wrong"))
                .andExpect(status().isUnauthorized());
    }
}
