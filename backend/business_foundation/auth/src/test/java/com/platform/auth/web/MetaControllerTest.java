package com.platform.auth.web;

import com.platform.auth.config.AppProps;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class MetaControllerTest {
    private final MetaController controller = new MetaController(new AppProps());

    @Test
    void describesAllCoreEndpoints() {
        Map<String, Object> doc = controller.openapi();
        assertThat(doc.get("openapi")).isEqualTo("3.1.0");
        @SuppressWarnings("unchecked")
        Map<String, Object> paths = (Map<String, Object>) doc.get("paths");
        assertThat(paths)
                .containsKey("/api/v1/auth/login")
                .containsKey("/api/v1/auth/mfa/totp/confirm")
                .containsKey("/api/v1/authz/check")
                .containsKey("/api/v1/admin/roles")
                .containsKey("/api/v1/internal/events")
                .containsKey("/oauth2/token")
                .containsKey("/oauth2/.well-known/openid-configuration")
                .containsKey("/saml/metadata")
                .containsKey("/health");
    }

    @Test
    void servesSwaggerUi() {
        assertThat(controller.docs()).contains("swagger-ui").contains("/openapi.json");
    }
}
