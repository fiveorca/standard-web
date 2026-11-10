package com.platform.auth.security;

import com.platform.auth.common.ApiException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasswordServiceTest {
    private final PasswordService service = new PasswordService();

    @Test
    void hashesWithArgon2AndVerifies() {
        String hash = service.hash("Secret12345");
        assertThat(hash).startsWith("$argon2");
        assertThat(service.matches("Secret12345", hash)).isTrue();
        assertThat(service.matches("wrong", hash)).isFalse();
        assertThat(service.matches(null, hash)).isFalse();
        assertThat(service.matches("Secret12345", null)).isFalse();
    }

    @Test
    void enforcesPasswordStrength() {
        assertThatCode(() -> service.validateStrength("Passw0rd")).doesNotThrowAnyException();
        assertThatThrownBy(() -> service.validateStrength("short1")).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> service.validateStrength("allletters")).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> service.validateStrength("12345678")).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> service.validateStrength(null)).isInstanceOf(ApiException.class);
    }
}
