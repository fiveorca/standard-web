package com.platform.auth.security;

import com.platform.auth.common.ApiException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TotpTest {
    private static final String RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    @Test
    void matchesRfc4226Vectors() {
        assertThat(Totp.code(RFC_SECRET, 0)).isEqualTo("755224");
        assertThat(Totp.code(RFC_SECRET, 1)).isEqualTo("287082");
        assertThat(Totp.code(RFC_SECRET, 2)).isEqualTo("359152");
        assertThat(Totp.code(RFC_SECRET, 9)).isEqualTo("520489");
    }

    @Test
    void verifiesWithinWindowOnly() {
        long counter = Totp.counter(30);
        String code = Totp.code(RFC_SECRET, counter);
        assertThat(Totp.verify(RFC_SECRET, code, counter, 1)).isTrue();
        assertThat(Totp.verify(RFC_SECRET, code, counter + 5, 1)).isFalse();
        assertThat(Totp.verify(RFC_SECRET, null, counter, 1)).isFalse();
    }

    @Test
    void base32RoundTrip() {
        byte[] data = "platform-auth".getBytes(StandardCharsets.UTF_8);
        assertThat(Totp.base32Decode(Totp.base32Encode(data))).isEqualTo(data);
    }

    @Test
    void rejectsInvalidSecret() {
        assertThatThrownBy(() -> Totp.base32Decode("!!!!")).isInstanceOf(ApiException.class);
    }

    @Test
    void generatesProvisioningUriAndRecoveryCodes() {
        String secret = Totp.newSecret();
        assertThat(secret).hasSize(32);
        assertThat(Totp.provisioningUri("Auth Center", "admin", secret))
                .startsWith("otpauth://totp/")
                .contains("secret=" + secret);
        assertThat(Totp.recoveryCode()).isNotEqualTo(Totp.recoveryCode());
    }
}
