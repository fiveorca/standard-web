package com.platform.auth.security;

import com.platform.auth.common.ApiException;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PkceTest {
    private static final String VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    @Test
    void computesS256Challenge() throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(VERIFIER.getBytes(StandardCharsets.US_ASCII));
        String expected = Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        assertThat(Pkce.s256(VERIFIER)).isEqualTo(expected);
    }

    @Test
    void acceptsPlainAndS256() {
        assertThatCode(() -> Pkce.verify(VERIFIER, "plain", VERIFIER)).doesNotThrowAnyException();
        assertThatCode(() -> Pkce.verify(Pkce.s256(VERIFIER), "S256", VERIFIER)).doesNotThrowAnyException();
        assertThatCode(() -> Pkce.verify(Pkce.s256(VERIFIER), "s256", VERIFIER)).doesNotThrowAnyException();
        assertThatCode(() -> Pkce.verify(null, "S256", null)).doesNotThrowAnyException();
    }

    @Test
    void rejectsMismatchAndMissingVerifier() {
        assertThatThrownBy(() -> Pkce.verify("challenge", "S256", VERIFIER)).isInstanceOf(ApiException.class);
        assertThatThrownBy(() -> Pkce.verify(Pkce.s256(VERIFIER), "S256", null)).isInstanceOf(ApiException.class);
    }
}
