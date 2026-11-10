package com.platform.file.infrastructure.security;

import com.platform.file.config.AppProperties;
import com.platform.file.shared.ApiException;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SecurityServicesTest {

    private static AppProperties properties() {
        AppProperties props = new AppProperties();
        props.encryption.key = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=";
        props.download.tokenSecret = "unit-test-download-secret";
        return props;
    }

    @Test
    void encryptsAndDecryptsCredentials() {
        AppProperties props = properties();
        SecretCipher cipher = new SecretCipher(props);
        String encrypted = cipher.encrypt("super-secret-access-key");
        assertNotEquals("super-secret-access-key", encrypted);
        assertEquals("super-secret-access-key", cipher.decrypt(encrypted));
        String second = cipher.encrypt("super-secret-access-key");
        assertNotEquals(encrypted, second);
        assertEquals(32, cipher.keyBytes().length);
    }

    @Test
    void issuesAndValidatesDownloadToken() {
        DownloadTokenService tokens = new DownloadTokenService(properties(), new SecretCipher(properties()));
        UUID fileId = UUID.randomUUID();
        String token = tokens.issue(fileId, 60);
        assertEquals(fileId, tokens.validate(token));
    }

    @Test
    void rejectsTamperedOrExpiredToken() {
        DownloadTokenService tokens = new DownloadTokenService(properties(), new SecretCipher(properties()));
        UUID fileId = UUID.randomUUID();
        String token = tokens.issue(fileId, 60);
        char replacement = token.charAt(token.length() - 1) == 'A' ? 'B' : 'A';
        String tampered = token.substring(0, token.length() - 1) + replacement;
        ApiException invalid = assertThrows(ApiException.class, () -> tokens.validate(tampered));
        assertEquals(401, invalid.status());

        String expired = tokens.issue(fileId, 1);
        assertThrows(ApiException.class, () -> {
            try {
                Thread.sleep(2200L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            tokens.validate(expired);
        });
    }

    @Test
    void rejectsMissingToken() {
        DownloadTokenService tokens = new DownloadTokenService(properties(), new SecretCipher(properties()));
        assertEquals(401, assertThrows(ApiException.class, () -> tokens.validate(null)).status());
        assertEquals(401, assertThrows(ApiException.class, () -> tokens.validate("bad")).status());
        Instant.now();
    }
}
