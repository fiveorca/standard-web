package com.platform.im.shared;

import com.platform.im.config.AppProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CryptoServiceTest {
    private CryptoService crypto;

    @BeforeEach
    void setUp() {
        AppProperties props = new AppProperties();
        props.encryption.key = Base64.getEncoder().encodeToString(new byte[32]);
        props.security.deviceTokenPepper = "unit-test-pepper";
        crypto = new CryptoService(props);
    }

    @Test
    void encryptsAndDecryptsWithRandomIv() {
        String first = crypto.encrypt("secret-value");
        String second = crypto.encrypt("secret-value");
        assertNotEquals(first, second);
        assertTrue(first.startsWith("v1:"));
        assertEquals("secret-value", crypto.decrypt(first));
        assertEquals("secret-value", crypto.decrypt(second));
    }

    @Test
    void rejectsTamperedCipherText() {
        String encrypted = crypto.encrypt("secret-value");
        String tampered = encrypted.substring(0, encrypted.length() - 2) + "AA";
        assertThrows(ApiException.class, () -> crypto.decrypt(tampered));
    }

    @Test
    void deviceSecretHashIsSaltedAndVerifiable() {
        String hash = crypto.deviceSecretHash("device-token");
        assertTrue(crypto.verifyDeviceSecret("device-token", hash));
        assertTrue(!crypto.verifyDeviceSecret("other-token", hash));
        assertNotEquals(CryptoService.sha256Hex("device-token"), hash);
    }

    @Test
    void constantTimeEqualsHandlesNulls() {
        assertTrue(CryptoService.constantTimeEquals("abc", "abc"));
        assertTrue(!CryptoService.constantTimeEquals("abc", "abd"));
        assertTrue(!CryptoService.constantTimeEquals(null, "abc"));
    }
}
