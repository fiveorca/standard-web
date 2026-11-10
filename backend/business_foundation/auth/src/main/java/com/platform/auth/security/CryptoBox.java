package com.platform.auth.security;

import com.platform.auth.common.ApiException;
import com.platform.auth.common.Ids;
import com.platform.auth.config.AppProps;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class CryptoBox {
    private static final SecureRandom RANDOM = new SecureRandom();
    private final SecretKeySpec key;
    private final AppProps props;

    public CryptoBox(AppProps props) {
        this.props = props;
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(props.getEncryptionKey().getBytes(StandardCharsets.UTF_8));
            this.key = new SecretKeySpec(digest, "AES");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public String encrypt(String plaintext) {
        try {
            byte[] iv = new byte[12];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
            return "v1." + b64.encodeToString(iv) + "." + b64.encodeToString(encrypted);
        } catch (Exception e) {
            throw ApiException.internal("加密失败");
        }
    }

    public String decrypt(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3 || !"v1".equals(parts[0])) {
                throw new IllegalArgumentException("bad token");
            }
            Base64.Decoder b64 = Base64.getUrlDecoder();
            byte[] iv = b64.decode(parts[1]);
            byte[] data = b64.decode(parts[2]);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(data), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw ApiException.internal("解密失败");
        }
    }

    public String hmac(String value) {
        return Ids.hmacSha256(props.getEncryptionKey(), value);
    }
}
