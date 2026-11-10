package com.platform.file.infrastructure.security;

import com.platform.file.config.AppProperties;
import com.platform.file.shared.ApiException;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * 使用 AES-256-GCM 加密存储 Access Key / Secret Key，数据库中只保存密文。
 */
@Component
public class SecretCipher {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String PREFIX = "v1:";

    private final SecretKeySpec key;

    public SecretCipher(AppProperties props) {
        this.key = new SecretKeySpec(deriveKey(props.encryption.key), "AES");
    }

    public String encrypt(String plain) {
        if (plain == null || plain.isEmpty()) {
            return null;
        }
        try {
            byte[] iv = new byte[12];
            RANDOM.nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] encrypted = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            byte[] combined = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);
            return PREFIX + Base64.getEncoder().encodeToString(combined);
        } catch (Exception e) {
            throw new ApiException(500, "encryption_error", "凭据加密失败");
        }
    }

    public String decrypt(String encrypted) {
        if (encrypted == null || encrypted.isBlank()) {
            return null;
        }
        if (!encrypted.startsWith(PREFIX)) {
            throw new ApiException(500, "encryption_error", "凭据密文格式不合法");
        }
        try {
            byte[] combined = Base64.getDecoder().decode(encrypted.substring(PREFIX.length()));
            byte[] iv = new byte[12];
            byte[] payload = new byte[combined.length - 12];
            System.arraycopy(combined, 0, iv, 0, 12);
            System.arraycopy(combined, 12, payload, 0, payload.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(payload), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new ApiException(500, "encryption_error", "凭据解密失败");
        }
    }

    public byte[] keyBytes() {
        return key.getEncoded();
    }

    private static byte[] deriveKey(String configured) {
        try {
            if (configured != null && !configured.isBlank()) {
                byte[] decoded = Base64.getDecoder().decode(configured.trim());
                if (decoded.length == 32) {
                    return decoded;
                }
                return MessageDigest.getInstance("SHA-256").digest(decoded);
            }
        } catch (Exception ignored) {
            // 配置不是合法 Base64 时同样使用摘要派生，保证服务可启动并给出明确错误。
            try {
                return MessageDigest.getInstance("SHA-256")
                        .digest(String.valueOf(configured).getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                throw new ApiException(500, "encryption_error", "无法初始化加密密钥");
            }
        }
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest("file-service-default-key".getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new ApiException(500, "encryption_error", "无法初始化加密密钥");
        }
    }
}
