package com.platform.im.shared;

import com.platform.im.config.AppProperties;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

/**
 * 敏感数据加密与摘要工具：AES-256-GCM 用于可逆加密，SHA-256 用于设备凭证校验。
 */
@Component
public class CryptoService {
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final String PREFIX = "v1:";

    private final SecretKeySpec key;
    private final String devicePepper;

    public CryptoService(AppProperties props) {
        this.key = new SecretKeySpec(deriveKey(props.encryption.key), "AES");
        this.devicePepper = props.security.deviceTokenPepper == null ? "" : props.security.deviceTokenPepper;
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
            throw ApiException.internal("敏感数据加密失败");
        }
    }

    public String decrypt(String encrypted) {
        if (encrypted == null || encrypted.isBlank()) {
            return null;
        }
        if (!encrypted.startsWith(PREFIX)) {
            throw ApiException.internal("敏感数据密文格式不合法");
        }
        try {
            byte[] combined = Base64.getDecoder().decode(encrypted.substring(PREFIX.length()));
            if (combined.length <= 12) {
                throw new IllegalArgumentException("cipher text too short");
            }
            byte[] iv = new byte[12];
            byte[] payload = new byte[combined.length - 12];
            System.arraycopy(combined, 0, iv, 0, 12);
            System.arraycopy(combined, 12, payload, 0, payload.length);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            return new String(cipher.doFinal(payload), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw ApiException.internal("敏感数据解密失败");
        }
    }

    public String deviceSecretHash(String rawSecret) {
        return sha256Hex(devicePepper + ":" + (rawSecret == null ? "" : rawSecret));
    }

    public boolean verifyDeviceSecret(String rawSecret, String storedHash) {
        if (rawSecret == null || storedHash == null) {
            return false;
        }
        return constantTimeEquals(deviceSecretHash(rawSecret), storedHash);
    }

    public static String sha256Hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw ApiException.internal("摘要计算失败");
        }
    }

    public static String sha256Base64(byte[] value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getEncoder().encodeToString(digest.digest(value));
        } catch (Exception e) {
            throw ApiException.internal("摘要计算失败");
        }
    }

    public static boolean constantTimeEquals(String left, String right) {
        if (left == null || right == null) {
            return false;
        }
        return MessageDigest.isEqual(left.getBytes(StandardCharsets.UTF_8), right.getBytes(StandardCharsets.UTF_8));
    }

    public static String randomSecret(int bytes) {
        byte[] buffer = new byte[bytes];
        RANDOM.nextBytes(buffer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
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
            try {
                return MessageDigest.getInstance("SHA-256")
                        .digest(String.valueOf(configured).getBytes(StandardCharsets.UTF_8));
            } catch (Exception e) {
                throw ApiException.internal("无法初始化加密密钥");
            }
        }
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest("im-service-default-key".getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw ApiException.internal("无法初始化加密密钥");
        }
    }
}
