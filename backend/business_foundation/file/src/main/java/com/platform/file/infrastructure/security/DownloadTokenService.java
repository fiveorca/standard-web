package com.platform.file.infrastructure.security;

import com.platform.file.config.AppProperties;
import com.platform.file.shared.ApiException;
import com.platform.file.shared.Ids;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

/**
 * 为无法使用对象存储预签名的后端（如本地磁盘）生成短期下载令牌。
 */
@Component
public class DownloadTokenService {
    private final byte[] secret;

    public DownloadTokenService(AppProperties props, SecretCipher cipher) {
        String configured = props.download.tokenSecret;
        this.secret = configured != null && !configured.isBlank()
                ? configured.getBytes(StandardCharsets.UTF_8)
                : cipher.keyBytes();
    }

    public String issue(UUID fileId, long ttlSeconds) {
        long expiresAt = Instant.now().plusSeconds(Math.max(1, ttlSeconds)).getEpochSecond();
        String payload = fileId + ":" + expiresAt;
        String body = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
        return body + "." + sign(body);
    }

    public UUID validate(String token) {
        if (token == null || token.isBlank()) {
            throw ApiException.unauthorized("缺少下载令牌");
        }
        String[] parts = token.split("\\.");
        if (parts.length != 2) {
            throw ApiException.unauthorized("下载令牌格式不合法");
        }
        if (!MessageDigest.isEqual(sign(parts[0]).getBytes(StandardCharsets.UTF_8),
                parts[1].getBytes(StandardCharsets.UTF_8))) {
            throw ApiException.unauthorized("下载令牌签名不合法");
        }
        String payload = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        int colon = payload.lastIndexOf(':');
        if (colon <= 0) {
            throw ApiException.unauthorized("下载令牌内容不合法");
        }
        UUID fileId = Ids.parse(payload.substring(0, colon));
        long expiresAt;
        try {
            expiresAt = Long.parseLong(payload.substring(colon + 1));
        } catch (NumberFormatException e) {
            throw ApiException.unauthorized("下载令牌内容不合法");
        }
        if (fileId == null) {
            throw ApiException.unauthorized("下载令牌内容不合法");
        }
        if (Instant.now().getEpochSecond() > expiresAt) {
            throw ApiException.expired("下载令牌已过期");
        }
        return fileId;
    }

    public long ttlSeconds(AppProperties props) {
        return Math.max(1, props.download.urlTtlSeconds);
    }

    private String sign(String body) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(mac.doFinal(body.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new ApiException(500, "token_error", "生成下载令牌失败");
        }
    }
}
