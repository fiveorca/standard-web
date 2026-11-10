package com.platform.auth.common;

import com.platform.auth.config.AppProps;
import com.platform.auth.security.CryptoBox;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

@Service
public class NotificationService {
    private static final Logger log = LoggerFactory.getLogger(NotificationService.class);
    private final Db db;
    private final AppProps props;
    private final CryptoBox crypto;
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(2)).build();

    public NotificationService(Db db, AppProps props, CryptoBox crypto) {
        this.db = db;
        this.props = props;
        this.crypto = crypto;
    }

    public String issue(String tenantId, String identityId, String purpose, String channel, String target) {
        String code = Ids.randomDigits(6);
        String hash = crypto.hmac(target + "|" + purpose + "|" + code);
        db.update("""
                INSERT INTO verification_codes
                (tenant_id, identity_id, purpose, channel, target, code_hash, expires_at)
                VALUES (:tenant, :identity, :purpose, :channel, :target, :hash, now() + (:ttl || ' seconds')::interval)
                """, Db.params("tenant", tenantId, "identity", identityId, "purpose", purpose,
                "channel", channel, "target", target, "hash", hash, "ttl", String.valueOf(props.getOtpTtlSeconds())));
        deliver(channel, target, purpose, code);
        return code;
    }

    public void verify(String tenantId, String purpose, String channel, String target, String code) {
        Map<String, Object> row = db.list("""
                SELECT id, code_hash, attempts, max_attempts FROM verification_codes
                WHERE tenant_id = :tenant AND purpose = :purpose AND channel = :channel AND target = :target
                  AND consumed_at IS NULL AND expires_at > now()
                ORDER BY created_at DESC LIMIT 1
                """, Db.params("tenant", tenantId, "purpose", purpose, "channel", channel, "target", target))
                .stream().findFirst().orElseThrow(() -> ApiException.badRequest("验证码无效或已过期"));
        int attempts = ((Number) row.get("attempts")).intValue();
        int maxAttempts = ((Number) row.get("max_attempts")).intValue();
        if (attempts >= maxAttempts) {
            throw ApiException.badRequest("验证码尝试次数过多");
        }
        String expected = crypto.hmac(target + "|" + purpose + "|" + code);
        if (!Ids.constantEquals(expected, String.valueOf(row.get("code_hash")))) {
            db.update("UPDATE verification_codes SET attempts = attempts + 1 WHERE id = :id",
                    Db.params("id", row.get("id")));
            throw ApiException.badRequest("验证码错误");
        }
        db.update("UPDATE verification_codes SET consumed_at = now() WHERE id = :id",
                Db.params("id", row.get("id")));
    }

    private void deliver(String channel, String target, String purpose, String code) {
        log.info("verification code channel={} purpose={} target={} code={}", channel, purpose, mask(target), code);
        if (props.getNotificationWebhook() == null || props.getNotificationWebhook().isBlank()) {
            return;
        }
        try {
            String body = Json.write(Map.of("channel", channel, "target", target, "purpose", purpose, "code", code));
            HttpRequest request = HttpRequest.newBuilder(URI.create(props.getNotificationWebhook()))
                    .timeout(Duration.ofSeconds(3))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build();
            http.send(request, HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            log.warn("notification webhook failed: {}", e.getMessage());
        }
    }

    private static String mask(String target) {
        if (target == null || target.length() < 4) {
            return "****";
        }
        return target.charAt(0) + "***" + target.substring(target.length() - 2);
    }
}
