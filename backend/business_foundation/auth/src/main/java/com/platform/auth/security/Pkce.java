package com.platform.auth.security;

import com.platform.auth.common.ApiException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public final class Pkce {
    private Pkce() {}

    public static void verify(String challenge, String method, String verifier) {
        if (challenge == null || challenge.isBlank()) {
            return;
        }
        if (verifier == null || verifier.isBlank()) {
            throw ApiException.badRequest("缺少 code_verifier");
        }
        String computed = "S256".equalsIgnoreCase(method)
                ? s256(verifier)
                : verifier;
        if (!MessageDigest.isEqual(computed.getBytes(StandardCharsets.UTF_8),
                challenge.getBytes(StandardCharsets.UTF_8))) {
            throw ApiException.badRequest("code_verifier 校验失败");
        }
    }

    public static String s256(String verifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw ApiException.internal("PKCE 计算失败");
        }
    }
}
