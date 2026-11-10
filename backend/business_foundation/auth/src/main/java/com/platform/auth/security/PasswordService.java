package com.platform.auth.security;

import com.platform.auth.common.ApiException;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
public class PasswordService {
    private static final Pattern LETTER = Pattern.compile("[A-Za-z]");
    private static final Pattern DIGIT = Pattern.compile("\\d");
    private final Argon2PasswordEncoder encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();

    public String hash(String raw) {
        return encoder.encode(raw);
    }

    public boolean matches(String raw, String hash) {
        if (raw == null || hash == null) {
            return false;
        }
        try {
            return encoder.matches(raw, hash);
        } catch (Exception e) {
            return false;
        }
    }

    public void validateStrength(String password) {
        if (password == null || password.length() < 8) {
            throw ApiException.badRequest("密码长度至少为 8 位");
        }
        if (password.length() > 128) {
            throw ApiException.badRequest("密码长度不能超过 128 位");
        }
        if (!LETTER.matcher(password).find() || !DIGIT.matcher(password).find()) {
            throw ApiException.badRequest("密码必须同时包含字母和数字");
        }
    }
}
