package com.platform.user.common;

import java.util.Locale;
import java.util.regex.Pattern;

public final class Text {
    private static final Pattern EMAIL = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern PHONE = Pattern.compile("^\\+?[0-9]{6,20}$");
    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$");

    private Text() {
    }

    public static String trim(String value) {
        return value == null ? null : value.trim();
    }

    public static String blankToNull(String value) {
        String trimmed = trim(value);
        return trimmed == null || trimmed.isEmpty() ? null : trimmed;
    }

    public static String normalizeEmail(String email) {
        String value = blankToNull(email);
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }

    public static String normalizePhone(String phone) {
        String value = blankToNull(phone);
        if (value == null) {
            return null;
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c >= '0' && c <= '9') {
                out.append(c);
            } else if (c == '+' && out.length() == 0) {
                out.append('+');
            }
        }
        return out.length() == 0 ? null : out.toString();
    }

    public static String normalizeUsername(String username) {
        String value = blankToNull(username);
        return value == null ? null : value.toLowerCase(Locale.ROOT);
    }

    public static boolean validEmail(String email) {
        return email != null && email.length() <= 254 && EMAIL.matcher(email).matches();
    }

    public static boolean validPhone(String phone) {
        return phone != null && PHONE.matcher(phone).matches();
    }

    public static boolean validUsername(String username) {
        return username != null && USERNAME.matcher(username).matches();
    }

    public static String requireEmail(String email, String field) {
        String normalized = normalizeEmail(email);
        if (!validEmail(normalized)) {
            throw ApiException.validation(field, "邮箱格式不合法");
        }
        return normalized;
    }

    public static String requirePhone(String phone, String field) {
        String normalized = normalizePhone(phone);
        if (!validPhone(normalized)) {
            throw ApiException.validation(field, "手机号格式不合法");
        }
        return normalized;
    }

    public static String requireUsername(String username, String field) {
        String normalized = normalizeUsername(username);
        if (!validUsername(normalized)) {
            throw ApiException.validation(field, "用户名需为 3-64 位字母、数字、点、下划线或中划线");
        }
        return normalized;
    }

    public static String maskEmail(String email) {
        if (email == null || email.isBlank()) {
            return email;
        }
        int at = email.indexOf('@');
        if (at <= 0) {
            return "***";
        }
        String local = email.substring(0, at);
        String domain = email.substring(at);
        if (local.length() <= 2) {
            return local.charAt(0) + "***" + domain;
        }
        return local.charAt(0) + "***" + local.charAt(local.length() - 1) + domain;
    }

    public static String maskPhone(String phone) {
        if (phone == null || phone.length() < 7) {
            return phone;
        }
        return phone.substring(0, 3) + "****" + phone.substring(phone.length() - 4);
    }

    public static String likePattern(String keyword) {
        String escaped = keyword.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
        return "%" + escaped + "%";
    }

    public static String limit(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
