package com.platform.auth.common;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public final class Cookies {
    private Cookies() {}

    public static String read(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (name.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    public static void write(HttpServletResponse response, String name, String value, long maxAge, boolean secure, String domain) {
        Cookie cookie = new Cookie(name, value);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        cookie.setMaxAge((int) Math.max(0, Math.min(Integer.MAX_VALUE, maxAge)));
        if (domain != null && !domain.isBlank()) {
            cookie.setDomain(domain);
        }
        response.addCookie(cookie);
    }

    public static void clear(HttpServletResponse response, String name, boolean secure, String domain) {
        write(response, name, "", 0, secure, domain);
    }
}
