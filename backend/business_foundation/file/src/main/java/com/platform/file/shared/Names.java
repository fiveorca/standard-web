package com.platform.file.shared;

import java.util.Locale;

public final class Names {
    private Names() {
    }

    public static String sanitize(String raw) {
        if (raw == null) {
            return "file";
        }
        String value = raw.replace('\\', '/');
        int slash = value.lastIndexOf('/');
        if (slash >= 0) {
            value = value.substring(slash + 1);
        }
        value = value.replaceAll("[\\p{Cntrl}]", "").trim();
        while (value.startsWith(".")) {
            value = value.substring(1);
        }
        if (value.isBlank()) {
            return "file";
        }
        if (value.length() > 255) {
            String ext = extension(value);
            String base = value.substring(0, 255 - (ext.isEmpty() ? 0 : ext.length() + 1));
            value = ext.isEmpty() ? base : base + "." + ext;
        }
        return value;
    }

    public static String extension(String filename) {
        if (filename == null) {
            return "";
        }
        int dot = filename.lastIndexOf('.');
        if (dot < 0 || dot == filename.length() - 1) {
            return "";
        }
        String ext = filename.substring(dot + 1).toLowerCase(Locale.ROOT);
        if (ext.length() > 16 || !ext.matches("[a-z0-9]+")) {
            return "";
        }
        return ext;
    }

    public static String displayName(String raw, String fallback) {
        String name = sanitize(raw);
        return name.isBlank() ? fallback : name;
    }
}
