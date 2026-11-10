package com.platform.file.shared;

import com.platform.file.config.AppProperties;

import java.util.Arrays;
import java.util.Locale;
import java.util.Map;

public final class ContentTypes {
    private static final Map<String, String> BY_EXTENSION = Map.ofEntries(
            Map.entry("jpg", "image/jpeg"), Map.entry("jpeg", "image/jpeg"),
            Map.entry("png", "image/png"), Map.entry("gif", "image/gif"),
            Map.entry("webp", "image/webp"), Map.entry("bmp", "image/bmp"),
            Map.entry("pdf", "application/pdf"), Map.entry("txt", "text/plain"),
            Map.entry("csv", "text/csv"), Map.entry("json", "application/json"),
            Map.entry("xml", "application/xml"), Map.entry("zip", "application/zip"),
            Map.entry("gz", "application/gzip"), Map.entry("mp4", "video/mp4"),
            Map.entry("webm", "video/webm"), Map.entry("mp3", "audio/mpeg"),
            Map.entry("ogg", "audio/ogg"), Map.entry("wav", "audio/wav"),
            Map.entry("doc", "application/msword"),
            Map.entry("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
            Map.entry("xls", "application/vnd.ms-excel"),
            Map.entry("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
            Map.entry("ppt", "application/vnd.ms-powerpoint"),
            Map.entry("pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"));

    private ContentTypes() {
    }

    public static String normalize(String mime) {
        if (mime == null || mime.isBlank()) {
            return null;
        }
        String value = mime.toLowerCase(Locale.ROOT).trim();
        int semicolon = value.indexOf(';');
        if (semicolon >= 0) {
            value = value.substring(0, semicolon).trim();
        }
        return value;
    }

    public static String guess(String filename) {
        return BY_EXTENSION.get(Names.extension(filename));
    }

    public static String validate(String filename, String declared, byte[] head, AppProperties.Security config) {
        String extension = Names.extension(filename);
        String allowedExtensions = config.allowedExtensions;
        if (allowedExtensions != null && !allowedExtensions.isBlank()
                && !Arrays.stream(allowedExtensions.split(","))
                .map(s -> s.trim().toLowerCase(Locale.ROOT))
                .filter(s -> !s.isEmpty())
                .toList()
                .contains(extension)) {
            throw ApiException.unsupportedMedia("不允许的文件扩展名: " + (extension.isEmpty() ? "(无)" : extension));
        }

        String mime = normalize(declared);
        if (mime == null || "application/octet-stream".equals(mime)) {
            mime = guess(filename);
        }
        if (mime == null) {
            mime = "application/octet-stream";
        }

        String allowedMimes = config.allowedMimeTypes;
        if (allowedMimes != null && !allowedMimes.isBlank() && !matchesAny(mime, allowedMimes)) {
            throw ApiException.unsupportedMedia("不允许的 MIME 类型: " + mime);
        }

        if (config.sniffContent && head != null && head.length > 0) {
            String detected = detect(head);
            if (detected != null && !compatible(detected, mime)) {
                throw ApiException.unsupportedMedia("文件内容与声明的 MIME 类型不一致: 声明 " + mime + "，实际 " + detected);
            }
        }
        return mime;
    }

    private static boolean matchesAny(String mime, String patterns) {
        for (String raw : patterns.split(",")) {
            String pattern = raw.trim().toLowerCase(Locale.ROOT);
            if (pattern.isEmpty()) {
                continue;
            }
            if (pattern.equals("*") || pattern.equals("*/*") || pattern.equals(mime)) {
                return true;
            }
            if (pattern.endsWith("/*")) {
                if (mime.startsWith(pattern.substring(0, pattern.length() - 1))) {
                    return true;
                }
            } else if (pattern.endsWith(".*")) {
                String prefix = pattern.substring(0, pattern.length() - 1);
                if (mime.startsWith(prefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean compatible(String detected, String declared) {
        if (detected.equals(declared)) {
            return true;
        }
        String detectedFamily = family(detected);
        String declaredFamily = family(declared);
        if (detectedFamily != null && detectedFamily.equals(declaredFamily)) {
            return true;
        }
        // Office Open XML 文件本质上是 ZIP 容器。
        if ("application/zip".equals(detected) && declared.startsWith("application/vnd.openxmlformats-officedocument.")) {
            return true;
        }
        // 文本类内容允许以 text/* 或 application/json / application/xml 声明。
        if ("text/plain".equals(detected)
                && ("application/json".equals(declared) || "application/xml".equals(declared))) {
            return true;
        }
        return false;
    }

    private static String family(String mime) {
        int slash = mime.indexOf('/');
        return slash > 0 ? mime.substring(0, slash) : null;
    }

    public static String detect(byte[] b) {
        if (b.length >= 4 && (b[0] & 0xFF) == 0x89 && b[1] == 'P' && b[2] == 'N' && b[3] == 'G') {
            return "image/png";
        }
        if (b.length >= 3 && (b[0] & 0xFF) == 0xFF && (b[1] & 0xFF) == 0xD8 && (b[2] & 0xFF) == 0xFF) {
            return "image/jpeg";
        }
        if (b.length >= 4 && b[0] == 'G' && b[1] == 'I' && b[2] == 'F' && b[3] == '8') {
            return "image/gif";
        }
        if (b.length >= 2 && b[0] == 'B' && b[1] == 'M') {
            return "image/bmp";
        }
        if (b.length >= 12 && b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F'
                && b[8] == 'W' && b[9] == 'E' && b[10] == 'B' && b[11] == 'P') {
            return "image/webp";
        }
        if (b.length >= 12 && b[0] == 'R' && b[1] == 'I' && b[2] == 'F' && b[3] == 'F'
                && b[8] == 'W' && b[9] == 'A' && b[10] == 'V' && b[11] == 'E') {
            return "audio/wav";
        }
        if (b.length >= 4 && b[0] == '%' && b[1] == 'P' && b[2] == 'D' && b[3] == 'F') {
            return "application/pdf";
        }
        if (b.length >= 4 && (b[0] & 0xFF) == 0x50 && (b[1] & 0xFF) == 0x4B
                && ((b[2] & 0xFF) == 0x03 || (b[2] & 0xFF) == 0x05)) {
            return "application/zip";
        }
        if (b.length >= 2 && (b[0] & 0xFF) == 0x1F && (b[1] & 0xFF) == 0x8B) {
            return "application/gzip";
        }
        if (b.length >= 8 && b[4] == 'f' && b[5] == 't' && b[6] == 'y' && b[7] == 'p') {
            return "video/mp4";
        }
        if (b.length >= 4 && (b[0] & 0xFF) == 0x1A && (b[1] & 0xFF) == 0x45
                && (b[2] & 0xFF) == 0xDF && (b[3] & 0xFF) == 0xA3) {
            return "video/webm";
        }
        if (b.length >= 4 && b[0] == 'O' && b[1] == 'g' && b[2] == 'g' && b[3] == 'S') {
            return "audio/ogg";
        }
        if (b.length >= 3 && b[0] == 'I' && b[1] == 'D' && b[2] == '3') {
            return "audio/mpeg";
        }
        boolean text = true;
        int printable = 0;
        for (byte value : b) {
            int c = value & 0xFF;
            if (c == 0) {
                text = false;
                break;
            }
            if (c >= 0x20 || c == 0x09 || c == 0x0A || c == 0x0D) {
                printable++;
            }
        }
        if (text && printable >= Math.max(1, b.length * 9 / 10)) {
            return "text/plain";
        }
        return null;
    }
}
