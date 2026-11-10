package com.platform.user.common;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * 简单的 RFC4180 CSV 解析/生成，支持引号、转义双引号、CRLF 与 BOM。
 */
public final class Csv {
    private Csv() {
    }

    public static List<Map<String, String>> parse(String content) {
        if (content == null || content.isBlank()) {
            return new ArrayList<>();
        }
        String text = content;
        if (!text.isEmpty() && text.charAt(0) == '\uFEFF') {
            text = text.substring(1);
        }
        List<List<String>> rows = readRows(text);
        if (rows.isEmpty()) {
            return new ArrayList<>();
        }
        List<String> header = rows.getFirst();
        List<Map<String, String>> out = new ArrayList<>();
        for (int i = 1; i < rows.size(); i++) {
            List<String> row = rows.get(i);
            if (row.stream().allMatch(v -> v == null || v.isBlank())) {
                continue;
            }
            Map<String, String> item = new LinkedHashMap<>();
            for (int c = 0; c < header.size(); c++) {
                String key = header.get(c).trim().toLowerCase(Locale.ROOT);
                if (key.isEmpty()) {
                    continue;
                }
                item.put(key, c < row.size() ? row.get(c) : null);
            }
            out.add(item);
        }
        return out;
    }

    public static List<List<String>> readRows(String text) {
        List<List<String>> rows = new ArrayList<>();
        List<String> row = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (quoted) {
                if (c == '"') {
                    if (i + 1 < text.length() && text.charAt(i + 1) == '"') {
                        field.append('"');
                        i++;
                    } else {
                        quoted = false;
                    }
                } else {
                    field.append(c);
                }
                continue;
            }
            if (c == '"') {
                quoted = true;
            } else if (c == ',') {
                row.add(field.toString());
                field.setLength(0);
            } else if (c == '\n' || c == '\r') {
                if (c == '\r' && i + 1 < text.length() && text.charAt(i + 1) == '\n') {
                    i++;
                }
                row.add(field.toString());
                field.setLength(0);
                rows.add(row);
                row = new ArrayList<>();
            } else {
                field.append(c);
            }
        }
        if (field.length() > 0 || !row.isEmpty()) {
            row.add(field.toString());
            rows.add(row);
        }
        return rows;
    }

    public static String line(List<Object> values) {
        List<String> cells = new ArrayList<>();
        for (Object value : values) {
            cells.add(escape(value == null ? "" : String.valueOf(value)));
        }
        return String.join(",", cells);
    }

    public static String escape(String value) {
        boolean needsQuote = value.indexOf(',') >= 0 || value.indexOf('"') >= 0
                || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0
                || (!value.isEmpty() && (value.charAt(0) == '=' || value.charAt(0) == '+' || value.charAt(0) == '-'));
        String escaped = value.replace("\"", "\"\"");
        return needsQuote ? "\"" + escaped + "\"" : escaped;
    }
}
