package com.platform.user.common;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 请求体访问器。HTTP 层统一接收 Map<String,Object>，内部再做类型收敛与校验。
 */
public final class Body {
    private final Map<String, Object> map;

    private Body(Map<String, Object> map) {
        this.map = map == null ? new LinkedHashMap<>() : map;
    }

    public static Body of(Object raw) {
        return new Body(Json.readMap(raw));
    }

    public static Body of(Map<String, Object> raw) {
        return new Body(raw);
    }

    public Map<String, Object> map() {
        return map;
    }

    public boolean has(String key) {
        return map.containsKey(key);
    }

    public Object raw(String key) {
        return map.get(key);
    }

    public String str(String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value);
        return text.isEmpty() ? null : text;
    }

    public String trimmed(String key) {
        String value = str(key);
        return value == null ? null : value.trim();
    }

    public String required(String key, String label) {
        String value = trimmed(key);
        if (value == null || value.isBlank()) {
            throw ApiException.validation(key, label + "不能为空");
        }
        return value;
    }

    public String str(String key, String fallback) {
        String value = str(key);
        return value == null ? fallback : value;
    }

    public Integer integer(String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Number n) {
            return n.intValue();
        }
        try {
            return Integer.parseInt(String.valueOf(value).trim());
        } catch (NumberFormatException e) {
            throw ApiException.validation(key, "必须为整数");
        }
    }

    public int integer(String key, int fallback) {
        Integer value = integer(key);
        return value == null ? fallback : value;
    }

    public Boolean bool(String key) {
        Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (value instanceof Boolean b) {
            return b;
        }
        String text = String.valueOf(value).trim();
        if ("true".equalsIgnoreCase(text) || "1".equals(text)) {
            return true;
        }
        if ("false".equalsIgnoreCase(text) || "0".equals(text)) {
            return false;
        }
        throw ApiException.validation(key, "必须为布尔值");
    }

    public boolean bool(String key, boolean fallback) {
        Boolean value = bool(key);
        return value == null ? fallback : value;
    }

    public java.util.UUID uuid(String key) {
        String value = trimmed(key);
        if (value == null) {
            return null;
        }
        java.util.UUID id = Ids.parse(value);
        if (id == null) {
            throw ApiException.validation(key, "ID 格式不合法");
        }
        return id;
    }

    public java.util.UUID requiredUuid(String key, String label) {
        java.util.UUID id = uuid(key);
        if (id == null) {
            throw ApiException.validation(key, label + "不能为空");
        }
        return id;
    }

    public List<Object> list(String key) {
        Object value = map.get(key);
        if (value instanceof List<?> list) {
            return new ArrayList<>(list);
        }
        return new ArrayList<>();
    }

    public List<String> strings(String key) {
        List<String> out = new ArrayList<>();
        for (Object value : list(key)) {
            if (value != null) {
                out.add(String.valueOf(value));
            }
        }
        return out;
    }

    public List<java.util.UUID> uuids(String key) {
        List<java.util.UUID> out = new ArrayList<>();
        for (Object value : list(key)) {
            java.util.UUID id = Ids.parse(value == null ? null : String.valueOf(value));
            if (id == null) {
                throw ApiException.validation(key, "ID 列表格式不合法");
            }
            out.add(id);
        }
        return out;
    }

    public Map<String, Object> map(String key) {
        Object value = map.get(key);
        if (value instanceof Map<?, ?>) {
            return Json.readMap(value);
        }
        return new LinkedHashMap<>();
    }
}
