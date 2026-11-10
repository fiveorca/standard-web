package com.platform.file.shared;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.postgresql.util.PGobject;

import java.sql.Timestamp;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 内部 JSON 统一使用 Jackson 2；HTTP 层只收发 DTO/Map，JSONB 使用字符串加 SQL 转换。
 */
public final class Json {
    public static final ObjectMapper M = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            .setSerializationInclusion(JsonInclude.Include.ALWAYS);

    private Json() {
    }

    public static String write(Object value) {
        try {
            return M.writeValueAsString(value);
        } catch (Exception e) {
            throw new ApiException(500, "internal_error", "无法序列化 JSON 数据");
        }
    }

    public static Object read(String value) {
        try {
            return M.readValue(value, Object.class);
        } catch (Exception e) {
            return value;
        }
    }

    public static Map<String, Object> readMap(String value) {
        Object parsed = read(value);
        if (parsed instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            map.forEach((k, v) -> out.put(String.valueOf(k), v));
            return out;
        }
        return new LinkedHashMap<>();
    }

    public static Map<String, Object> readMap(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            map.forEach((k, v) -> out.put(String.valueOf(k), v));
            return out;
        }
        if (value == null) {
            return new LinkedHashMap<>();
        }
        return readMap(String.valueOf(value));
    }

    public static List<Object> readList(String value) {
        Object parsed = read(value);
        if (parsed instanceof List<?> list) {
            return new ArrayList<>(list);
        }
        return new ArrayList<>();
    }

    public static Object normalize(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof PGobject pg) {
            String raw = pg.getValue();
            return raw == null ? null : read(raw);
        }
        if (value instanceof Timestamp ts) {
            return ts.toInstant().toString();
        }
        if (value instanceof OffsetDateTime odt) {
            return odt.toInstant().toString();
        }
        if (value instanceof java.sql.Date d) {
            return d.toString();
        }
        if (value instanceof java.util.UUID u) {
            return u.toString();
        }
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> out = new LinkedHashMap<>();
            map.forEach((k, v) -> out.put(String.valueOf(k), normalize(v)));
            return out;
        }
        if (value instanceof List<?> list) {
            List<Object> out = new ArrayList<>(list.size());
            list.forEach(v -> out.add(normalize(v)));
            return out;
        }
        return value;
    }

    public static Map<String, Object> normalizeRow(Map<String, Object> row) {
        Map<String, Object> out = new LinkedHashMap<>();
        row.forEach((k, v) -> out.put(k, normalize(v)));
        return out;
    }
}
