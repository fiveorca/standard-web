package com.platform.file.shared;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

@Component
public class Db {
    private final NamedParameterJdbcTemplate named;
    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;

    public Db(NamedParameterJdbcTemplate named, JdbcTemplate jdbc, TransactionTemplate tx) {
        this.named = named;
        this.jdbc = jdbc;
        this.tx = tx;
    }

    public List<Map<String, Object>> list(String sql, Map<String, ?> params) {
        return named.queryForList(sql, normalize(params)).stream().map(Json::normalizeRow).toList();
    }

    public List<Map<String, Object>> list(String sql) {
        return list(sql, Map.of());
    }

    public Optional<Map<String, Object>> find(String sql, Map<String, ?> params) {
        List<Map<String, Object>> rows = list(sql, params);
        return rows.isEmpty() ? Optional.empty() : Optional.of(rows.getFirst());
    }

    public Map<String, Object> one(String sql, Map<String, ?> params) {
        return find(sql, params).orElseThrow(() -> ApiException.notFound("记录不存在"));
    }

    public int update(String sql, Map<String, ?> params) {
        return named.update(sql, normalize(params));
    }

    public long count(String sql, Map<String, ?> params) {
        Map<String, Object> row = named.queryForMap(sql, normalize(params));
        Object value = row.values().iterator().next();
        return value == null ? 0 : ((Number) value).longValue();
    }

    public <T> T inTx(Supplier<T> work) {
        return tx.execute(status -> work.get());
    }

    public void inTx(Runnable work) {
        tx.executeWithoutResult(status -> work.run());
    }

    public boolean ping() {
        Integer value = jdbc.queryForObject("SELECT 1", Integer.class);
        return value != null && value == 1;
    }

    public JdbcTemplate jdbc() {
        return jdbc;
    }

    public static Map<String, Object> params(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) {
            out.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return out;
    }

    private static Map<String, Object> normalize(Map<String, ?> params) {
        if (params == null || params.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> out = new LinkedHashMap<>(params.size());
        params.forEach((key, value) -> out.put(key, normalizeValue(value)));
        return out;
    }

    private static Object normalizeValue(Object value) {
        if (value instanceof Instant instant) {
            return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC);
        }
        if (value instanceof Duration duration) {
            return duration.toMillis();
        }
        if (value instanceof Enum<?> enumValue) {
            return enumValue.name();
        }
        return value;
    }

    public static Map<String, Object> page(List<Map<String, Object>> items, long total, int page, int size) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("items", items);
        out.put("total", total);
        out.put("page", page);
        out.put("page_size", size);
        return out;
    }
}
