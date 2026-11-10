package com.platform.user.service;

import com.platform.user.bootstrap.OutboxService;
import com.platform.user.common.ApiException;
import com.platform.user.common.Body;
import com.platform.user.common.Db;
import com.platform.user.common.Ids;
import com.platform.user.common.Json;
import com.platform.user.common.PageQuery;
import com.platform.user.common.RequestMeta;
import com.platform.user.common.Text;
import com.platform.user.common.Times;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

@Service
public class AttributeService {
    private static final List<String> DATA_TYPES = List.of("string", "number", "boolean", "date", "enum", "array");
    private static final Pattern CODE = Pattern.compile("^[A-Za-z][A-Za-z0-9_.-]{0,63}$");

    private final Db db;
    private final AuditService audit;
    private final OutboxService outbox;

    public AttributeService(Db db, AuditService audit, OutboxService outbox) {
        this.db = db;
        this.audit = audit;
        this.outbox = outbox;
    }

    public Map<String, Object> listDefinitions(UUID tenantId, Map<String, String> query) {
        PageQuery page = PageQuery.parse(query.get("page"), query.get("page_size"));
        StringBuilder where = new StringBuilder(" WHERE tenant_id = :tenant AND deleted_at IS NULL");
        Map<String, Object> params = new LinkedHashMap<>();
        params.put("tenant", tenantId);
        String status = blank(query.get("status"));
        if (status != null) {
            where.append(" AND status = :status");
            params.put("status", status);
        }
        String keyword = blank(query.get("keyword"));
        if (keyword != null) {
            where.append(" AND (name ILIKE :kw ESCAPE '\\' OR code ILIKE :kw ESCAPE '\\')");
            params.put("kw", Text.likePattern(keyword));
        }
        long total = db.count("SELECT count(*) FROM user_attributes" + where, params);
        Map<String, Object> pageParams = new LinkedHashMap<>(params);
        pageParams.put("limit", page.limit());
        pageParams.put("offset", page.offset());
        List<Map<String, Object>> items = db.list("SELECT * FROM user_attributes" + where
                + " ORDER BY sort_order, created_at LIMIT :limit OFFSET :offset", pageParams);
        return Db.page(items, total, page.page(), page.pageSize());
    }

    public Map<String, Object> getDefinition(UUID tenantId, UUID id) {
        return db.one("""
                SELECT * FROM user_attributes
                WHERE tenant_id = :tenant AND id = :id AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "id", id));
    }

    public Map<String, Object> createDefinition(UUID tenantId, Body input, UUID actorId, RequestMeta meta) {
        String code = input.required("code", "编码");
        if (!CODE.matcher(code).matches()) {
            throw ApiException.validation("code", "编码需以字母开头，仅含字母、数字、点、下划线或中划线");
        }
        String name = input.required("name", "名称");
        String dataType = input.str("data_type", "string").toLowerCase();
        validateDataType(dataType);
        Map<String, Object> validation = input.map("validation");
        validateRules(validation);
        List<Object> options = input.list("options");
        boolean required = input.bool("required", false);
        String status = input.str("status", "active");
        if (!List.of("active", "disabled").contains(status)) {
            throw ApiException.validation("status", "状态值不合法");
        }
        if (db.count("""
                SELECT count(*) FROM user_attributes
                WHERE tenant_id = :tenant AND lower(code) = lower(:code) AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "code", code)) > 0) {
            throw ApiException.conflict("属性编码已存在");
        }
        UUID id = Ids.uuidValue();
        db.update("""
                INSERT INTO user_attributes
                    (id, tenant_id, code, name, description, data_type, required, default_value, options,
                     validation, user_type, sort_order, status)
                VALUES
                    (:id, :tenant, :code, :name, :description, :dtype, :required, :default, :options,
                     :validation, :utype, :sort, :status)
                """, Db.params("id", id, "tenant", tenantId, "code", code, "name", name,
                "description", input.trimmed("description"), "dtype", dataType, "required", required,
                "default", input.has("default_value") ? Json.jsonb(input.raw("default_value")) : null,
                "options", Json.jsonb(options), "validation", Json.jsonb(validation),
                "utype", input.trimmed("user_type"), "sort", input.integer("sort_order", 0), "status", status));
        audit.success(tenantId, actorId, "attribute.create", "attribute", id.toString(), meta, Map.of("code", code));
        return getDefinition(tenantId, id);
    }

    public Map<String, Object> updateDefinition(UUID tenantId, UUID id, Body input, UUID actorId, RequestMeta meta) {
        Map<String, Object> current = getDefinition(tenantId, id);
        String code = input.has("code") ? input.required("code", "编码") : String.valueOf(current.get("code"));
        if (!CODE.matcher(code).matches()) {
            throw ApiException.validation("code", "编码格式不合法");
        }
        String name = input.has("name") ? input.required("name", "名称") : String.valueOf(current.get("name"));
        String dataType = input.has("data_type") ? input.str("data_type", "string").toLowerCase()
                : String.valueOf(current.get("data_type"));
        validateDataType(dataType);
        Map<String, Object> validation = input.has("validation") ? input.map("validation")
                : Json.readMap(current.get("validation"));
        validateRules(validation);
        List<Object> options = input.has("options") ? input.list("options")
                : Json.readList(Json.write(current.get("options")));
        boolean required = input.has("required") ? input.bool("required", false)
                : Boolean.TRUE.equals(current.get("required"))
                || "true".equalsIgnoreCase(String.valueOf(current.get("required")));
        String status = input.has("status") ? input.str("status", "active") : String.valueOf(current.get("status"));
        if (!List.of("active", "disabled").contains(status)) {
            throw ApiException.validation("status", "状态值不合法");
        }
        if (db.count("""
                SELECT count(*) FROM user_attributes
                WHERE tenant_id = :tenant AND lower(code) = lower(:code) AND id <> :id AND deleted_at IS NULL
                """, Db.params("tenant", tenantId, "code", code, "id", id)) > 0) {
            throw ApiException.conflict("属性编码已存在");
        }
        Object defaultValue = input.has("default_value") ? Json.jsonb(input.raw("default_value"))
                : current.get("default_value") == null ? null : Json.jsonb(current.get("default_value"));
        db.update("""
                UPDATE user_attributes
                SET code = :code, name = :name, description = :description, data_type = :dtype,
                    required = :required, default_value = :default, options = :options,
                    validation = :validation, user_type = :utype, sort_order = :sort, status = :status,
                    updated_at = now()
                WHERE tenant_id = :tenant AND id = :id AND deleted_at IS NULL
                """, Db.params("code", code, "name", name,
                "description", input.has("description") ? input.trimmed("description") : current.get("description"),
                "dtype", dataType, "required", required, "default", defaultValue,
                "options", Json.jsonb(options), "validation", Json.jsonb(validation),
                "utype", input.has("user_type") ? input.trimmed("user_type") : current.get("user_type"),
                "sort", input.has("sort_order") ? input.integer("sort_order", 0)
                        : ((Number) current.getOrDefault("sort_order", 0)).intValue(),
                "status", status, "tenant", tenantId, "id", id));
        audit.success(tenantId, actorId, "attribute.update", "attribute", id.toString(), meta, Map.of("code", code));
        return getDefinition(tenantId, id);
    }

    public void deleteDefinition(UUID tenantId, UUID id, UUID actorId, RequestMeta meta) {
        getDefinition(tenantId, id);
        db.inTx(() -> {
            db.update("DELETE FROM user_attribute_values WHERE tenant_id = :tenant AND attribute_id = :id",
                    Db.params("tenant", tenantId, "id", id));
            db.update("""
                    UPDATE user_attributes SET deleted_at = now(), updated_at = now()
                    WHERE tenant_id = :tenant AND id = :id
                    """, Db.params("tenant", tenantId, "id", id));
        });
        audit.success(tenantId, actorId, "attribute.delete", "attribute", id.toString(), meta, Map.of());
    }

    public List<Map<String, Object>> listValues(UUID tenantId, UUID userId) {
        return db.list("""
                SELECT a.id AS attribute_id, a.code, a.name, a.data_type, a.required, a.options, a.validation,
                       COALESCE(v.value, a.default_value) AS value, v.updated_at
                FROM user_attributes a
                LEFT JOIN user_attribute_values v ON v.attribute_id = a.id AND v.user_id = :user
                WHERE a.tenant_id = :tenant AND a.deleted_at IS NULL AND a.status = 'active'
                ORDER BY a.sort_order, a.code
                """, Db.params("tenant", tenantId, "user", userId));
    }

    public List<Map<String, Object>> setValues(UUID tenantId, UUID userId, Map<String, Object> values,
                                                UUID actorId, RequestMeta meta) {
        List<Map<String, Object>> definitions = db.list("""
                SELECT * FROM user_attributes WHERE tenant_id = :tenant AND deleted_at IS NULL
                """, Db.params("tenant", tenantId));
        Map<String, Map<String, Object>> byCode = new LinkedHashMap<>();
        for (Map<String, Object> definition : definitions) {
            byCode.put(String.valueOf(definition.get("code")).toLowerCase(), definition);
        }
        Map<String, Object> normalized = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : values.entrySet()) {
            Map<String, Object> definition = byCode.get(entry.getKey().toLowerCase());
            if (definition == null) {
                throw ApiException.validation("values", "未知属性: " + entry.getKey());
            }
            if ("disabled".equals(String.valueOf(definition.get("status")))) {
                throw ApiException.validation(entry.getKey(), "属性已停用");
            }
            if (entry.getValue() != null) {
                validateValue(definition, entry.getValue());
                normalized.put(String.valueOf(definition.get("code")), entry.getValue());
            }
        }
        for (Map<String, Object> definition : definitions) {
            if (!bool(definition.get("required")) || !"active".equals(String.valueOf(definition.get("status")))) {
                continue;
            }
            String code = String.valueOf(definition.get("code"));
            if (!normalized.containsKey(code) && definition.get("default_value") == null) {
                throw ApiException.validation(code, "必填属性不能为空");
            }
        }
        db.inTx(() -> {
            db.update("DELETE FROM user_attribute_values WHERE tenant_id = :tenant AND user_id = :user",
                    Db.params("tenant", tenantId, "user", userId));
            for (Map.Entry<String, Object> entry : normalized.entrySet()) {
                Map<String, Object> definition = byCode.get(entry.getKey().toLowerCase());
                db.update("""
                        INSERT INTO user_attribute_values (user_id, attribute_id, tenant_id, value)
                        VALUES (:user, :attribute, :tenant, :value)
                        """, Db.params("user", userId, "attribute", definition.get("id"), "tenant", tenantId,
                        "value", Json.jsonb(entry.getValue())));
            }
        });
        audit.success(tenantId, actorId, "user.attributes_update", "user", userId.toString(), meta,
                Map.of("codes", new ArrayList<>(normalized.keySet())));
        outbox.publish("user.updated", "user", userId.toString(),
                Map.of("identity_id", userId.toString(), "tenant_id", tenantId.toString(), "fields", List.of("attributes")));
        return listValues(tenantId, userId);
    }

    public static void validateValue(Map<String, Object> definition, Object value) {
        String code = String.valueOf(definition.get("code"));
        String dataType = String.valueOf(definition.get("data_type"));
        Map<String, Object> rules = Json.readMap(definition.get("validation"));
        switch (dataType) {
            case "string" -> {
                if (!(value instanceof String text)) {
                    throw ApiException.validation(code, "必须为字符串");
                }
                checkLength(code, text, rules);
            }
            case "number" -> {
                double number;
                if (value instanceof Number n) {
                    number = n.doubleValue();
                } else {
                    try {
                        number = Double.parseDouble(String.valueOf(value));
                    } catch (NumberFormatException e) {
                        throw ApiException.validation(code, "必须为数字");
                    }
                }
                Double min = number(rules.get("min"));
                Double max = number(rules.get("max"));
                if (min != null && number < min) {
                    throw ApiException.validation(code, "不能小于 " + min);
                }
                if (max != null && number > max) {
                    throw ApiException.validation(code, "不能大于 " + max);
                }
            }
            case "boolean" -> {
                if (!(value instanceof Boolean)
                        && !"true".equalsIgnoreCase(String.valueOf(value))
                        && !"false".equalsIgnoreCase(String.valueOf(value))) {
                    throw ApiException.validation(code, "必须为布尔值");
                }
            }
            case "date" -> {
                try {
                    LocalDate.parse(String.valueOf(value));
                } catch (Exception e) {
                    throw ApiException.validation(code, "必须为 YYYY-MM-DD 日期");
                }
            }
            case "enum" -> {
                List<Object> options = Json.readList(Json.write(definition.get("options")));
                String text = String.valueOf(value);
                boolean matched = options.stream().anyMatch(option -> {
                    if (option instanceof Map<?, ?> map) {
                        Object optionValue = map.get("value");
                        return optionValue != null && String.valueOf(optionValue).equals(text);
                    }
                    return String.valueOf(option).equals(text);
                });
                if (!matched) {
                    throw ApiException.validation(code, "值不在可选范围内");
                }
            }
            case "array" -> {
                if (!(value instanceof List<?> list)) {
                    throw ApiException.validation(code, "必须为数组");
                }
                Double maxItems = number(rules.get("max_items"));
                Double minItems = number(rules.get("min_items"));
                if (maxItems != null && list.size() > maxItems) {
                    throw ApiException.validation(code, "数组元素过多");
                }
                if (minItems != null && list.size() < minItems) {
                    throw ApiException.validation(code, "数组元素过少");
                }
            }
            default -> throw ApiException.validation(code, "不支持的属性类型");
        }
    }

    private static void checkLength(String code, String text, Map<String, Object> rules) {
        Double minLength = number(rules.get("min_length"));
        Double maxLength = number(rules.get("max_length"));
        if (minLength != null && text.length() < minLength) {
            throw ApiException.validation(code, "长度不能小于 " + minLength.intValue());
        }
        if (maxLength != null && text.length() > maxLength) {
            throw ApiException.validation(code, "长度不能大于 " + maxLength.intValue());
        }
        Object pattern = rules.get("pattern");
        if (pattern != null && !String.valueOf(pattern).isBlank()) {
            try {
                if (!Pattern.compile(String.valueOf(pattern)).matcher(text).matches()) {
                    throw ApiException.validation(code, "格式不匹配");
                }
            } catch (PatternSyntaxException e) {
                throw ApiException.validation(code, "校验正则表达式无效");
            }
        }
    }

    private static Double number(Object value) {
        if (value == null) {
            return null;
        }
        if (value instanceof Number n) {
            return n.doubleValue();
        }
        try {
            return Double.parseDouble(String.valueOf(value));
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static void validateDataType(String dataType) {
        if (!DATA_TYPES.contains(dataType)) {
            throw ApiException.validation("data_type", "不支持的数据类型");
        }
    }

    private static void validateRules(Map<String, Object> rules) {
        Object pattern = rules.get("pattern");
        if (pattern != null && !String.valueOf(pattern).isBlank()) {
            try {
                Pattern.compile(String.valueOf(pattern));
            } catch (PatternSyntaxException e) {
                throw ApiException.validation("validation.pattern", "正则表达式无效");
            }
        }
    }

    private static boolean bool(Object value) {
        return Boolean.TRUE.equals(value) || "true".equalsIgnoreCase(String.valueOf(value));
    }

    private static String blank(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
