package com.platform.user.service;

import com.platform.user.common.ApiException;
import org.junit.jupiter.api.Test;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class AttributeServiceTest {

    private static Map<String, Object> definition(String code, String dataType, Map<String, Object> rules) {
        Map<String, Object> def = new LinkedHashMap<>();
        def.put("code", code);
        def.put("data_type", dataType);
        def.put("validation", rules);
        return def;
    }

    @Test
    void validatesStringLengthAndPattern() {
        Map<String, Object> rules = Map.of("min_length", 2, "max_length", 4, "pattern", "^[a-z]+$");
        Map<String, Object> def = definition("nickname", "string", rules);
        assertDoesNotThrow(() -> AttributeService.validateValue(def, "abc"));
        assertEquals(422, assertThrows(ApiException.class,
                () -> AttributeService.validateValue(def, "a")).status());
        assertEquals(422, assertThrows(ApiException.class,
                () -> AttributeService.validateValue(def, "ABCD")).status());
    }

    @Test
    void validatesNumberRange() {
        Map<String, Object> def = definition("age", "number", Map.of("min", 0, "max", 120));
        assertDoesNotThrow(() -> AttributeService.validateValue(def, 30));
        assertDoesNotThrow(() -> AttributeService.validateValue(def, "30"));
        assertEquals(422, assertThrows(ApiException.class,
                () -> AttributeService.validateValue(def, 121)).status());
        assertEquals(422, assertThrows(ApiException.class,
                () -> AttributeService.validateValue(def, "abc")).status());
    }

    @Test
    void validatesBooleanAndDate() {
        Map<String, Object> booleanDef = definition("vip", "boolean", Map.of());
        assertDoesNotThrow(() -> AttributeService.validateValue(booleanDef, true));
        assertDoesNotThrow(() -> AttributeService.validateValue(booleanDef, "TRUE"));
        assertEquals(422, assertThrows(ApiException.class,
                () -> AttributeService.validateValue(booleanDef, "yes")).status());

        Map<String, Object> dateDef = definition("birthday", "date", Map.of());
        assertDoesNotThrow(() -> AttributeService.validateValue(dateDef, "2024-02-29"));
        assertEquals(422, assertThrows(ApiException.class,
                () -> AttributeService.validateValue(dateDef, "2024-13-01")).status());
    }

    @Test
    void validatesEnumAndArray() {
        Map<String, Object> enumDef = definition("level", "enum", Map.of());
        enumDef.put("options", List.of("gold", "silver"));
        assertDoesNotThrow(() -> AttributeService.validateValue(enumDef, "gold"));
        assertEquals(422, assertThrows(ApiException.class,
                () -> AttributeService.validateValue(enumDef, "bronze")).status());

        Map<String, Object> arrayDef = definition("tags", "array", Map.of("max_items", 2));
        assertDoesNotThrow(() -> AttributeService.validateValue(arrayDef, List.of("a", "b")));
        assertEquals(422, assertThrows(ApiException.class,
                () -> AttributeService.validateValue(arrayDef, List.of("a", "b", "c"))).status());
    }

    @Test
    void rejectsUnsupportedDataType() {
        assertEquals(422, assertThrows(ApiException.class,
                () -> AttributeService.validateDataType("jsonb")).status());
        assertDoesNotThrow(() -> AttributeService.validateDataType("enum"));
    }
}
