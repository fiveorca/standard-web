package com.platform.user.common;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class StatusMachine {
    public static final String ACTIVE = "active";
    public static final String PENDING = "pending";
    public static final String DISABLED = "disabled";
    public static final String LOCKED = "locked";
    public static final String FROZEN = "frozen";
    public static final String DELETING = "deleting";
    public static final String DELETED = "deleted";

    public static final Set<String> STATUSES = Set.of(
            ACTIVE, PENDING, DISABLED, LOCKED, FROZEN, DELETING, DELETED);

    private static final Map<String, Set<String>> ALLOWED = build();

    private StatusMachine() {
    }

    private static Map<String, Set<String>> build() {
        Map<String, Set<String>> map = new LinkedHashMap<>();
        map.put(PENDING, Set.of(ACTIVE, DISABLED, DELETED));
        map.put(ACTIVE, Set.of(DISABLED, LOCKED, FROZEN, DELETING, DELETED));
        map.put(DISABLED, Set.of(ACTIVE, LOCKED, FROZEN, DELETING, DELETED));
        map.put(LOCKED, Set.of(ACTIVE, DISABLED, DELETING, DELETED));
        map.put(FROZEN, Set.of(ACTIVE, DISABLED, DELETING, DELETED));
        map.put(DELETING, Set.of(DELETED, ACTIVE));
        map.put(DELETED, Set.of(ACTIVE));
        return Map.copyOf(map);
    }

    public static void validateTarget(String status) {
        if (status == null || !STATUSES.contains(status)) {
            throw ApiException.validation("status", "状态值不合法");
        }
    }

    public static boolean canTransition(String from, String to) {
        if (from == null) {
            return STATUSES.contains(to);
        }
        if (from.equals(to)) {
            return true;
        }
        return ALLOWED.getOrDefault(from, Set.of()).contains(to);
    }

    public static void requireTransition(String from, String to) {
        validateTarget(to);
        if (!canTransition(from, to)) {
            throw ApiException.conflict("非法的状态转换: " + from + " -> " + to);
        }
    }

    public static List<String> statuses() {
        return List.copyOf(STATUSES);
    }
}
