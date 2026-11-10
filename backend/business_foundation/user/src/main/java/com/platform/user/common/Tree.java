package com.platform.user.common;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class Tree {
    private Tree() {
    }

    public static List<Map<String, Object>> build(List<Map<String, Object>> rows, String idKey, String parentKey) {
        Map<String, Map<String, Object>> index = new HashMap<>();
        List<Map<String, Object>> roots = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            Map<String, Object> copy = new LinkedHashMap<>(row);
            copy.put("children", new ArrayList<Map<String, Object>>());
            index.put(String.valueOf(copy.get(idKey)), copy);
        }
        for (Map<String, Object> row : rows) {
            Object parent = row.get(parentKey);
            Map<String, Object> node = index.get(String.valueOf(row.get(idKey)));
            if (parent != null && index.containsKey(String.valueOf(parent))) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> children =
                        (List<Map<String, Object>>) index.get(String.valueOf(parent)).get("children");
                children.add(node);
            } else {
                roots.add(node);
            }
        }
        return roots;
    }
}
