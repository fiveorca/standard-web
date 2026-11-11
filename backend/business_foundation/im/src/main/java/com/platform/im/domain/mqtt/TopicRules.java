package com.platform.im.domain.mqtt;

import com.platform.im.shared.ApiException;

import java.util.Map;
import java.util.regex.Pattern;

/**
 * MQTT Topic 模板解析、通配符匹配与合法性校验。
 */
public final class TopicRules {
    private static final Pattern PLACEHOLDER = Pattern.compile("\\{([a-zA-Z0-9_]+)}");
    private static final Pattern DEVICE_ID = Pattern.compile("^[A-Za-z0-9._:-]{1,128}$");

    private TopicRules() {
    }

    public static String resolve(String template, Map<String, String> variables) {
        if (template == null || template.isBlank()) {
            throw ApiException.badRequest("Topic 模板不能为空");
        }
        var matcher = PLACEHOLDER.matcher(template);
        StringBuilder out = new StringBuilder();
        while (matcher.find()) {
            String key = matcher.group(1);
            String value = variables.get(key);
            if (value == null) {
                throw ApiException.internal("Topic 模板变量未提供: " + key);
            }
            matcher.appendReplacement(out, java.util.regex.Matcher.quoteReplacement(value));
        }
        matcher.appendTail(out);
        return out.toString();
    }

    public static void validateDeviceId(String deviceId) {
        if (deviceId == null || !DEVICE_ID.matcher(deviceId).matches()) {
            throw ApiException.validation("device_id", "仅允许字母、数字、点、下划线、冒号和连字符，长度 1-128");
        }
    }

    public static void validatePublishTopic(String topic) {
        if (topic == null || topic.isBlank() || topic.length() > 512) {
            throw ApiException.validation("topic", "Topic 不能为空且长度不能超过 512");
        }
        if (topic.indexOf('+') >= 0 || topic.indexOf('#') >= 0) {
            throw ApiException.validation("topic", "发布 Topic 不允许包含通配符");
        }
        if (topic.indexOf('\u0000') >= 0) {
            throw ApiException.validation("topic", "Topic 包含非法字符");
        }
    }

    public static void validateTopicPattern(String pattern) {
        if (pattern == null || pattern.isBlank() || pattern.length() > 512) {
            throw ApiException.validation("topic_pattern", "Topic 规则不能为空且长度不能超过 512");
        }
        String[] levels = pattern.split("/", -1);
        for (int i = 0; i < levels.length; i++) {
            String level = levels[i];
            if (level.contains("#") && !(level.equals("#") && i == levels.length - 1)) {
                throw ApiException.validation("topic_pattern", "# 只能作为最后一级且必须独占一级");
            }
            if (level.contains("+") && !level.equals("+")) {
                throw ApiException.validation("topic_pattern", "+ 必须独占一级");
            }
        }
    }

    /**
     * 标准 MQTT 通配符匹配。pattern 可以包含 + 与 #，topic 不允许包含通配符。
     */
    public static boolean matches(String pattern, String topic) {
        if (pattern == null || topic == null) {
            return false;
        }
        if (pattern.equals(topic)) {
            return true;
        }
        String[] p = pattern.split("/", -1);
        String[] t = topic.split("/", -1);
        int i = 0;
        for (; i < p.length; i++) {
            if ("#".equals(p[i])) {
                return true;
            }
            if (i >= t.length) {
                return false;
            }
            if ("+".equals(p[i])) {
                continue;
            }
            if (!p[i].equals(t[i])) {
                return false;
            }
        }
        return i == t.length;
    }

    /**
     * 判断已授权规则是否覆盖设备请求订阅的 Topic Filter。
     * 请求的 Filter 不能比授权规则更宽泛（例如授权 a/b 不允许订阅 a/+）。
     */
    public static boolean covers(String allowedPattern, String requestedFilter) {
        if (allowedPattern == null || requestedFilter == null) {
            return false;
        }
        if (allowedPattern.equals(requestedFilter)) {
            return true;
        }
        String[] allowed = allowedPattern.split("/", -1);
        String[] requested = requestedFilter.split("/", -1);
        for (int i = 0; i < allowed.length; i++) {
            if ("#".equals(allowed[i])) {
                return true;
            }
            if (i >= requested.length) {
                return false;
            }
            if ("#".equals(requested[i])) {
                return false;
            }
            if ("+".equals(allowed[i])) {
                continue;
            }
            if ("+".equals(requested[i])) {
                return false;
            }
            if (!allowed[i].equals(requested[i])) {
                return false;
            }
        }
        return allowed.length == requested.length;
    }

    public static int normalizeQos(Integer requested, int defaultValue, int maxAllowed) {
        int qos = requested == null ? defaultValue : requested;
        if (qos < 0 || qos > 2) {
            throw ApiException.validation("qos", "QoS 只能为 0、1、2");
        }
        return Math.min(qos, Math.max(0, Math.min(2, maxAllowed)));
    }
}
