package com.platform.im.domain.mqtt;

import com.platform.im.shared.ApiException;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TopicRulesTest {

    @Test
    void resolveReplacesAllTemplateVariables() {
        String topic = TopicRules.resolve("tenants/{tenantId}/devices/{deviceId}/up",
                Map.of("tenantId", "t-1", "deviceId", "dev-1"));
        assertEquals("tenants/t-1/devices/dev-1/up", topic);
    }

    @Test
    void resolveRejectsUnresolvedVariables() {
        assertThrows(ApiException.class,
                () -> TopicRules.resolve("devices/{deviceId}/up", Map.of()));
    }

    @Test
    void matchesSupportsSingleAndMultiLevelWildcards() {
        assertTrue(TopicRules.matches("devices/+/up", "devices/dev1/up"));
        assertTrue(TopicRules.matches("devices/#", "devices/dev1/up"));
        assertFalse(TopicRules.matches("devices/+/up", "devices/dev1/down"));
        assertFalse(TopicRules.matches("devices/dev1/up", "devices/dev2/up"));
    }

    @Test
    void coversRejectsBroaderSubscriptionFilters() {
        assertTrue(TopicRules.covers("devices/dev1/down", "devices/dev1/down"));
        assertTrue(TopicRules.covers("devices/+/down", "devices/dev1/down"));
        assertTrue(TopicRules.covers("devices/#", "devices/dev1/down"));
        assertFalse(TopicRules.covers("devices/dev1/down", "devices/+/down"));
        assertFalse(TopicRules.covers("devices/dev1/down", "devices/#"));
        assertFalse(TopicRules.covers("devices/+/down", "devices/#"));
    }

    @Test
    void validatesDeviceIdsAndTopics() {
        assertThrows(ApiException.class, () -> TopicRules.validateDeviceId("../etc"));
        assertThrows(ApiException.class, () -> TopicRules.validateDeviceId(""));
        TopicRules.validateDeviceId("device-01_A");
        assertThrows(ApiException.class, () -> TopicRules.validatePublishTopic("devices/+/up"));
        assertThrows(ApiException.class, () -> TopicRules.validatePublishTopic("devices/#"));
        assertThrows(ApiException.class, () -> TopicRules.validateTopicPattern("devices/a#"));
    }

    @Test
    void normalizeQosValidatesAndClampsToMax() {
        assertEquals(1, TopicRules.normalizeQos(null, 1, 2));
        assertThrows(ApiException.class, () -> TopicRules.normalizeQos(-1, 1, 2));
        assertThrows(ApiException.class, () -> TopicRules.normalizeQos(5, 1, 2));
        assertEquals(1, TopicRules.normalizeQos(2, 1, 1));
    }
}
