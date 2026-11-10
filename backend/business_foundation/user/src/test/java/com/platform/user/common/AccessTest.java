package com.platform.user.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccessTest {

    @Test
    void requirePermissionRejectsMissingPermission() {
        ApiException ex = assertThrows(ApiException.class,
                () -> Access.requirePermission(false, "user:write"));
        assertEquals(403, ex.status());
        assertEquals("forbidden", ex.code());
    }

    @Test
    void requirePermissionAllowsGrantedPermission() {
        assertDoesNotThrow(() -> Access.requirePermission(true, "user:read"));
    }

    @Test
    void requireInternalRejectsBlankExpectedToken() {
        ApiException ex = assertThrows(ApiException.class,
                () -> Access.requireInternal("token", ""));
        assertEquals(401, ex.status());
    }

    @Test
    void tokenMatchesUsesExactComparison() {
        assertTrue(Access.tokenMatches("secret", "secret"));
        assertFalse(Access.tokenMatches("secret", "secreT"));
        assertFalse(Access.tokenMatches(null, "secret"));
        assertFalse(Access.tokenMatches("secret", null));
    }
}
