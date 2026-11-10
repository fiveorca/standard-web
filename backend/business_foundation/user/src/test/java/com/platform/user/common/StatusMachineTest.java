package com.platform.user.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StatusMachineTest {

    @Test
    void allowsKnownTransitions() {
        assertTrue(StatusMachine.canTransition("pending", "active"));
        assertTrue(StatusMachine.canTransition("active", "locked"));
        assertTrue(StatusMachine.canTransition("deleted", "active"));
        assertTrue(StatusMachine.canTransition("active", "active"));
    }

    @Test
    void rejectsIllegalTransitions() {
        assertFalse(StatusMachine.canTransition("pending", "locked"));
        assertFalse(StatusMachine.canTransition("deleted", "pending"));
        assertFalse(StatusMachine.canTransition("active", "pending"));
    }

    @Test
    void requireTransitionThrowsConflict() {
        ApiException ex = assertThrows(ApiException.class,
                () -> StatusMachine.requireTransition("pending", "frozen"));
        assertEquals(409, ex.status());
        assertEquals("conflict", ex.code());
    }

    @Test
    void requireTransitionRejectsUnknownTarget() {
        ApiException ex = assertThrows(ApiException.class,
                () -> StatusMachine.requireTransition("active", "unknown"));
        assertEquals(422, ex.status());
    }

    @Test
    void treatsNullSourceAsFreshState() {
        assertTrue(StatusMachine.canTransition(null, "pending"));
        assertFalse(StatusMachine.canTransition(null, "unknown"));
    }
}
