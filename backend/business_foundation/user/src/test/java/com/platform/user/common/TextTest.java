package com.platform.user.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TextTest {

    @Test
    void normalizesEmailToLowerCase() {
        assertEquals("alice@example.com", Text.normalizeEmail("  Alice@Example.COM "));
        assertNull(Text.normalizeEmail("   "));
        assertTrue(Text.validEmail("alice@example.com"));
        assertFalse(Text.validEmail("alice@"));
    }

    @Test
    void normalizesPhoneByKeepingDigitsAndLeadingPlus() {
        assertEquals("+8613800138000", Text.normalizePhone("+86 138-0013-8000"));
        assertEquals("13800138000", Text.normalizePhone("(138) 0013 8000"));
        assertNull(Text.normalizePhone("no digits"));
    }

    @Test
    void validatesPhoneAndUsername() {
        assertTrue(Text.validPhone("13800138000"));
        assertFalse(Text.validPhone("123"));
        assertTrue(Text.validUsername("alice.01"));
        assertFalse(Text.validUsername("a"));
    }

    @Test
    void masksSensitiveValues() {
        assertEquals("a***e@example.com", Text.maskEmail("alice@example.com"));
        assertEquals("a***@example.com", Text.maskEmail("ab@example.com"));
        assertEquals("138****8000", Text.maskPhone("13800138000"));
    }

    @Test
    void escapeLikePatterns() {
        assertEquals("%50\\%\\_off%", Text.likePattern("50%_off"));
    }

    @Test
    void requireEmailRejectsInvalidInput() {
        ApiException ex = assertThrows(ApiException.class,
                () -> Text.requireEmail("bad-email", "email"));
        assertEquals(422, ex.status());
        assertEquals("email", ex.details().keySet().iterator().next());
    }
}
