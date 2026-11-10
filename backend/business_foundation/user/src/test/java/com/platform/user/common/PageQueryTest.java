package com.platform.user.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PageQueryTest {

    @Test
    void defaultsWhenValuesMissing() {
        PageQuery query = PageQuery.parse(null, "");
        assertEquals(1, query.page());
        assertEquals(20, query.pageSize());
        assertEquals(0L, query.offset());
    }

    @Test
    void clampsPageSizeToMaximum() {
        PageQuery query = PageQuery.of(3, 1000);
        assertEquals(3, query.page());
        assertEquals(PageQuery.MAX_SIZE, query.pageSize());
        assertEquals((3 - 1) * 200L, query.offset());
        assertEquals(200L, query.limit());
    }

    @Test
    void normalizesNonPositiveValues() {
        PageQuery query = PageQuery.of(0, -5);
        assertEquals(PageQuery.DEFAULT_PAGE, query.page());
        assertEquals(PageQuery.DEFAULT_SIZE, query.pageSize());
    }

    @Test
    void rejectsNonNumericInput() {
        ApiException ex = assertThrows(ApiException.class, () -> PageQuery.parse("abc", "10"));
        assertEquals(422, ex.status());
        assertEquals("validation_failed", ex.code());
    }

    @Test
    void rejectsNonNumericSize() {
        ApiException ex = assertThrows(ApiException.class, () -> PageQuery.parse("1", "ten"));
        assertEquals(422, ex.status());
        assertEquals("page_size", ex.details().keySet().iterator().next());
    }
}
