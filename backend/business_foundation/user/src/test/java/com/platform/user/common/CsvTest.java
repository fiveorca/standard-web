package com.platform.user.common;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CsvTest {

    @Test
    void parsesHeaderAndRows() {
        List<Map<String, String>> rows = Csv.parse("username,email\nalice,alice@example.com\nbob,bob@example.com\n");
        assertEquals(2, rows.size());
        assertEquals("alice", rows.get(0).get("username"));
        assertEquals("bob@example.com", rows.get(1).get("email"));
    }

    @Test
    void handlesQuotedFieldsAndEscapedQuotes() {
        List<Map<String, String>> rows = Csv.parse("username,display_name\n\"alice\",\"Alice \"\"A\"\" Chen\"\n");
        assertEquals(1, rows.size());
        assertEquals("alice", rows.get(0).get("username"));
        assertEquals("Alice \"A\" Chen", rows.get(0).get("display_name"));
    }

    @Test
    void handlesBomAndCrlf() {
        List<Map<String, String>> rows = Csv.parse("\uFEFFusername,email\r\nalice,alice@example.com\r\n");
        assertEquals(1, rows.size());
        assertEquals("alice", rows.get(0).get("username"));
    }

    @Test
    void skipsBlankLines() {
        List<Map<String, String>> rows = Csv.parse("username,email\nalice,alice@example.com\n\n   \n");
        assertEquals(1, rows.size());
    }

    @Test
    void returnsEmptyForBlankContent() {
        assertTrue(Csv.parse("").isEmpty());
        assertTrue(Csv.parse(null).isEmpty());
    }

    @Test
    void escapesFormulaInjectionAndQuotes() {
        assertEquals("\"=1+1\"", Csv.escape("=1+1"));
        assertEquals("\"a,b\"", Csv.escape("a,b"));
        assertEquals("\"a\"\"b\"", Csv.escape("a\"b"));
        assertEquals("alice,alice@example.com", Csv.line(List.of("alice", "alice@example.com")));
    }
}
