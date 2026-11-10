package com.platform.auth.common;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class IdsTest {
    @Test
    void generatesUniqueTokens() {
        assertThat(Ids.uuidStr()).isNotEqualTo(Ids.uuidStr()).hasSize(36);
        assertThat(Ids.randomToken(32)).isNotEqualTo(Ids.randomToken(32));
        assertThat(Ids.randomDigits(6)).hasSize(6).matches("\\d{6}");
    }

    @Test
    void hashesAndComparesSafely() {
        assertThat(Ids.sha256("a")).hasSize(64).isEqualTo(Ids.sha256("a"));
        assertThat(Ids.hmacSha256("key", "value")).isNotEqualTo(Ids.hmacSha256("key", "other"));
        assertThat(Ids.constantEquals("abc", "abc")).isTrue();
        assertThat(Ids.constantEquals("abc", "abd")).isFalse();
        assertThat(Ids.constantEquals("abc", null)).isFalse();
    }

    @Test
    void detectsBlank() {
        assertThat(Ids.blank(" ")).isTrue();
        assertThat(Ids.blank(null)).isTrue();
        assertThat(Ids.blank("x")).isFalse();
    }
}
