package com.platform.file.shared;

import com.platform.file.config.AppProperties;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SharedUtilitiesTest {

    @Test
    void sanitizesFileNameAndExtension() {
        assertEquals("passwd", Names.sanitize("../../etc/passwd"));
        assertEquals("a.txt", Names.sanitize("C:\\temp\\a.txt"));
        assertEquals("file", Names.sanitize("..."));
        assertEquals("png", Names.extension("LOGO.PNG"));
        assertEquals("", Names.extension("no-extension"));
        assertEquals("zip", Names.extension("ARCHIVE.ZIP"));
    }

    @Test
    void validatesMimeAndSniffedContent() {
        AppProperties.Security config = new AppProperties.Security();
        config.allowedExtensions = "png,txt";
        config.allowedMimeTypes = "image/*,text/*";
        config.sniffContent = true;

        byte[] png = new byte[]{(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};
        assertEquals("image/png", ContentTypes.validate("logo.png", "image/png", png, config));
        assertEquals("text/plain", ContentTypes.validate("readme.txt", null,
                "hello".getBytes(StandardCharsets.UTF_8), config));

        ApiException wrongType = assertThrows(ApiException.class,
                () -> ContentTypes.validate("logo.png", "image/png",
                        "plain text".getBytes(StandardCharsets.UTF_8), config));
        assertEquals(415, wrongType.status());

        ApiException badExtension = assertThrows(ApiException.class,
                () -> ContentTypes.validate("evil.exe", "application/octet-stream", null, config));
        assertEquals(415, badExtension.status());
    }

    @Test
    void detectsKnownMagicNumbers() {
        assertEquals("application/pdf", ContentTypes.detect("%PDF-1.7".getBytes(StandardCharsets.UTF_8)));
        assertEquals("application/gzip", ContentTypes.detect(new byte[]{0x1F, (byte) 0x8B, 8, 0}));
        assertNull(ContentTypes.detect(new byte[]{0, 1, 2, 3}));
    }

    @Test
    void computesSha256AndCompares() {
        String sha = Hash.sha256(new ByteArrayInputStream("abc".getBytes(StandardCharsets.UTF_8)));
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", sha);
        assertTrue(Hash.equalsHash(sha.toUpperCase(), sha));
    }

    @Test
    void generatesUuidV7AndParsesSafely() {
        UUID id = Ids.uuidV7();
        assertEquals(7, id.version());
        assertEquals(id, Ids.parse(id.toString()));
        assertNull(Ids.parse("not-a-uuid"));
        assertNotNull(Ids.required(id.toString(), "id"));
        assertEquals(422, assertThrows(ApiException.class,
                () -> Ids.required("bad", "file_id")).status());
    }

    @Test
    void clampsPagination() {
        PageQuery page = PageQuery.of(Map.of("page", "2", "page_size", "50"));
        assertEquals(2, page.page());
        assertEquals(50, page.size());
        assertEquals(50, page.offset());
        assertEquals(200, PageQuery.of(Map.of("page_size", "1000")).size());
        assertEquals(1, PageQuery.of(Map.of("page", "-3")).page());
        assertEquals(400, assertThrows(ApiException.class,
                () -> PageQuery.of(Map.of("page", "abc"))).status());
    }

    @Test
    void boundsInputStreamAndRejectsOversize() throws Exception {
        BoundedInputStream bounded = new BoundedInputStream(
                new ByteArrayInputStream(new byte[32]), 16);
        byte[] buffer = new byte[8];
        int total = 0;
        try {
            int read;
            while ((read = bounded.read(buffer)) != -1) {
                total += read;
            }
        } catch (ApiException e) {
            assertEquals(413, e.status());
        }
        assertTrue(total <= 24);
    }
}
