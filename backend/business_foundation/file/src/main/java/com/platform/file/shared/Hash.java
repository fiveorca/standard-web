package com.platform.file.shared;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;

public final class Hash {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private Hash() {
    }

    public static String sha256(InputStream in) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                digest.update(buffer, 0, read);
            }
            return hex(digest.digest());
        } catch (Exception e) {
            throw new ApiException(500, "hash_error", "计算文件 SHA-256 失败");
        }
    }

    public static String sha256(Path path) {
        try (InputStream in = Files.newInputStream(path)) {
            return sha256(in);
        } catch (ApiException e) {
            throw e;
        } catch (Exception e) {
            throw new ApiException(500, "hash_error", "读取文件计算 SHA-256 失败");
        }
    }

    public static boolean equalsHash(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.toLowerCase().getBytes(), b.toLowerCase().getBytes());
    }

    public static String hex(byte[] bytes) {
        char[] out = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            out[i * 2] = HEX[v >>> 4];
            out[i * 2 + 1] = HEX[v & 0x0F];
        }
        return new String(out);
    }
}
