package com.platform.file.shared;

import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

public final class Ids {
    private Ids() {
    }

    /**
     * 生成 UUIDv7：48 位毫秒时间戳 + 版本 7 + 随机位，用于文件、对象和任务的全局唯一标识。
     */
    public static UUID uuidV7() {
        long timestamp = System.currentTimeMillis();
        long randomA = ThreadLocalRandom.current().nextLong() & 0x0FFFL;
        long randomB = ThreadLocalRandom.current().nextLong();
        long msb = (timestamp << 16) | 0x7000L | randomA;
        long lsb = (randomB & 0x3FFFFFFFFFFFFFFFL) | 0x8000000000000000L;
        return new UUID(msb, lsb);
    }

    public static UUID parse(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(value.trim());
        } catch (Exception e) {
            return null;
        }
    }

    public static UUID required(String value, String field) {
        UUID id = parse(value);
        if (id == null) {
            throw ApiException.validation(field, "ID 格式不合法");
        }
        return id;
    }

    public static String text(UUID id) {
        return id == null ? null : id.toString();
    }
}
