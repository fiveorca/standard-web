package com.platform.file.shared;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * 读取上限包装流，超过限制立即中止，避免异常请求占满磁盘或对象存储。
 */
public class BoundedInputStream extends FilterInputStream {
    private final long maxBytes;
    private long count;

    public BoundedInputStream(InputStream in, long maxBytes) {
        super(in);
        this.maxBytes = maxBytes;
    }

    public long count() {
        return count;
    }

    @Override
    public int read() throws IOException {
        int value = super.read();
        if (value >= 0) {
            add(1);
        }
        return value;
    }

    @Override
    public int read(byte[] buffer, int offset, int length) throws IOException {
        int read = super.read(buffer, offset, length);
        if (read > 0) {
            add(read);
        }
        return read;
    }

    @Override
    public long skip(long n) throws IOException {
        long skipped = super.skip(n);
        add(skipped);
        return skipped;
    }

    private void add(long value) {
        count += value;
        if (maxBytes >= 0 && count > maxBytes) {
            throw ApiException.payloadTooLarge("文件超过允许的最大大小 " + maxBytes + " 字节");
        }
    }
}
