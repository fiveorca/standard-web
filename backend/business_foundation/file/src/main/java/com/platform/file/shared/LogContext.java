package com.platform.file.shared;

import org.slf4j.MDC;

import java.util.Map;

public final class LogContext {
    public static final String UPLOAD_ID = "uploadId";
    public static final String FILE_ID = "fileId";
    public static final String OBJECT_ID = "fileObjectId";
    public static final String PROVIDER_ID = "storageProviderId";
    public static final String OPERATION = "operation";

    private LogContext() {
    }

    public static void open(Map<String, ?> values) {
        values.forEach((key, value) -> {
            if (value != null) {
                MDC.put(key, String.valueOf(value));
            }
        });
    }

    public static void operation(String operation) {
        if (operation != null) {
            MDC.put(OPERATION, operation);
        }
    }

    public static void clear() {
        MDC.remove(UPLOAD_ID);
        MDC.remove(FILE_ID);
        MDC.remove(OBJECT_ID);
        MDC.remove(PROVIDER_ID);
        MDC.remove(OPERATION);
    }

    public static String traceId() {
        return MDC.get("traceId");
    }
}
