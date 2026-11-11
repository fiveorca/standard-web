package com.platform.im.infrastructure.ratelimit;

import com.platform.im.config.AppProperties;
import com.platform.im.shared.ApiException;
import org.springframework.stereotype.Component;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * 轻量级固定窗口限流器。单实例内存实现，用于保护 HTTP/gRPC 入口；
 * 多实例严格全局限流应接入 Redis 或网关限流。
 */
@Component
public class RequestRateLimiter {
    private static final long WINDOW_MS = 60_000;
    private static final int CLEANUP_THRESHOLD = 10_000;

    private final AppProperties props;
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    public RequestRateLimiter(AppProperties props) {
        this.props = props;
    }

    public void checkHttp(String key) {
        check("http", key, props.rateLimit.httpPerMinute);
    }

    public void checkGrpc(String key) {
        check("grpc", key, props.rateLimit.grpcPerMinute);
    }

    private void check(String scope, String key, int limit) {
        if (!props.rateLimit.enabled || limit <= 0) {
            return;
        }
        long windowId = System.currentTimeMillis() / WINDOW_MS;
        String mapKey = scope + ":" + (key == null || key.isBlank() ? "anonymous" : key);
        Window window = windows.compute(mapKey, (ignored, current) ->
                current == null || current.windowId != windowId ? new Window(windowId) : current);
        if (window.count.incrementAndGet() > limit) {
            throw new ApiException(429, 42901, "rate_limited", "请求过于频繁，请稍后重试");
        }
        if (windows.size() > CLEANUP_THRESHOLD) {
            windows.entrySet().removeIf(entry -> entry.getValue().windowId < windowId - 1);
        }
    }

    private static final class Window {
        private final long windowId;
        private final AtomicInteger count = new AtomicInteger();

        private Window(long windowId) {
            this.windowId = windowId;
        }
    }
}
