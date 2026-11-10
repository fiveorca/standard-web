package com.platform.auth.common;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class RateLimiter {
    private final ObjectProvider<StringRedisTemplate> redis;
    private final Map<String, Window> local = new ConcurrentHashMap<>();

    public RateLimiter(ObjectProvider<StringRedisTemplate> redis) {
        this.redis = redis;
    }

    public void check(String key, int limit, long windowSeconds) {
        if (limit <= 0) {
            return;
        }
        String redisKey = "auth:rl:" + key;
        try {
            StringRedisTemplate template = redis.getIfAvailable();
            if (template != null) {
                Long count = template.opsForValue().increment(redisKey);
                if (count != null) {
                    if (count == 1L) {
                        template.expire(redisKey, Duration.ofSeconds(windowSeconds));
                    }
                    if (count > limit) {
                        throw ApiException.tooMany("请求过于频繁，请稍后重试");
                    }
                    return;
                }
            }
        } catch (ApiException e) {
            throw e;
        } catch (Exception ignored) {
            // Redis 不可用时降级到内存限流
        }
        long now = System.currentTimeMillis();
        Window w = local.compute(key, (k, old) -> {
            if (old == null || old.start + windowSeconds * 1000 < now) {
                return new Window(now, 1);
            }
            return new Window(old.start, old.count + 1);
        });
        if (w.count > limit) {
            throw ApiException.tooMany("请求过于频繁，请稍后重试");
        }
        if (local.size() > 100_000) {
            local.clear();
        }
    }

    private record Window(long start, int count) {}
}
