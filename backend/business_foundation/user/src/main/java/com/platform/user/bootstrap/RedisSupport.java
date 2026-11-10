package com.platform.user.bootstrap;

import com.platform.user.common.ApiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Redis 为可选依赖：连接失败自动降级到进程内缓存/限流，不影响启动与主流程。
 */
@Component
public class RedisSupport {
    private static final Logger log = LoggerFactory.getLogger(RedisSupport.class);
    private final ObjectProvider<StringRedisTemplate> redis;
    private final Map<String, Window> local = new ConcurrentHashMap<>();
    private volatile boolean warned = false;

    public RedisSupport(ObjectProvider<StringRedisTemplate> redis) {
        this.redis = redis;
    }

    public boolean rateLimit(String key, int limit, long windowSeconds) {
        if (limit <= 0) {
            return true;
        }
        String redisKey = "user:rl:" + key;
        try {
            StringRedisTemplate template = redis.getIfAvailable();
            if (template != null) {
                Long count = template.opsForValue().increment(redisKey);
                if (count != null) {
                    if (count == 1L) {
                        template.expire(redisKey, Duration.ofSeconds(windowSeconds));
                    }
                    return count <= limit;
                }
            }
        } catch (Exception e) {
            warnOnce(e);
        }
        long now = System.currentTimeMillis();
        Window window = local.compute(key, (k, old) -> {
            if (old == null || old.start + windowSeconds * 1000 < now) {
                return new Window(now, 1);
            }
            return new Window(old.start, old.count + 1);
        });
        if (local.size() > 100_000) {
            local.clear();
        }
        return window.count <= limit;
    }

    public void requireRateLimit(String key, int limit, long windowSeconds) {
        if (!rateLimit(key, limit, windowSeconds)) {
            throw ApiException.tooMany("请求过于频繁，请稍后重试");
        }
    }

    public void put(String key, String value, Duration ttl) {
        try {
            StringRedisTemplate template = redis.getIfAvailable();
            if (template != null) {
                template.opsForValue().set(key, value, ttl);
            }
        } catch (Exception e) {
            warnOnce(e);
        }
    }

    public boolean ping() {
        try {
            StringRedisTemplate template = redis.getIfAvailable();
            if (template == null) {
                return false;
            }
            String pong = template.execute(connection -> connection.ping(), true);
            return "PONG".equalsIgnoreCase(pong);
        } catch (Exception e) {
            warnOnce(e);
            return false;
        }
    }

    private void warnOnce(Exception e) {
        if (!warned) {
            warned = true;
            log.warn("Redis 不可用，已降级到内存实现: {}", e.getMessage());
        }
    }

    private record Window(long start, int count) {
    }
}
