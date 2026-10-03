package com.application.security_log_analyzer.logs;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@RequiredArgsConstructor
public class RateLimiter {
    private static final int MAX_REQUESTS = 100;
    private static final Duration WINDOW = Duration.ofSeconds(10);

    private final StringRedisTemplate redisTemplate;

    public boolean allow(String callerKey){
        String key = "ratelimit:" + callerKey;
        Long count = redisTemplate.opsForValue().increment(key);

        if(count != null && count == 1L){
            redisTemplate.expire(key,WINDOW);
        }

        return count != null && count <= MAX_REQUESTS;
    }
}
