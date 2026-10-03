package com.application.security_log_analyzer.logs;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimiterTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOperations;

    private RateLimiter rateLimiter;

    @BeforeEach
    void setUp() {
        rateLimiter = new RateLimiter(redisTemplate);
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    void allowsRequestUnderLimit() {
        when(valueOperations.increment(anyString())).thenReturn(50L);

        assertThat(rateLimiter.allow("1.2.3.4")).isTrue();
    }

    @Test
    void rejectsRequestOverLimit() {
        when(valueOperations.increment(anyString())).thenReturn(101L);

        assertThat(rateLimiter.allow("1.2.3.4")).isFalse();
    }

    @Test
    void allowsExactlyAtLimit() {
        when(valueOperations.increment(anyString())).thenReturn(100L);

        assertThat(rateLimiter.allow("1.2.3.4")).isTrue();
    }

    @Test
    void setsTtlOnFirstRequest() {
        when(valueOperations.increment(anyString())).thenReturn(1L);

        rateLimiter.allow("1.2.3.4");

        verify(redisTemplate).expire(eq("ratelimit:1.2.3.4"), eq(java.time.Duration.ofSeconds(10)));
    }
}