package com.application.security_log_analyzer.detection;

import com.application.security_log_analyzer.events.NormalizeEvent;
import com.application.security_log_analyzer.logs.EventType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class BruteForceDetectionRuleTest {

    @Mock
    private StringRedisTemplate redisTemplate;
    @Mock
    private ValueOperations<String,String> valueOperations;

    private BruteForceDetectionRule rule;

    @BeforeEach
    void setUp(){
        rule = new BruteForceDetectionRule(redisTemplate);
        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    private NormalizeEvent loginFailure(String ip,String username){
        NormalizeEvent event = new NormalizeEvent();
        event.setIp(ip);
        event.setUsername(username);
        event.setEventType(EventType.LOGIN_FAILURE);
        event.setOccurredAt(Instant.now());
        return event;
    }

    @Test
    void ignoresNonLoginFailureEvents(){
        NormalizeEvent event = loginFailure("10.0.0.1","man");
        event.setEventType(EventType.LOGIN_SUCCESS);

        Optional<DetectionResult> result = rule.evaluate(event);

        assertThat(result).isEmpty();
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void doesNotFireBelowThreshold() {
        when(valueOperations.increment(anyString())).thenReturn(4L);

        Optional<DetectionResult> result = rule.evaluate(loginFailure("10.0.0.1", "man"));
        assertThat(result).isEmpty();
    }

    @Test
    void firesAtThreshold(){
        when(valueOperations.increment(anyString())).thenReturn(5L);

        Optional<DetectionResult> result = rule.evaluate(loginFailure("10.0.0.1","man"));

        assertThat(result).isPresent();
        assertThat(result.get().ruleName()).isEqualTo("BRUTE_FORCE_LOGIN");
        assertThat(result.get().ip()).isEqualTo("10.0.0.1");
        assertThat(result.get().username()).isEqualTo("man");
        assertThat(result.get().points()).isEqualTo(30);
    }

    @Test
    void setsTftOnFirstIncrement(){
        when(valueOperations.increment(anyString())).thenReturn(1L);

        rule.evaluate(loginFailure("10.0.0.1","man"));

        verify(redisTemplate).expire(eq("bruteforce:10.0.0.1:man"),eq(java.time.Duration.ofMinutes(2)));
    }

    @Test
    void doesNotResetTftOnSubsequentIncrements(){
        when(valueOperations.increment(anyString())).thenReturn(2L);

        rule.evaluate(loginFailure("10.0.0.1","man"));

        verify(redisTemplate,never()).expire(anyString(),any(java.time.Duration.class));
    }
}
