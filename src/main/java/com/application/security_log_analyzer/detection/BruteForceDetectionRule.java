package com.application.security_log_analyzer.detection;

import com.application.security_log_analyzer.events.NormalizeEvent;
import com.application.security_log_analyzer.logs.EventType;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class BruteForceDetectionRule implements DetectionRule{

    static final String RULE_NAME = "BRUTE_FORCE_LOGIN";
    static final int FAILURE_THRESHOLD = 5;
    static final Duration WINDOW = Duration.ofMinutes(2);
    static final int POINTS = 30;

    private final StringRedisTemplate redisTemplate;

    @Override
    public String name(){
        return RULE_NAME;
    }

    @Override
    public Optional<DetectionResult> evaluate(NormalizeEvent event){
        if(event.getEventType() != EventType.LOGIN_FAILURE){
            return Optional.empty();
        }

        String key = "bruteforce:%s:%s".formatted(event.getIp(),event.getUsername());
        Long count = redisTemplate.opsForValue().increment(key);


        if(count != null && count == 1L){
            redisTemplate.expire(key,WINDOW);
        }
        if(count==null || count<FAILURE_THRESHOLD){
            return Optional.empty();
        }

        Map<String,Object> evidence = Map.of("failureCount",count,"windowSeconds",WINDOW.toSeconds(),"ip",event.getIp(),"username",event.getUsername());

        return Optional.of(new DetectionResult(RULE_NAME, event.getIp(), event.getUsername(),POINTS,evidence));
    }
}
