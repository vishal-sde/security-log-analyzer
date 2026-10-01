package com.application.security_log_analyzer.detection;

import com.application.security_log_analyzer.events.NormalizeEvent;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Component
public class RiskyIpDetectionRule implements DetectionRule{

    static final String RULE_NAME = "KNOWN_RISKY_IP";
    static final int POINTS = 30;

    private static final Set<String> DENYLIST = Set.of("198.51.100.66");

    @Override
    public String name(){
        return RULE_NAME;
    }

    @Override
    public Optional<DetectionResult> evaluate(NormalizeEvent event){
        if(!DENYLIST.contains(event.getIp())){
            return Optional.empty();
        }

        Map<String,Object> evidence = Map.of(
                "ip",event.getIp(),
                "eventType",event.getEventType(),
                "reason","IP matched known-risky denylist"
        );

        return Optional.of(new DetectionResult(RULE_NAME,event.getIp(),event.getUsername(),POINTS,evidence));
    }
}
