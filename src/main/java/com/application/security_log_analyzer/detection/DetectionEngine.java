package com.application.security_log_analyzer.detection;

import com.application.security_log_analyzer.events.NormalizeEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Slf4j
@RequiredArgsConstructor
public class DetectionEngine {

    private final List<DetectionRule> rules;

    public void evaluate(NormalizeEvent event){
        for (DetectionRule rule: rules){
            rule.evaluate(event).ifPresent(detectionResult ->
                    log.warn("ALERT [{}] ip={} username={} points={} evidence={}",
                            detectionResult.ruleName(),detectionResult.ip(),detectionResult.username(),
                            detectionResult.points(),detectionResult.evidence()));
        }
    }
}
