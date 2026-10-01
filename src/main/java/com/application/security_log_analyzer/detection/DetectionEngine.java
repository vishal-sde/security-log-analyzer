package com.application.security_log_analyzer.detection;

import com.application.security_log_analyzer.events.NormalizeEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.List;

@Component
@Slf4j
@RequiredArgsConstructor
public class DetectionEngine {

    private final List<DetectionRule> rules;
    private final AlertRepository alertRepository;
    private final ObjectMapper objectMapper;

    public void evaluate(NormalizeEvent event){
        int totalScore = 0;
        StringBuilder triggeredRules = new StringBuilder();

        var evidence = new java.util.LinkedHashMap<String ,Object>();
        for (DetectionRule rule: rules){
            var result = rule.evaluate(event);
            if (result.isEmpty()) continue;

            DetectionResult r = result.get();
            totalScore += r.points();
            if (!triggeredRules.isEmpty()) triggeredRules.append(",");
            triggeredRules.append(r.ruleName());
            evidence.put(r.ruleName(), r.evidence());
        }

        if (totalScore == 0) {
            return; // no rule fired
        }

        Alert alert = new Alert();
        alert.setNormalizedEventId(event.getId());
        alert.setRuleTriggered(triggeredRules.toString());
        alert.setRiskScore(totalScore);
        alert.setSeverity(Severity.fromScore(totalScore));
        alert.setIp(event.getIp());
        alert.setUsername(event.getUsername());
        alert.setEvidence(objectMapper.writeValueAsString(evidence));
        alert.setCreatedAt(Instant.now());
        alertRepository.save(alert);
        log.warn("ALERT [{}] ip={} username={} score={} severity={}",
                alert.getRuleTriggered(), alert.getIp(), alert.getUsername(),
                alert.getRiskScore(), alert.getSeverity());


    }
}
