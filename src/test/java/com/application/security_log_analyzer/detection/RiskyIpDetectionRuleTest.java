package com.application.security_log_analyzer.detection;

import com.application.security_log_analyzer.events.NormalizeEvent;
import com.application.security_log_analyzer.logs.EventType;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class RiskyIpDetectionRuleTest {

    private final RiskyIpDetectionRule rule = new RiskyIpDetectionRule();

    private NormalizeEvent event(String ip, EventType type) {
        NormalizeEvent e = new NormalizeEvent();
        e.setIp(ip);
        e.setUsername("someone");
        e.setEventType(type);
        e.setOccurredAt(Instant.now());
        return e;
    }

    @Test
    void firesForDenylistedIp() {
        Optional<DetectionResult> result = rule.evaluate(event("198.51.100.66", EventType.LOGIN_SUCCESS));

        assertThat(result).isPresent();
        assertThat(result.get().ruleName()).isEqualTo("KNOWN_RISKY_IP");
        assertThat(result.get().points()).isEqualTo(30);
    }

    @Test
    void ignoresCleanIp() {
        Optional<DetectionResult> result = rule.evaluate(event("10.0.0.5", EventType.LOGIN_SUCCESS));

        assertThat(result).isEmpty();
    }
}