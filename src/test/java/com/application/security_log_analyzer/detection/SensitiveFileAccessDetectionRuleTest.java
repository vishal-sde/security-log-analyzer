package com.application.security_log_analyzer.detection;

import com.application.security_log_analyzer.events.NormalizeEvent;
import com.application.security_log_analyzer.logs.EventType;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SensitiveFileAccessDetectionRuleTest {

    private final ObjectMapper mapper = new ObjectMapper();
    private final SensitiveFileAccessDetectionRule rule = new SensitiveFileAccessDetectionRule(mapper);

    private NormalizeEvent fileEvent(String path) {
        NormalizeEvent e = new NormalizeEvent();
        e.setIp("10.0.0.5");
        e.setUsername("someone");
        e.setEventType(EventType.FILE_ACCESS);
        e.setOccurredAt(Instant.now());
        e.setDetails("{\"path\":\"" + path + "\"}");
        return e;
    }

    @Test
    void firesForShadowFile() {
        Optional<DetectionResult> result = rule.evaluate(fileEvent("/etc/shadow"));

        assertThat(result).isPresent();
        assertThat(result.get().ruleName()).isEqualTo("SENSITIVE_FILE_ACCESS");
        assertThat(result.get().points()).isEqualTo(25);
    }

    @Test
    void firesForPayrollFileWithoutLeadingSlash() {
        Optional<DetectionResult> result = rule.evaluate(fileEvent("finance/payroll.xlsx"));

        assertThat(result).isPresent();
    }

    @Test
    void ignoresOrdinaryFile() {
        Optional<DetectionResult> result = rule.evaluate(fileEvent("/home/alice/notes.txt"));

        assertThat(result).isEmpty();
    }

    @Test
    void ignoresNonFileAccessEvent() {
        NormalizeEvent e = fileEvent("/etc/shadow");
        e.setEventType(EventType.LOGIN_SUCCESS);

        assertThat(rule.evaluate(e)).isEmpty();
    }
}