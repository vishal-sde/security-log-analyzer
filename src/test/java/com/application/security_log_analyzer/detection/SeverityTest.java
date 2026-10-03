package com.application.security_log_analyzer.detection;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SeverityTest {

    @Test
    void mapsScoreBandsToSeverity() {
        assertThat(Severity.fromScore(0)).isEqualTo(Severity.LOW);
        assertThat(Severity.fromScore(29)).isEqualTo(Severity.LOW);
        assertThat(Severity.fromScore(30)).isEqualTo(Severity.MEDIUM);
        assertThat(Severity.fromScore(49)).isEqualTo(Severity.MEDIUM);
        assertThat(Severity.fromScore(50)).isEqualTo(Severity.HIGH);
        assertThat(Severity.fromScore(69)).isEqualTo(Severity.HIGH);
        assertThat(Severity.fromScore(70)).isEqualTo(Severity.CRITICAL);
        assertThat(Severity.fromScore(100)).isEqualTo(Severity.CRITICAL);
    }
}