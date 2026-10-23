package com.application.security_log_analyzer.detection;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AlertStatusTest {

    @Test
    void openCanMoveToAnyOtherState() {
        assertThat(AlertStatus.OPEN.canTransitionTo(AlertStatus.ACKNOWLEDGED)).isTrue();
        assertThat(AlertStatus.OPEN.canTransitionTo(AlertStatus.RESOLVED)).isTrue();
        assertThat(AlertStatus.OPEN.canTransitionTo(AlertStatus.FALSE_POSITIVE)).isTrue();
    }

    @Test
    void cannotMoveBackwards() {
        assertThat(AlertStatus.INVESTIGATING.canTransitionTo(AlertStatus.OPEN)).isFalse();
        assertThat(AlertStatus.ACKNOWLEDGED.canTransitionTo(AlertStatus.OPEN)).isFalse();
    }

    @Test
    void closedStatesAreTerminal() {
        for (AlertStatus next : AlertStatus.values()) {
            assertThat(AlertStatus.RESOLVED.canTransitionTo(next)).isFalse();
            assertThat(AlertStatus.FALSE_POSITIVE.canTransitionTo(next)).isFalse();
        }
    }
}