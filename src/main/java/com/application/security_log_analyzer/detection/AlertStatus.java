package com.application.security_log_analyzer.detection;

import java.util.EnumSet;
import java.util.Set;

public enum AlertStatus {
    OPEN, ACKNOWLEDGED, INVESTIGATING, RESOLVED, FALSE_POSITIVE;

    public static final Set<AlertStatus> ACTIVE = EnumSet.of(OPEN, ACKNOWLEDGED, INVESTIGATING);

    public boolean canTransitionTo(AlertStatus next) {
        return switch (this) {
            case OPEN -> next != OPEN;
            case ACKNOWLEDGED -> next == INVESTIGATING || next == RESOLVED || next == FALSE_POSITIVE;
            case INVESTIGATING -> next == RESOLVED || next == FALSE_POSITIVE;
            case RESOLVED, FALSE_POSITIVE -> false;
        };
    }
}