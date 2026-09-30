package com.application.security_log_analyzer.detection;

import com.application.security_log_analyzer.events.NormalizeEvent;

import java.util.Optional;

public interface DetectionRule {

    /*unique,stable name stored on any alert this rule raises. */
    String name();

    /*
      Evaluate one normalized event. Returns a result if the rule fires,
      or empty if the event doesn't trigger this rule.
     */
    Optional<DetectionResult> evaluate(NormalizeEvent event);
}
