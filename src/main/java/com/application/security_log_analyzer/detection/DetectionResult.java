package com.application.security_log_analyzer.detection;

import java.util.Map;

public record DetectionResult (
    String ruleName,
    String ip,
    String username,
    int points,
    Map<String,Object> evidence

){}
