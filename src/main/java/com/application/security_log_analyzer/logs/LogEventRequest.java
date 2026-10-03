package com.application.security_log_analyzer.logs;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.rmi.MarshalledObject;
import java.time.Instant;
import java.util.Map;

public record LogEventRequest (
    @NotNull Instant timestamp,
    @NotBlank String ip,
    @NotBlank String username,
    @NotNull EventType eventType,
    String eventId,
    Map<String,Object> meta

){}
