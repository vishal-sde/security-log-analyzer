package com.application.security_log_analyzer.events;

import com.application.security_log_analyzer.logs.LogEventRequest;
import com.application.security_log_analyzer.logs.RawLog;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

@Component
@RequiredArgsConstructor
public class LogNormalizer {

    private final ObjectMapper objectMapper;

    public NormalizeEvent normalize(RawLog raw){
        LogEventRequest req = objectMapper.readValue(raw.getPayLoad(), LogEventRequest.class);

        NormalizeEvent event = new NormalizeEvent();
        event.setRawLogId(raw.getId());
        event.setIp(req.ip().trim());
        event.setUsername(req.username().trim().toLowerCase());
        event.setEventType(req.eventType());
        event.setOccurredAt(req.timestamp());
        event.setDetails(req.meta() == null ? null : objectMapper.writeValueAsString(req.meta()));
        return event;
    }
}
