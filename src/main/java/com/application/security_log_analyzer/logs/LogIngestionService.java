package com.application.security_log_analyzer.logs;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class LogIngestionService {

    private final RawLogRepository rawLogRepository;
    private final ObjectMapper objectMapper;

    public RawLog ingest(LogEventRequest request,String source){
        String payload = objectMapper.writeValueAsString(request);
        return rawLogRepository.save(new RawLog(source,payload, Instant.now()));
    }
}
