package com.application.security_log_analyzer.logs;

import com.application.security_log_analyzer.detection.DetectionEngine;
import com.application.security_log_analyzer.events.LogNormalizer;
import com.application.security_log_analyzer.events.NormalizeEvent;
import com.application.security_log_analyzer.events.NormalizedEventRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class LogIngestionService {

    private final RawLogRepository rawLogRepository;
    private final ObjectMapper objectMapper;
    private final LogNormalizer normalizer;
    private final NormalizedEventRepository eventRepository;
    private final DetectionEngine detectionEngine;

    public RawLog ingest(LogEventRequest request,String source){

        if(request.eventId() !=  null){
            var exisiting = rawLogRepository.findByEventId(request.eventId());
            if(exisiting.isPresent()){
                log.info("Duplicate eventId {} - skipping reprocessing",request.eventId());
                return exisiting.get();
            }
        }
        String payload = objectMapper.writeValueAsString(request);

        RawLog raw = rawLogRepository.save(new RawLog(source,request.eventId(),payload,Instant.now()));
        try {
            NormalizeEvent event = eventRepository.save(normalizer.normalize(raw));
            detectionEngine.evaluate(event);
        }catch (Exception e){
            log.error("Normalization failed for raw log {}",raw.getId(),e);
        }

        return raw;
    }
}
