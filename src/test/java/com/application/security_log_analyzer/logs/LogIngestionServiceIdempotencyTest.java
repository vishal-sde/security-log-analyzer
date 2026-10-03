package com.application.security_log_analyzer.logs;

import com.application.security_log_analyzer.detection.DetectionEngine;
import com.application.security_log_analyzer.events.LogNormalizer;
import com.application.security_log_analyzer.events.NormalizedEventRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class LogIngestionServiceIdempotencyTest {

    @Mock private RawLogRepository rawLogRepository;
    @Mock private NormalizedEventRepository eventRepository;
    @Mock private LogNormalizer normalizer;
    @Mock private DetectionEngine detectionEngine;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void skipsReprocessingForKnownEventId() {
        LogIngestionService service = new LogIngestionService(
                rawLogRepository,objectMapper,normalizer,eventRepository,detectionEngine);

        RawLog existing = new RawLog("api", "dup-1", "{}",Instant.now());
        when(rawLogRepository.findByEventId("dup-1")).thenReturn(Optional.of(existing));

        LogEventRequest request = new LogEventRequest(
                Instant.now(), "10.0.0.1", "bob", EventType.LOGIN_SUCCESS, "dup-1", null);

        RawLog result = service.ingest(request, "api");

        assertThat(result).isSameAs(existing);
        verify(rawLogRepository, never()).save(any());
        verifyNoInteractions(detectionEngine);
    }
}