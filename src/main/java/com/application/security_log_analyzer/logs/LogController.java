package com.application.security_log_analyzer.logs;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/logs")
@RequiredArgsConstructor
public class LogController {

    private final LogIngestionService logIngestionService;

    @PostMapping
    public ResponseEntity<Map<String,Object>> ingest(
            @Valid @RequestBody LogEventRequest request,
            @RequestHeader(value = "X-Log-Source",defaultValue = "api")String source){
        RawLog saved = logIngestionService.ingest(request,source);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(Map.of("id",saved.getId(),"status","accepted"));
    }
}
