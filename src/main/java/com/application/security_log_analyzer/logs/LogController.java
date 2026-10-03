package com.application.security_log_analyzer.logs;

import jakarta.servlet.http.HttpServletRequest;
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
    private final RateLimiter rateLimiter;

    @PostMapping
    public ResponseEntity<Map<String,Object>> ingest(
            @Valid @RequestBody LogEventRequest request,
            @RequestHeader(value = "X-Log-Source",defaultValue = "api")String source, HttpServletRequest httpServletRequest){

        String callerKey = httpServletRequest.getRemoteAddr();
        if(!rateLimiter.allow(callerKey)){
            return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                    .body(Map.of("status","rejected","errors","Rate limit exceeded"));
        }

        RawLog saved = logIngestionService.ingest(request,source);
        return ResponseEntity.status(HttpStatus.ACCEPTED)
                .body(Map.of("id",saved.getId(),"status","accepted"));
    }
}
