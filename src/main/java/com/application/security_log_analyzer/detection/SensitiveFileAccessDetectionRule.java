package com.application.security_log_analyzer.detection;

import com.application.security_log_analyzer.events.NormalizeEvent;
import com.application.security_log_analyzer.logs.EventType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class SensitiveFileAccessDetectionRule implements DetectionRule{

    static final String RULE_NAME = "SENSITIVE_FILE_ACCESS";
    static final int POINTS = 25;

    private static final List<String> SENSITIVE_FRAGMENTS = List.of(
            "shadow","payroll","/etc/","finance/"
    );

    private final ObjectMapper objectMapper;

    @Override
    public String name(){
        return RULE_NAME;
    }

    public Optional<DetectionResult> evaluate(NormalizeEvent event){
        if(event.getEventType() != EventType.FILE_ACCESS || event.getDetails() == null){
            return Optional.empty();
        }

        JsonNode details = objectMapper.readTree(event.getDetails());
        String path = details.path("path").asString("");

        boolean sensitive = SENSITIVE_FRAGMENTS.stream()
                .anyMatch(fragment -> path.toLowerCase().contains(fragment));

        if(!sensitive){
            return Optional.empty();
        }

        Map<String,Object> evidence = Map.of(
                "ip",event.getIp(),
                "username",event.getUsername(),
                "path",path
        );

        return Optional.of(new DetectionResult(RULE_NAME,event.getIp(),event.getUsername(),POINTS,evidence));
    }
}
