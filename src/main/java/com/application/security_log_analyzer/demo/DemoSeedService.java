package com.application.security_log_analyzer.demo;

import com.application.security_log_analyzer.logs.EventType;
import com.application.security_log_analyzer.logs.LogEventRequest;
import com.application.security_log_analyzer.logs.LogIngestionService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class DemoSeedService {

    private final LogIngestionService ingestionService;

    public void runScenario() {
        send("10.0.0.12", "priya", EventType.LOGIN_SUCCESS, Map.of("userAgent", "Chrome/128"));
        send("10.0.0.18", "arjun", EventType.LOGIN_SUCCESS, Map.of("userAgent", "Firefox/130"));

        send("10.0.0.12", "priya", EventType.LOGIN_FAILURE, Map.of("userAgent", "Chrome/128"));
        send("10.0.0.12", "priya", EventType.LOGIN_SUCCESS, Map.of("userAgent", "Chrome/128"));

        String attackerIp = "203.0.113.77";
        for (int i = 0; i < 7; i++) {
            send(attackerIp, "admin", EventType.LOGIN_FAILURE, Map.of("userAgent", "hydra"));
        }
        send(attackerIp, "admin", EventType.LOGIN_SUCCESS, Map.of("userAgent", "hydra"));

        String riskyIp = "198.51.100.66";
        for (int i = 0; i < 3; i++) {
            send(riskyIp, "finance_admin", EventType.LOGIN_FAILURE, Map.of("userAgent", "python-requests"));
        }

        send(attackerIp, "admin", EventType.FILE_ACCESS, Map.of("path", "/etc/shadow"));
        send(attackerIp, "admin", EventType.FILE_ACCESS, Map.of("path", "finance/payroll.xlsx"));

        for (String user : new String[]{"priya", "arjun", "rohith", "admin"}) {
            send("10.0.0.99", user, EventType.LOGIN_SUCCESS, Map.of("userAgent", "corp-proxy"));
        }
    }

    private void send(String ip, String username, EventType type, Map<String, Object> meta) {
        LogEventRequest request = new LogEventRequest(
                Instant.now(), ip, username, type, UUID.randomUUID().toString(), meta);
        ingestionService.ingest(request, "demo-seed");
    }
}
