package com.application.security_log_analyzer;


import com.application.security_log_analyzer.detection.Alert;
import com.application.security_log_analyzer.detection.AlertRepository;
import com.application.security_log_analyzer.events.NormalizedEventRepository;
import com.application.security_log_analyzer.logs.RawLogRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

@Testcontainers
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
public class IngestionFlowIntegrationTest {
    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("security_log_analyzer_test")
            .withUsername("test")
            .withPassword("test");

    @Container
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

    @DynamicPropertySource
    static void registerProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", () -> redis.getMappedPort(6379));
    }

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;
    @Autowired
    private RawLogRepository rawLogRepository;
    @Autowired
    private NormalizedEventRepository eventRepository;
    @Autowired
    private AlertRepository alertRepository;

    private ResponseEntity<Map> postLog(String ip, String username, String eventType) {
        String body = """
                {"timestamp":"%s","ip":"%s","username":"%s","eventType":"%s","meta":{}}
                """.formatted(Instant.now(), ip, username, eventType);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return restTemplate.postForEntity("http://localhost:" + port + "/api/logs",
                new HttpEntity<>(body, headers), Map.class);
    }

    @Test
    void singleEventIsPersistedAndNormalized() {
        ResponseEntity<Map> response = postLog("10.0.0.99", "alice", "LOGIN_SUCCESS");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);

        await().untilAsserted(() -> {
            assertThat(rawLogRepository.count()).isGreaterThanOrEqualTo(1);
            assertThat(eventRepository.findAll())
                    .anyMatch(e -> e.getIp().equals("10.0.0.99") && e.getUsername().equals("alice"));
        });
    }

    @Test
    void bruteForceBurstCreatesAlert() {
        String ip = "203.0.113.200";
        String username = "victim";

        for (int i = 0; i < 6; i++) {
            ResponseEntity<Map> response = postLog(ip, username, "LOGIN_FAILURE");
            assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        }

        await().untilAsserted(() -> {
            List<Alert> alerts = alertRepository.findAll();
            assertThat(alerts)
                    .anyMatch(a -> a.getIp().equals(ip)
                            && a.getUsername().equals(username)
                            && a.getRuleTriggered().contains("BRUTE_FORCE_LOGIN"));
        });
    }

    @Test
    void rejectsInvalidEventType() {
        String body = """
                {"timestamp":"%s","ip":"10.0.0.1","username":"bob","eventType":"NOT_REAL","meta":{}}
                """.formatted(Instant.now());

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        ResponseEntity<Map> response = restTemplate.postForEntity("http://localhost:" + port + "/api/logs",
                new HttpEntity<>(body, headers), Map.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }
}
