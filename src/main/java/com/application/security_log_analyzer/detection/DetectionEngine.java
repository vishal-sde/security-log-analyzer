package com.application.security_log_analyzer.detection;

import com.application.security_log_analyzer.events.NormalizedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.*;

@Slf4j
@Component
@RequiredArgsConstructor
public class DetectionEngine {

    private static final int MAX_SCORE = 100;

    private final List<DetectionRule> rules;
    private final AlertRepository alertRepository;
    private final JdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    @Transactional
    public void evaluate(NormalizedEvent event) {
        List<DetectionResult> results = new ArrayList<>();
        for (DetectionRule rule : rules) {
            rule.evaluate(event).ifPresent(results::add);
        }
        if (results.isEmpty()) {
            return;
        }

        String fingerprint = event.getIp() + "|" + event.getUsername();

        // Serialize concurrent detections for the same fingerprint. The lock is
        // transaction-scoped, so it is released automatically on commit/rollback.
        jdbcTemplate.queryForObject(
                "SELECT pg_advisory_xact_lock(hashtext(?))::text", String.class, fingerprint);

        Optional<Alert> existing = alertRepository
                .findFirstByFingerprintAndStatusInOrderByCreatedAtDesc(fingerprint, AlertStatus.ACTIVE);

        Alert alert = existing.isPresent()
                ? merge(existing.get(), results)
                : open(event, fingerprint, results);

        log.warn("INCIDENT #{} [{}] {} score={} severity={} status={} hits={}",
                alert.getId(), alert.getRuleTriggered(), fingerprint, alert.getRiskScore(),
                alert.getSeverity(), alert.getStatus(), alert.getOccurrenceCount());
    }

    private Alert open(NormalizedEvent event, String fingerprint, List<DetectionResult> results) {
        Map<String, Object> evidence = new LinkedHashMap<>();
        List<String> names = new ArrayList<>();
        int score = 0;
        for (DetectionResult r : results) {
            score += r.points();
            names.add(r.ruleName());
            evidence.put(r.ruleName(), r.evidence());
        }

        Instant now = Instant.now();
        Alert alert = new Alert();
        alert.setNormalizedEventId(event.getId());
        alert.setRuleTriggered(String.join(",", names));
        alert.setRiskScore(Math.min(score, MAX_SCORE));
        alert.setSeverity(Severity.fromScore(alert.getRiskScore()));
        alert.setStatus(AlertStatus.OPEN);
        alert.setFingerprint(fingerprint);
        alert.setOccurrenceCount(1);
        alert.setIp(event.getIp());
        alert.setUsername(event.getUsername());
        alert.setEvidence(objectMapper.writeValueAsString(evidence));
        alert.setCreatedAt(now);
        alert.setLastSeenAt(now);
        return alertRepository.save(alert);
    }

    @SuppressWarnings("unchecked")
    private Alert merge(Alert alert, List<DetectionResult> results) {
        Map<String, Object> evidence =
                new LinkedHashMap<>(objectMapper.readValue(alert.getEvidence(), Map.class));
        Set<String> ruleNames = new LinkedHashSet<>(Arrays.asList(alert.getRuleTriggered().split(",")));

        int score = alert.getRiskScore();
        for (DetectionResult r : results) {
            if (ruleNames.add(r.ruleName())) {
                score += r.points(); // a rule newly seen on this incident escalates it
            }
            evidence.put(r.ruleName(), r.evidence()); // keep the latest evidence per rule
        }

        Instant now = Instant.now();
        alert.setRuleTriggered(String.join(",", ruleNames));
        alert.setRiskScore(Math.min(score, MAX_SCORE));
        alert.setSeverity(Severity.fromScore(alert.getRiskScore()));
        alert.setOccurrenceCount(alert.getOccurrenceCount() + 1);
        alert.setEvidence(objectMapper.writeValueAsString(evidence));
        alert.setLastSeenAt(now);
        alert.setUpdatedAt(now);
        return alertRepository.save(alert);
    }
}