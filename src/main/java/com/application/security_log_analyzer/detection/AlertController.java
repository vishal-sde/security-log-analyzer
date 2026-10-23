package com.application.security_log_analyzer.detection;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/alerts")
@RequiredArgsConstructor
public class AlertController {

    private final AlertRepository repository;

    public record AlertResponse(Long id, String ruleTriggered, int riskScore, Severity severity,
                                AlertStatus status, String ip, String username, int occurrenceCount,
                                String evidence, Instant createdAt, Instant lastSeenAt) {
        static AlertResponse from(Alert a) {
            return new AlertResponse(a.getId(), a.getRuleTriggered(), a.getRiskScore(), a.getSeverity(),
                    a.getStatus(), a.getIp(), a.getUsername(), a.getOccurrenceCount(),
                    a.getEvidence(), a.getCreatedAt(), a.getLastSeenAt());
        }
    }

    public record StatusUpdate(@NotNull AlertStatus status) {}

    @GetMapping
    public List<AlertResponse> search(
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) AlertStatus status,
            @RequestParam(defaultValue = "false") boolean activeOnly,
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(defaultValue = "50") int limit) {

        Specification<Alert> spec = (root, query, cb) -> cb.conjunction();
        if (severity != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("severity"), severity));
        }
        if (status != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("status"), status));
        }
        if (activeOnly) {
            spec = spec.and((root, query, cb) -> root.get("status").in(AlertStatus.ACTIVE));
        }
        if (ip != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("ip"), ip));
        }
        if (from != null) {
            spec = spec.and((root, query, cb) -> cb.greaterThanOrEqualTo(root.get("createdAt"), from));
        }
        if (to != null) {
            spec = spec.and((root, query, cb) -> cb.lessThanOrEqualTo(root.get("createdAt"), to));
        }

        return repository.findAll(spec,
                        PageRequest.of(0, Math.min(limit, 500), Sort.by(Sort.Direction.DESC, "lastSeenAt")))
                .getContent().stream().map(AlertResponse::from).toList();
    }

    @GetMapping("/stats")
    public Map<String, Object> stats() {
        long total = repository.count();
        long active = repository.count((root, query, cb) -> root.get("status").in(AlertStatus.ACTIVE));

        var bySeverity = new EnumMap<Severity, Long>(Severity.class);
        for (Severity s : Severity.values()) {
            bySeverity.put(s, repository.count((root, query, cb) -> cb.and(
                    cb.equal(root.get("severity"), s),
                    root.get("status").in(AlertStatus.ACTIVE))));
        }
        return Map.of("totalAlerts", total, "activeAlerts", active, "bySeverity", bySeverity);
    }

    @PatchMapping("/{id}/status")
    public AlertResponse updateStatus(@PathVariable Long id, @Valid @RequestBody StatusUpdate body) {
        Alert alert = repository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Incident not found"));

        if (!alert.getStatus().canTransitionTo(body.status())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Cannot move from " + alert.getStatus() + " to " + body.status());
        }
        alert.setStatus(body.status());
        alert.setUpdatedAt(Instant.now());
        return AlertResponse.from(repository.save(alert));
    }
}