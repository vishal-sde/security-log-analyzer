package com.application.security_log_analyzer.detection;

import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;

@RestController
@RequestMapping("/api/alerts")
@RequiredArgsConstructor
public class AlertController {
    private final AlertRepository repository;

    public record AlertResponse(Long id, String ruleTriggered, int riskScore, Severity severity,
                                String ip, String username, String evidence, Instant createdAt) {
        static AlertResponse from(Alert a) {
            return new AlertResponse(a.getId(), a.getRuleTriggered(), a.getRiskScore(), a.getSeverity(),
                    a.getIp(), a.getUsername(), a.getEvidence(), a.getCreatedAt());
        }
    }

    @GetMapping
    public List<AlertResponse> search(
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) String ip,
            @RequestParam(required = false) Instant from,
            @RequestParam(required = false) Instant to,
            @RequestParam(defaultValue = "50") int limit) {

        Specification<Alert> spec = (root, query, cb) -> cb.conjunction();
        if (severity != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("severity"), severity));
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
                        PageRequest.of(0, Math.min(limit, 500), Sort.by(Sort.Direction.DESC, "createdAt")))
                .getContent().stream().map(AlertResponse::from).toList();
    }
}
