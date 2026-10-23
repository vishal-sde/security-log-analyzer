package com.application.security_log_analyzer.detection;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.DynamicUpdate;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;

// DynamicUpdate: only changed columns are written, so the detection engine
// updating hit counts can't overwrite a status change made by an analyst.
@DynamicUpdate
@Entity
@Table(name = "alerts", indexes = {
        @Index(name = "idx_alerts_severity", columnList = "severity"),
        @Index(name = "idx_alerts_ip", columnList = "ip"),
        @Index(name = "idx_alerts_status", columnList = "status"),
        @Index(name = "idx_alerts_fingerprint", columnList = "fingerprint"),
        @Index(name = "idx_alerts_last_seen", columnList = "last_seen_at")
})
@Getter
@Setter
@NoArgsConstructor
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** The first event that opened this incident. */
    @Column(name = "normalized_event_id", nullable = false)
    private Long normalizedEventId;

    @Column(name = "rule_triggered", nullable = false)
    private String ruleTriggered;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AlertStatus status = AlertStatus.OPEN;

    @Column(nullable = false)
    private String fingerprint;

    @Column(name = "occurrence_count", nullable = false)
    private int occurrenceCount = 1;

    private String ip;

    private String username;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private String evidence;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    @Column(name = "updated_at")
    private Instant updatedAt;
}