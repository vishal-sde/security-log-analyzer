package com.application.security_log_analyzer.detection;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;


import java.time.Instant;

@Entity
@Table(name = "alerts",indexes = {
        @Index(name = "idx_alerts_severity",columnList = "severity"),
        @Index(name = "idx_alerts_ip",columnList = "ip"),
        @Index(name = "idx_alerts_created_at",columnList = "created_at")
})
@Getter
@Setter
@NoArgsConstructor
public class Alert {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "normalized_event_id",nullable = false)
    private Long normalizedEventId;

    @Column(name = "rule_triggered",nullable = false)
    private String ruleTriggered;

    @Column(name = "risk_score",nullable = false)
    private int riskScore;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    private String ip;

    private String username;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private String evidence;

    @Column(name = "created_at",nullable = false)
    private Instant createdAt;
}
