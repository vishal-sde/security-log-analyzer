package com.application.security_log_analyzer.events;

import com.application.security_log_analyzer.logs.EventType;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;

@Entity
@Table(name = "normalized_events",indexes = {
        @Index(name = "idx_events_ip",columnList = "ip"),
        @Index(name = "idx_events_username",columnList = "username"),
        @Index(name = "idx_events_type",columnList = "event_type"),
        @Index(name = "idx_events_occurred_at",columnList = "occurred_at")
})
@Getter
@Setter
@NoArgsConstructor
public class NormalizeEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String ip;

    @Column(nullable = false)
    private String username;

    @Column(name = "event_type",nullable = false)
    @Enumerated(EnumType.STRING)
    private EventType eventType;

    @Column(name = "occurred_at",nullable = false)
    private Instant occurredAt;

    @Column(name = "raw_log_id",nullable = false,unique = true)
    private Long rawLogId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private String details;


}
