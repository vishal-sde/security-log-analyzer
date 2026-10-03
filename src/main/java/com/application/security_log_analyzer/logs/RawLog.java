package com.application.security_log_analyzer.logs;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;

@Entity
@Table(name = "raw_logs",indexes = {
        @Index(name = "idx_raw_logs_event_id",columnList = "event_id",unique = true)
})
@Getter
@Setter
@NoArgsConstructor
public class RawLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String source;

    @Column(name = "event_id")
    private String eventId;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb",nullable = false)
    private String payLoad;

    @Column(name = "received_at",nullable = false)
    private Instant receivedAt;

    public RawLog(String source, String eventId, String payLoad, Instant receivedAt){
        this.source = source;
        this.eventId = eventId;
        this.payLoad = payLoad;
        this.receivedAt = receivedAt;

    }
}
