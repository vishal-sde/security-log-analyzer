package com.application.security_log_analyzer.logs;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RawLogRepository extends JpaRepository<RawLog,Long> {
    Optional<RawLog> findByEventId(String eventId);

}
