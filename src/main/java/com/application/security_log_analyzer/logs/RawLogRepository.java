package com.application.security_log_analyzer.logs;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RawLogRepository extends JpaRepository<RawLog,Long> {

}
