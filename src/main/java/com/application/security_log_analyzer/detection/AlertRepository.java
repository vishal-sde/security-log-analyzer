package com.application.security_log_analyzer.detection;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface AlertRepository extends JpaRepository<Alert,Long>, JpaSpecificationExecutor<Alert> {
}
