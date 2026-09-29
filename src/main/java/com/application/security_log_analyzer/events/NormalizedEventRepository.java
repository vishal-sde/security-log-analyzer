package com.application.security_log_analyzer.events;


import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface NormalizedEventRepository extends JpaRepository<NormalizeEvent,Long>, JpaSpecificationExecutor<NormalizeEvent> {
}
