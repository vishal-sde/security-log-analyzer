package com.application.security_log_analyzer.events;

import com.application.security_log_analyzer.logs.EventType;
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
@RequestMapping("/api/events")
@RequiredArgsConstructor
public class EventController {

    private final NormalizedEventRepository repository;

    public record EventResponse(Long id, String ip, String username, EventType eventType, Instant occurredAt,Long rawLogId,String details){
        static EventResponse from(NormalizeEvent e){
            return new EventResponse(e.getId(),e.getIp(),e.getUsername(),e.getEventType(),e.getOccurredAt(),e.getRawLogId(),e.getDetails());

        }
    }

    @GetMapping
    public List<EventResponse> search(@RequestParam(required = false) String ip,
                                      @RequestParam(required = false) String username,
                                      @RequestParam(required = false) EventType type,
                                      @RequestParam(defaultValue = "50") int limit){

        Specification<NormalizeEvent> spec = ((root, query, criteriaBuilder) -> criteriaBuilder.conjunction());
        if(ip != null){
            spec = spec.and(((root, query, criteriaBuilder) -> criteriaBuilder.equal(root.get("ip"),ip)));
        }
        if(username != null){
            spec = spec.and(((root, query, criteriaBuilder) -> criteriaBuilder.equal(root.get("username"),username)));
        }
        if(type != null){
            spec = spec.and(((root, query, criteriaBuilder) -> criteriaBuilder.equal(root.get("eventType"),type)));
        }

        return repository.findAll(spec, PageRequest.of(0,Math.min(limit,500), Sort.by(Sort.Direction.DESC,"occurredAt")))
                .getContent().stream().map(EventResponse::from).toList();
    }

    @GetMapping("/stats")
    public java.util.Map<String,Object> stats(){
        return java.util.Map.of("totalEvents",repository.count());
    }

}
