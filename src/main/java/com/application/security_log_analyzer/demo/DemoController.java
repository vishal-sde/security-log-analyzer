package com.application.security_log_analyzer.demo;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/demo")
@RequiredArgsConstructor
public class DemoController {

    private final DemoSeedService demoSeedService;

    @PostMapping("/seed")
    public Map<String, String> seed() {
        demoSeedService.runScenario();
        return Map.of("status", "seeded");
    }
}