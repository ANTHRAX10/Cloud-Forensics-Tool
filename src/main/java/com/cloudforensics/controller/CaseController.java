package com.cloudforensics.controller;

import com.cloudforensics.model.Alert;
import com.cloudforensics.model.IncidentCase;
import com.cloudforensics.model.LogEvent;
import com.cloudforensics.service.CorrelationService;
import com.cloudforensics.service.DetectionRuleService;
import com.cloudforensics.service.LogService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@CrossOrigin(origins = "*")
public class CaseController {

    private final LogService logService;
    private final DetectionRuleService detectionRuleService;
    private final CorrelationService correlationService;

    public CaseController(LogService logService,
                          DetectionRuleService detectionRuleService,
                          CorrelationService correlationService) {
        this.logService = logService;
        this.detectionRuleService = detectionRuleService;
        this.correlationService = correlationService;
    }

    @GetMapping("/api/cases")
    public List<IncidentCase> getCases() {
        List<LogEvent> logs = logService.getAllLogs();
        List<Alert> alerts = detectionRuleService.detectAlerts(logs);
        return correlationService.correlateCases(logs, alerts);
    }
}