package com.cloudforensics.controller;

import com.cloudforensics.model.Alert;
import com.cloudforensics.model.LogEvent;
import com.cloudforensics.service.DetectionRuleService;
import com.cloudforensics.service.LogService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@CrossOrigin(origins = "*")
public class AlertController {

    private final LogService logService;
    private final DetectionRuleService detectionRuleService;

    public AlertController(LogService logService, DetectionRuleService detectionRuleService) {
        this.logService = logService;
        this.detectionRuleService = detectionRuleService;
    }

    @GetMapping("/api/alerts")
    public List<Alert> getAlerts() {
        List<LogEvent> logs = logService.getAllLogs();
        return detectionRuleService.detectAlerts(logs);
    }
}