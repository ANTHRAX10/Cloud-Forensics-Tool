package com.cloudforensics.controller;

import com.cloudforensics.model.Alert;
import com.cloudforensics.model.IncidentCase;
import com.cloudforensics.model.LogEvent;
import com.cloudforensics.model.StoredEvidence;
import com.cloudforensics.service.CorrelationService;
import com.cloudforensics.service.DetectionRuleService;
import com.cloudforensics.service.EvidenceLockerService;
import com.cloudforensics.service.LogService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/evidence")
public class EvidenceLockerController {

    private final EvidenceLockerService evidenceLockerService;
    private final LogService logService;
    private final DetectionRuleService detectionRuleService;
    private final CorrelationService correlationService;

    public EvidenceLockerController(EvidenceLockerService evidenceLockerService,
                                    LogService logService,
                                    DetectionRuleService detectionRuleService,
                                    CorrelationService correlationService) {
        this.evidenceLockerService = evidenceLockerService;
        this.logService = logService;
        this.detectionRuleService = detectionRuleService;
        this.correlationService = correlationService;
    }

    @GetMapping
    public List<StoredEvidence> getAllEvidence() {
        return evidenceLockerService.getAllEvidence();
    }

    @GetMapping("/{evidenceId}/verify")
    public EvidenceLockerService.IntegrityResult verifyIntegrity(@PathVariable String evidenceId) {
        return evidenceLockerService.verifyIntegrity(evidenceId);
    }
    
    @GetMapping("/verify-all")
    public List<EvidenceLockerService.IntegrityResult> verifyAll() {
        return evidenceLockerService.verifyAll();
    }

    @PostMapping("/store-batch")
    public String storeBatch() {
        List<LogEvent> logs = logService.getAllLogs();
        List<Alert> alerts = detectionRuleService.detectAlerts(logs);
        List<IncidentCase> cases = correlationService.correlateCases(logs, alerts);

        evidenceLockerService.storeBatch(logs, alerts, cases);
        return "Batch stored successfully. Locked " + logs.size() + " logs, " + 
               alerts.size() + " alerts, and " + cases.size() + " cases.";
    }
}
