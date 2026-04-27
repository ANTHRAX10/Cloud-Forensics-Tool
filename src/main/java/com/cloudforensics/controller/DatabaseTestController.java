package com.cloudforensics.controller;

import com.cloudforensics.model.Alert;
import com.cloudforensics.model.IncidentCase;
import com.cloudforensics.model.LogEvent;
import com.cloudforensics.repository.AlertRepository;
import com.cloudforensics.repository.CaseRepository;
import com.cloudforensics.repository.LogRepository;
import com.cloudforensics.repository.StoredEvidenceRepository;
import com.cloudforensics.service.CorrelationService;
import com.cloudforensics.service.DetectionRuleService;
import com.cloudforensics.service.EvidenceLockerService;
import com.cloudforensics.service.LogService;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Test controller to verify MongoDB integration.
 * Provides endpoints to trigger the full forensic pipeline and check DB status.
 */
@RestController
@CrossOrigin(origins = "*")
@RequestMapping("/api/db")
public class DatabaseTestController {

    private final LogService logService;
    private final DetectionRuleService detectionRuleService;
    private final CorrelationService correlationService;
    private final EvidenceLockerService evidenceLockerService;
    private final LogRepository logRepository;
    private final AlertRepository alertRepository;
    private final CaseRepository caseRepository;
    private final StoredEvidenceRepository evidenceRepository;

    public DatabaseTestController(LogService logService,
                                   DetectionRuleService detectionRuleService,
                                   CorrelationService correlationService,
                                   EvidenceLockerService evidenceLockerService,
                                   LogRepository logRepository,
                                   AlertRepository alertRepository,
                                   CaseRepository caseRepository,
                                   StoredEvidenceRepository evidenceRepository) {
        this.logService = logService;
        this.detectionRuleService = detectionRuleService;
        this.correlationService = correlationService;
        this.evidenceLockerService = evidenceLockerService;
        this.logRepository = logRepository;
        this.alertRepository = alertRepository;
        this.caseRepository = caseRepository;
        this.evidenceRepository = evidenceRepository;
    }

    /**
     * GET /api/db/status — Returns current document counts from all 4 MongoDB collections.
     */
    @GetMapping("/status")
    public Map<String, Object> getDbStatus() {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("database", "cloudforensics");
        status.put("logs_count", logRepository.count());
        status.put("alerts_count", alertRepository.count());
        status.put("cases_count", caseRepository.count());
        status.put("evidence_count", evidenceRepository.count());
        status.put("status", "CONNECTED");
        return status;
    }

    /**
     * GET /api/db/test — Runs the full pipeline and returns insertion summary.
     * Pipeline: parse logs → detect alerts → correlate cases → store evidence
     */
    @GetMapping("/test")
    public Map<String, Object> testFullPipeline() {
        Map<String, Object> result = new LinkedHashMap<>();

        try {
            // Step 1: Parse and save logs
            List<LogEvent> logs = logService.getAllLogs();
            result.put("logs_parsed_and_saved", logs.size());

            // Step 2: Detect and save alerts
            List<Alert> alerts = detectionRuleService.detectAlerts(logs);
            result.put("alerts_detected_and_saved", alerts.size());

            // Step 3: Correlate and save cases
            List<IncidentCase> cases = correlationService.correlateCases(logs, alerts);
            result.put("cases_correlated_and_saved", cases.size());

            // Step 4: Store evidence with SHA-256 hashes
            evidenceLockerService.storeBatch(logs, alerts, cases);
            result.put("evidence_stored", logs.size() + alerts.size() + cases.size());

            // Final counts from DB
            result.put("total_logs_in_db", logRepository.count());
            result.put("total_alerts_in_db", alertRepository.count());
            result.put("total_cases_in_db", caseRepository.count());
            result.put("total_evidence_in_db", evidenceRepository.count());

            result.put("pipeline_status", "SUCCESS");

        } catch (Exception e) {
            result.put("pipeline_status", "FAILED");
            result.put("error", e.getMessage());
        }

        return result;
    }
}
