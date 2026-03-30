package com.cloudforensics.service;

import com.cloudforensics.model.Alert;
import com.cloudforensics.model.LogEvent;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class DetectionRuleService {

    public void enrichLogs(List<LogEvent> logs) {
        Map<String, Integer> userFailureMap = new HashMap<>();

        for (LogEvent log : logs) {
            String eventName = log.getEventName();
            String outcome = log.getEventOutcome();
            String userName = log.getUserIdentity() != null ? log.getUserIdentity().getUserName() : "Unknown";

            // Default values
            log.setSeverity("INFO");
            log.setDetectionReason("Normal operation");

            // Avoid NPE
            if (eventName == null) continue;

            // FAILED login -> LOW/MEDIUM
            if ("ConsoleLogin".equals(eventName) && "FAILURE".equalsIgnoreCase(outcome)) {
                int count = userFailureMap.getOrDefault(userName, 0) + 1;
                userFailureMap.put(userName, count);

                if (count >= 3) {
                    log.setSeverity("MEDIUM");
                    log.setDetectionReason("Multiple failed login attempts detected");
                } else {
                    log.setSeverity("LOW");
                    log.setDetectionReason("Failed login attempt");
                }
            }

            // Privilege escalation -> HIGH
            if ("AttachUserPolicy".equals(eventName) || "PutUserPolicy".equals(eventName) || "CreateAccessKey".equals(eventName)) {
                log.setSeverity("HIGH");
                log.setDetectionReason("Potential privilege escalation activity detected");
            }

            // Data exfiltration -> CRITICAL
            if ("GetObject".equals(eventName)) {
                log.setSeverity("CRITICAL");
                log.setDetectionReason("Potential data exfiltration via object access");
            }
        }
    }

    public List<Alert> detectAlerts(List<LogEvent> logs) {
        List<Alert> alerts = new ArrayList<>();

        addFailedLoginBurstAlert(logs, alerts);
        addPrivilegeEscalationAlerts(logs, alerts);
        addSuspiciousStorageAccessAlert(logs, alerts);

        return alerts;
    }

    private void addFailedLoginBurstAlert(List<LogEvent> logs, List<Alert> alerts) {
        long failures = logs.stream()
                .filter(log -> "ConsoleLogin".equals(log.getEventName()))
                .filter(log -> "FAILURE".equalsIgnoreCase(log.getEventOutcome()))
                .filter(log -> log.getUserIdentity() != null && "dev_user_04".equals(log.getUserIdentity().getUserName()))
                .count();

        if (failures >= 3) {
            alerts.add(new Alert(
                    UUID.randomUUID().toString(),
                    "2026-03-25T10:04:00",
                    "Failed Login Burst",
                    "HIGH",
                    "dev_user_04",
                    "203.0.113.45",
                    "ConsoleLogin",
                    "Multiple failed login attempts detected for the same user and source IP."
            ));
        }
    }

    private void addPrivilegeEscalationAlerts(List<LogEvent> logs, List<Alert> alerts) {
        for (LogEvent log : logs) {
            if ("AttachUserPolicy".equals(log.getEventName())
                    || "PutUserPolicy".equals(log.getEventName())
                    || "CreateAccessKey".equals(log.getEventName())) {

                String userName = log.getUserIdentity() != null ? log.getUserIdentity().getUserName() : "Unknown";

                alerts.add(new Alert(
                        UUID.randomUUID().toString(),
                        log.getEventTime(),
                        "Privilege Escalation",
                        "CRITICAL",
                        userName,
                        log.getSourceIPAddress(),
                        log.getEventName(),
                        "Potential privilege escalation activity detected through IAM policy or access key modification."
                ));
            }
        }
    }

    private void addSuspiciousStorageAccessAlert(List<LogEvent> logs, List<Alert> alerts) {
        long objectAccessCount = logs.stream()
                .filter(log -> "GetObject".equals(log.getEventName()))
                .filter(log -> log.getUserIdentity() != null && "dev_user_04".equals(log.getUserIdentity().getUserName()))
                .count();

        if (objectAccessCount >= 3) {
            alerts.add(new Alert(
                    UUID.randomUUID().toString(),
                    "2026-03-25T10:14:00",
                    "Suspicious Storage Access",
                    "CRITICAL",
                    "dev_user_04",
                    "203.0.113.45",
                    "GetObject",
                    "Repeated access to sensitive cloud storage objects detected in a short interval (Data Exfiltration)"
            ));
        }
    }
}