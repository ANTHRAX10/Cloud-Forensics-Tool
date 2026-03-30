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
        // Group failed logins by user dynamically
        Map<String, List<LogEvent>> failuresByUser = logs.stream()
                .filter(log -> "ConsoleLogin".equals(log.getEventName()))
                .filter(log -> "FAILURE".equalsIgnoreCase(log.getEventOutcome()))
                .filter(log -> log.getUserIdentity() != null && log.getUserIdentity().getUserName() != null)
                .collect(java.util.stream.Collectors.groupingBy(
                        log -> log.getUserIdentity().getUserName()
                ));

        for (Map.Entry<String, List<LogEvent>> entry : failuresByUser.entrySet()) {
            List<LogEvent> userFailures = entry.getValue();
            if (userFailures.size() >= 3) {
                // Use the last failure event for timestamp and IP
                LogEvent lastFailure = userFailures.get(userFailures.size() - 1);
                alerts.add(new Alert(
                        UUID.randomUUID().toString(),
                        lastFailure.getEventTime(),
                        "Failed Login Burst",
                        "HIGH",
                        entry.getKey(),
                        lastFailure.getSourceIPAddress(),
                        "ConsoleLogin",
                        "Multiple failed login attempts (" + userFailures.size()
                                + ") detected for user '" + entry.getKey()
                                + "' from IP " + lastFailure.getSourceIPAddress() + "."
                ));
            }
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
        // Group storage access by user dynamically
        Map<String, List<LogEvent>> accessByUser = logs.stream()
                .filter(log -> "GetObject".equals(log.getEventName()))
                .filter(log -> log.getUserIdentity() != null && log.getUserIdentity().getUserName() != null)
                .collect(java.util.stream.Collectors.groupingBy(
                        log -> log.getUserIdentity().getUserName()
                ));

        for (Map.Entry<String, List<LogEvent>> entry : accessByUser.entrySet()) {
            List<LogEvent> userAccesses = entry.getValue();
            if (userAccesses.size() >= 3) {
                LogEvent lastAccess = userAccesses.get(userAccesses.size() - 1);
                alerts.add(new Alert(
                        UUID.randomUUID().toString(),
                        lastAccess.getEventTime(),
                        "Suspicious Storage Access",
                        "CRITICAL",
                        entry.getKey(),
                        lastAccess.getSourceIPAddress(),
                        "GetObject",
                        "Repeated access to cloud storage objects (" + userAccesses.size()
                                + " objects) detected for user '" + entry.getKey()
                                + "' — potential data exfiltration."
                ));
            }
        }
    }




    // =========================
// REQUIRED FOR TIMELINE
// =========================

public String getSeverity(LogEvent log) {
    if (log.getSeverity() != null) {
        return log.getSeverity();
    }

    // fallback if enrichLogs not called
    String event = log.getEventName();

    if (event == null) return "INFO";

    if ("GetObject".equals(event)) return "CRITICAL";

    if ("AttachUserPolicy".equals(event) ||
        "PutUserPolicy".equals(event) ||
        "CreateAccessKey".equals(event)) return "HIGH";

    if ("ConsoleLogin".equals(event) &&
        "FAILURE".equalsIgnoreCase(log.getEventOutcome())) return "MEDIUM";

    return "INFO";
}

public boolean isSuspicious(LogEvent log) {

    String severity = getSeverity(log);

    return "MEDIUM".equals(severity) ||
           "HIGH".equals(severity) ||
           "CRITICAL".equals(severity);
}
}
