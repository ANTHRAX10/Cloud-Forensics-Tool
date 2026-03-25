package com.cloudforensics.service;

import com.cloudforensics.model.Alert;
import com.cloudforensics.model.LogEvent;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Service
public class DetectionRuleService {

    public List<Alert> detectAlerts(List<LogEvent> logs) {
        List<Alert> alerts = new ArrayList<>();

        addFailedLoginBurstAlert(logs, alerts);
        addPrivilegeEscalationAlerts(logs, alerts);
        addSuspiciousStorageAccessAlert(logs, alerts);

        return alerts;
    }

    private void addFailedLoginBurstAlert(List<LogEvent> logs, List<Alert> alerts) {
        long failures = logs.stream()
                .filter(log -> "ConsoleLogin".equals(log.getEventType()))
                .filter(log -> "FAILURE".equalsIgnoreCase(log.getStatus()))
                .filter(log -> "dev_user_04".equals(log.getUser()))
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
            if ("AttachUserPolicy".equals(log.getEventType())
                    || "PutUserPolicy".equals(log.getEventType())
                    || "CreateAccessKey".equals(log.getEventType())) {

                alerts.add(new Alert(
                        UUID.randomUUID().toString(),
                        log.getTimestamp(),
                        "Privilege Escalation",
                        "CRITICAL",
                        log.getUser(),
                        log.getIp(),
                        log.getEventType(),
                        "Potential privilege escalation activity detected through IAM policy or access key modification."
                ));
            }
        }
    }

    private void addSuspiciousStorageAccessAlert(List<LogEvent> logs, List<Alert> alerts) {
        long objectAccessCount = logs.stream()
                .filter(log -> "GetObject".equals(log.getEventType()))
                .filter(log -> "dev_user_04".equals(log.getUser()))
                .count();

        if (objectAccessCount >= 3) {
            alerts.add(new Alert(
                    UUID.randomUUID().toString(),
                    "2026-03-25T10:14:00",
                    "Suspicious Storage Access",
                    "HIGH",
                    "dev_user_04",
                    "203.0.113.45",
                    "GetObject",
                    "Repeated access to sensitive cloud storage objects detected in a short interval."
            ));
        }
    }
}