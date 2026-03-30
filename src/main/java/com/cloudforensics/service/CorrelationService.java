package com.cloudforensics.service;

import com.cloudforensics.model.Alert;
import com.cloudforensics.model.IncidentCase;
import com.cloudforensics.model.LogEvent;
import com.cloudforensics.model.LogResponseDTO;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
public class CorrelationService {

    // Event types considered suspicious for correlation
    private static final Set<String> SUSPICIOUS_EVENTS = Set.of(
            "ConsoleLogin", "AttachUserPolicy", "PutUserPolicy",
            "CreateAccessKey", "ListBuckets", "ListUsers",
            "DescribeInstances", "GetObject", "DeleteBucket", "StopInstances"
    );

    public List<IncidentCase> correlateCases(List<LogEvent> logs, List<Alert> alerts) {
        List<IncidentCase> cases = new ArrayList<>();

        // Group logs by userName dynamically
        Map<String, List<LogEvent>> logsByUser = logs.stream()
                .filter(log -> log.getUserIdentity() != null && log.getUserIdentity().getUserName() != null)
                .collect(Collectors.groupingBy(log -> log.getUserIdentity().getUserName()));

        // Group alerts by user for quick lookup
        Map<String, List<Alert>> alertsByUser = alerts.stream()
                .filter(a -> a.getUser() != null)
                .collect(Collectors.groupingBy(Alert::getUser));

        int caseCounter = 1;

        for (Map.Entry<String, List<LogEvent>> entry : logsByUser.entrySet()) {
            String userName = entry.getKey();
            List<LogEvent> userLogs = entry.getValue();

            // Filter to suspicious events for this user
            List<LogEvent> suspiciousChain = userLogs.stream()
                    .filter(log -> SUSPICIOUS_EVENTS.contains(log.getEventName()))
                    .collect(Collectors.toList());

            // Check if this user has enough alerts and suspicious events to warrant a case
            List<Alert> userAlerts = alertsByUser.getOrDefault(userName, Collections.emptyList());

            if (userAlerts.size() >= 2 && suspiciousChain.size() >= 3) {
                List<LogResponseDTO> eventDtos = suspiciousChain.stream()
                        .map(LogResponseDTO::fromLogEvent)
                        .collect(Collectors.toList());

                // Determine the most common IP for this user
                String primaryIp = suspiciousChain.stream()
                        .map(LogEvent::getSourceIPAddress)
                        .filter(Objects::nonNull)
                        .collect(Collectors.groupingBy(ip -> ip, Collectors.counting()))
                        .entrySet().stream()
                        .max(Map.Entry.comparingByValue())
                        .map(Map.Entry::getKey)
                        .orElse("Unknown");

                // Determine severity based on alert severity levels
                String severity = determineCaseSeverity(userAlerts);

                // Build a dynamic correlation reason from actual event types
                String reason = buildCorrelationReason(suspiciousChain);

                String caseId = String.format("CF-%03d", caseCounter++);

                cases.add(new IncidentCase(
                        caseId,
                        userName,
                        primaryIp,
                        severity,
                        suspiciousChain.size(),
                        eventDtos,
                        reason
                ));
            }
        }

        return cases;
    }

    private String determineCaseSeverity(List<Alert> userAlerts) {
        boolean hasCritical = userAlerts.stream()
                .anyMatch(a -> "CRITICAL".equalsIgnoreCase(a.getSeverity()));
        boolean hasHigh = userAlerts.stream()
                .anyMatch(a -> "HIGH".equalsIgnoreCase(a.getSeverity()));

        if (hasCritical) return "CRITICAL";
        if (hasHigh) return "HIGH";
        return "MEDIUM";
    }

    private String buildCorrelationReason(List<LogEvent> chain) {
        Set<String> eventTypes = chain.stream()
                .map(LogEvent::getEventName)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        List<String> stages = new ArrayList<>();
        if (eventTypes.contains("ConsoleLogin")) stages.add("authentication anomalies");
        if (eventTypes.stream().anyMatch(e -> e.contains("Policy") || e.contains("AccessKey")))
            stages.add("privilege escalation");
        if (eventTypes.stream().anyMatch(e -> e.contains("List") || e.contains("Describe")))
            stages.add("reconnaissance activity");
        if (eventTypes.contains("GetObject")) stages.add("data access/exfiltration");

        if (stages.isEmpty()) stages.add("suspicious behavioral pattern");

        return "Correlated suspicious activity: " + String.join(", ", stages) + ".";
    }
}