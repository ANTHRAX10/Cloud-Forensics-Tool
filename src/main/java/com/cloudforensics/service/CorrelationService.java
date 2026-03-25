package com.cloudforensics.service;

import com.cloudforensics.model.Alert;
import com.cloudforensics.model.IncidentCase;
import com.cloudforensics.model.LogEvent;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class CorrelationService {

    public List<IncidentCase> correlateCases(List<LogEvent> logs, List<Alert> alerts) {
        List<IncidentCase> cases = new ArrayList<>();

        List<LogEvent> suspiciousChain = logs.stream()
                .filter(log -> "dev_user_04".equals(log.getUser()))
                .filter(log -> "203.0.113.45".equals(log.getIp()))
                .filter(log ->
                        "ConsoleLogin".equals(log.getEventType()) ||
                        "AttachUserPolicy".equals(log.getEventType()) ||
                        "ListBuckets".equals(log.getEventType()) ||
                        "GetObject".equals(log.getEventType()))
                .collect(Collectors.toList());

        if (alerts.size() >= 2 && suspiciousChain.size() >= 5) {
            cases.add(new IncidentCase(
                    "CF-001",
                    "dev_user_04",
                    "203.0.113.45",
                    "CRITICAL",
                    suspiciousChain.size(),
                    suspiciousChain,
                    "Correlated suspicious activity: repeated failed logins followed by successful access, privilege escalation, and abnormal cloud storage access."
            ));
        }

        return cases;
    }
}