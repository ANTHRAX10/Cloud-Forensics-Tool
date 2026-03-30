package com.cloudforensics.service;

import com.cloudforensics.model.LogEvent;
import com.cloudforensics.util.CloudLogParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class LogService {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DetectionRuleService detectionRuleService;

    public LogService(DetectionRuleService detectionRuleService) {
        this.detectionRuleService = detectionRuleService;
    }

    /**
     * MAIN: Get all logs (parsed + enriched + sorted)
     */
    public List<LogEvent> getAllLogs() {
        List<LogEvent> logs = loadAndParseLogs();

        if (logs.isEmpty()) return logs;

        // Apply detection rules
        detectionRuleService.enrichLogs(logs);

        // Sort by timestamp
        logs.sort(Comparator.comparing(LogEvent::getTimestamp));

        return logs;
    }

    /**
     * FILTER: Logs by User
     */
    public List<LogEvent> getLogsByUser(String userId) {
        return getAllLogs().stream()
                .filter(log -> log.getUserId().equalsIgnoreCase(userId))
                .collect(Collectors.toList());
    }

    /**
     * FILTER: Logs by IP
     */
    public List<LogEvent> getLogsByIp(String ip) {
        return getAllLogs().stream()
                .filter(log -> log.getIpAddress().equals(ip))
                .collect(Collectors.toList());
    }

    /**
     * INTERNAL: Load + parse logs safely
     */
    private List<LogEvent> loadAndParseLogs() {
        try {
            ClassPathResource resource = new ClassPathResource("logs/logs.json");
            InputStream inputStream = resource.getInputStream();

            List<Map<String, Object>> rawLogs = objectMapper.readValue(
                    inputStream,
                    new TypeReference<List<Map<String, Object>>>() {}
            );

            return rawLogs.stream()
                    .map(this::safeParse)
                    .filter(Objects::nonNull)
                    .collect(Collectors.toList());

        } catch (Exception e) {
            System.err.println("Error loading logs: " + e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * SAFE PARSER WRAPPER (prevents crashes)
     */
    private LogEvent safeParse(Map<String, Object> raw) {
        try {
            return CloudLogParser.parseLog(raw);
        } catch (Exception e) {
            System.err.println("Skipping bad log: " + e.getMessage());
            return null;
        }
    }
}