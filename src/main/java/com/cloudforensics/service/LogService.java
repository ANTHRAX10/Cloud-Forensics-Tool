package com.cloudforensics.service;

import com.cloudforensics.model.LogEvent;
import com.cloudforensics.util.CloudLogParser;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class LogService {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final DetectionRuleService detectionRuleService;

    public LogService(DetectionRuleService detectionRuleService) {
        this.detectionRuleService = detectionRuleService;
    }

    public List<LogEvent> getAllLogs() {
        try {
            ClassPathResource resource = new ClassPathResource("logs/logs.json");
            InputStream inputStream = resource.getInputStream();
            
            List<Map<String, Object>> rawLogs = objectMapper.readValue(inputStream, new TypeReference<List<Map<String, Object>>>() {});
            
            List<LogEvent> parsedLogs = rawLogs.stream()
                    .map(CloudLogParser::parseLog)
                    .collect(Collectors.toList());
                    
            detectionRuleService.enrichLogs(parsedLogs);
            
            return parsedLogs;
        } catch (Exception e) {
            e.printStackTrace();
            return Collections.emptyList();
        }
    }
}