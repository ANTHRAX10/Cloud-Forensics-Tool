package com.cloudforensics.service;

import com.cloudforensics.model.LogEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Service responsible for loading and filtering log events from a JSON file.
 */
@Service
public class LogService {

    private static final String LOG_FILE_PATH = "logs/logs.json";
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Reads all log entries from the classpath JSON file.
     *
     * @return list of {@link LogEvent}
     */
    public List<LogEvent> getAllLogs() {
        try {
            ClassPathResource resource = new ClassPathResource(LOG_FILE_PATH);
            try (InputStream is = resource.getInputStream()) {
                return objectMapper.readValue(is, new TypeReference<List<LogEvent>>() {});
            }
        } catch (IOException ex) {
            // in production we might log this and rethrow a custom exception
            ex.printStackTrace();
            return Collections.emptyList();
        }
    }

    /**
     * Optional helper to filter logs by severity and/or user. Parameters may be null.
     */
    public List<LogEvent> filterLogs(String severity, String user) {
        List<LogEvent> all = getAllLogs();
        return all.stream()
                .filter(e -> severity == null || severity.equalsIgnoreCase(e.getSeverity()))
                .filter(e -> user == null || user.equalsIgnoreCase(e.getUser()))
                .collect(Collectors.toList());
    }
}
