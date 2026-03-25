package com.cloudforensics.service;

import com.cloudforensics.model.LogEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.util.Collections;
import java.util.List;

@Service
public class LogService {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public List<LogEvent> getAllLogs() {
        try {
            ClassPathResource resource = new ClassPathResource("logs/logs.json");
            InputStream inputStream = resource.getInputStream();
            return objectMapper.readValue(inputStream, new TypeReference<List<LogEvent>>() {});
        } catch (Exception e) {
            e.printStackTrace();
            return Collections.emptyList();
        }
    }
}