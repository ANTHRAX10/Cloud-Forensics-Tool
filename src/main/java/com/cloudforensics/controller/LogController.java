package com.cloudforensics.controller;

import com.cloudforensics.model.LogResponseDTO;
import com.cloudforensics.service.LogService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@CrossOrigin(origins = "*")
public class LogController {

    private final LogService logService;

    public LogController(LogService logService) {
        this.logService = logService;
    }

    @GetMapping("/api/logs")
    public List<LogResponseDTO> getLogs() {
        return logService.getAllLogs().stream()
                .map(LogResponseDTO::fromLogEvent)
                .collect(Collectors.toList());
    }
}