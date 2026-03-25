package com.cloudforensics.controller;

import com.cloudforensics.model.LogEvent;
import com.cloudforensics.service.LogService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@CrossOrigin(origins = "*")
public class LogController {

    private final LogService logService;

    public LogController(LogService logService) {
        this.logService = logService;
    }

    @GetMapping("/api/logs")
    public List<LogEvent> getLogs() {
        return logService.getAllLogs();
    }
}