package com.cloudforensics.controller;

import com.cloudforensics.model.LogEvent;
import com.cloudforensics.service.LogService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Controller that provides log data to the frontend. Supports optional
 * filtering by severity and user through query parameters.
 */
@RestController
@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:5500"})
public class LogController {

    private final LogService logService;

    @Autowired
    public LogController(LogService logService) {
        this.logService = logService;
    }

    @GetMapping("/api/logs")
    public List<LogEvent> getLogs(
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String user) {
        if (severity != null || user != null) {
            return logService.filterLogs(severity, user);
        }
        return logService.getAllLogs();
    }
}
