package com.cloudforensics.controller;

import com.cloudforensics.model.DashboardStats;
import com.cloudforensics.service.DashboardService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller exposing the dashboard statistics endpoint.
 */
@RestController
@CrossOrigin(origins = {"http://localhost:3000", "http://localhost:5500"})
public class DashboardController {

    private final DashboardService dashboardService;

    @Autowired
    public DashboardController(DashboardService dashboardService) {
        this.dashboardService = dashboardService;
    }

    @GetMapping("/api/dashboard")
    public DashboardStats getStats() {
        return dashboardService.getDashboardStats();
    }
}
