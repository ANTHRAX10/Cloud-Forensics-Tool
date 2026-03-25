package com.cloudforensics.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data transfer object representing the metrics displayed on the dashboard.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class DashboardStats {
    private long totalEvents;
    private int criticalAlerts;
    private int activeCases;
    private String integrityRate;
}
