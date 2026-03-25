package com.cloudforensics.service;

import com.cloudforensics.model.DashboardStats;
import org.springframework.stereotype.Service;

/**
 * Service layer for computing dashboard statistics.  Currently returns
 * hardcoded/mock values; in a real application these would be derived
 * from persisted data or analytics.
 */
@Service
public class DashboardService {

    public DashboardStats getDashboardStats() {
        // Return static mock data for now
        return new DashboardStats(48291L, 7, 3, "99.8%");
    }
}
