package com.cloudforensics.model;

/**
 * Controls which sections are included in the generated report.
 * TECHNICAL   — includes full alert details, detection rules, raw evidence hashes.
 * EXECUTIVE   — includes only case summary and high-level risk assessment.
 * COMBINED    — includes all available sections.
 */
public enum ReportType {
    TECHNICAL,
    EXECUTIVE,
    COMBINED
}
