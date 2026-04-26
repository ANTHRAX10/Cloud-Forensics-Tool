package com.cloudforensics.model;

/**
 * Lifecycle status for a forensic report generation job.
 * PENDING     — request accepted, not yet started.
 * GENERATING  — actively building the PDF.
 * COMPLETE    — PDF is available for download.
 * FAILED      — an error occurred during generation.
 */
public enum ReportStatus {
    PENDING,
    GENERATING,
    COMPLETE,
    FAILED
}
