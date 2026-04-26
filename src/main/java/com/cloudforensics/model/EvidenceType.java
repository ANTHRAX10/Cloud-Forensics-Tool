package com.cloudforensics.model;

/**
 * Classifies the type of digital evidence captured during a forensic investigation.
 *
 * LOG_BUNDLE       — Aggregated cloud provider log files (e.g., CloudTrail batch)
 * CONFIG_SNAPSHOT  — Infrastructure configuration state at a point in time
 * NETWORK_CAPTURE  — Network flow logs, VPC traffic, or packet captures
 * IAM_SNAPSHOT     — Identity and access management policy/role snapshots
 */
public enum EvidenceType {
    LOG_BUNDLE,
    CONFIG_SNAPSHOT,
    NETWORK_CAPTURE,
    IAM_SNAPSHOT
}
