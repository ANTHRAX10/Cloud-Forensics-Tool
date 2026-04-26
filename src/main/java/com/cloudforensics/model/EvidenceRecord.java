package com.cloudforensics.model;

/**
 * Represents a single piece of evidence captured from a log event,
 * including full chain of custody metadata.
 *
 * Chain of Custody fields:
 *   evidenceName  — human-readable label (e.g., "cloudtrail-2026-03-25-batch-001")
 *   evidenceType  — classification enum: LOG_BUNDLE, CONFIG_SNAPSHOT, NETWORK_CAPTURE, IAM_SNAPSHOT
 *   collectedBy   — investigator username who collected/captured this evidence
 *
 * The SHA-256 hash is computed deterministically from the event's key fields
 * to guarantee evidence integrity and prevent tampering.
 */
public class EvidenceRecord {

    /** Human-readable label for this evidence item (e.g. "ConsoleLogin by root"). */
    private String name;

    /** SHA-256 hex digest of (eventTime + eventName + userName). */
    private String sha256Hash;

    /** Whether the hash has been verified against the original source. */
    private boolean verified;

    /** Originating event timestamp. */
    private String timestamp;

    /** Source IP address associated with the event. */
    private String sourceIp;

    // ─── Chain of Custody Fields ─────────────────────────────────────────────

    /** Human-readable evidence label (e.g. "cloudtrail-2026-03-25-batch-001"). */
    private String evidenceName;

    /** Evidence classification: LOG_BUNDLE, CONFIG_SNAPSHOT, NETWORK_CAPTURE, IAM_SNAPSHOT. */
    private EvidenceType evidenceType;

    /** Investigator username who collected this evidence (future-proofed for auth). */
    private String collectedBy;

    public EvidenceRecord() {}

    /**
     * Legacy constructor — backward compatible with existing callers.
     */
    public EvidenceRecord(String name, String sha256Hash, boolean verified,
                          String timestamp, String sourceIp) {
        this.name = name;
        this.sha256Hash = sha256Hash;
        this.verified = verified;
        this.timestamp = timestamp;
        this.sourceIp = sourceIp;
    }

    /**
     * Full constructor including chain of custody fields.
     */
    public EvidenceRecord(String name, String sha256Hash, boolean verified,
                          String timestamp, String sourceIp,
                          String evidenceName, EvidenceType evidenceType,
                          String collectedBy) {
        this.name = name;
        this.sha256Hash = sha256Hash;
        this.verified = verified;
        this.timestamp = timestamp;
        this.sourceIp = sourceIp;
        this.evidenceName = evidenceName;
        this.evidenceType = evidenceType;
        this.collectedBy = collectedBy;
    }

    // ─── Getters & Setters ───────────────────────────────────────────────────

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getSha256Hash() { return sha256Hash; }
    public void setSha256Hash(String sha256Hash) { this.sha256Hash = sha256Hash; }

    public boolean isVerified() { return verified; }
    public void setVerified(boolean verified) { this.verified = verified; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getEvidenceName() { return evidenceName; }
    public void setEvidenceName(String evidenceName) { this.evidenceName = evidenceName; }

    public EvidenceType getEvidenceType() { return evidenceType; }
    public void setEvidenceType(EvidenceType evidenceType) { this.evidenceType = evidenceType; }

    public String getCollectedBy() { return collectedBy; }
    public void setCollectedBy(String collectedBy) { this.collectedBy = collectedBy; }
}
