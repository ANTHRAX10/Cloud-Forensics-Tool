package com.cloudforensics.model;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * JPA entity that persists lightweight report metadata to the H2 in-memory database.
 * Stores only the minimum needed to list reports and serve PDF downloads —
 * the full ForensicReport domain object is cached in-memory in the service layer.
 *
 * Table: forensic_report_metadata
 */
@Entity
@Table(name = "forensic_report_metadata")
public class ForensicReportMetadata {

    /** UUID primary key assigned at generation time. */
    @Id
    private String reportId;

    /** ISO-8601 UTC generation timestamp. */
    private Instant generatedAt;

    /** TECHNICAL / EXECUTIVE / COMBINED. */
    @Enumerated(EnumType.STRING)
    private ReportType reportType;

    /** Current lifecycle status of the generation job. */
    @Enumerated(EnumType.STRING)
    private ReportStatus status;

    /** Analyst name from the original request. */
    private String investigatorName;

    /** Organization name from the original request. */
    private String organizationName;

    /** Number of IncidentCases included in this report. */
    private int caseCount;

    /** Non-null error message if status == FAILED. */
    private String errorMessage;

    public ForensicReportMetadata() {}

    public ForensicReportMetadata(String reportId, Instant generatedAt, ReportType reportType,
                                   ReportStatus status, String investigatorName,
                                   String organizationName, int caseCount) {
        this.reportId = reportId;
        this.generatedAt = generatedAt;
        this.reportType = reportType;
        this.status = status;
        this.investigatorName = investigatorName;
        this.organizationName = organizationName;
        this.caseCount = caseCount;
    }

    // ─── Getters & Setters ───────────────────────────────────────────────────

    public String getReportId() { return reportId; }
    public void setReportId(String reportId) { this.reportId = reportId; }

    public Instant getGeneratedAt() { return generatedAt; }
    public void setGeneratedAt(Instant generatedAt) { this.generatedAt = generatedAt; }

    public ReportType getReportType() { return reportType; }
    public void setReportType(ReportType reportType) { this.reportType = reportType; }

    public ReportStatus getStatus() { return status; }
    public void setStatus(ReportStatus status) { this.status = status; }

    public String getInvestigatorName() { return investigatorName; }
    public void setInvestigatorName(String investigatorName) { this.investigatorName = investigatorName; }

    public String getOrganizationName() { return organizationName; }
    public void setOrganizationName(String organizationName) { this.organizationName = organizationName; }

    public int getCaseCount() { return caseCount; }
    public void setCaseCount(int caseCount) { this.caseCount = caseCount; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
}
