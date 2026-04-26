package com.cloudforensics.model;

import java.util.List;

/**
 * Request DTO for the POST /api/reports/generate endpoint.
 *
 * Example JSON body:
 * {
 *   "caseIds": ["CF-001", "CF-002"],
 *   "reportType": "COMBINED",
 *   "includeTimeline": true,
 *   "includeMitreMapping": true,
 *   "includeEvidenceHashes": true,
 *   "investigatorName": "Alice Smith",
 *   "organizationName": "Acme Corp"
 * }
 */
public class ReportRequest {

    /** Case IDs to include in the report (e.g. "CF-001"). Empty list = all cases. */
    private List<String> caseIds;

    /** Controls which sections are rendered. Defaults to COMBINED if null. */
    private ReportType reportType;

    /** Whether to include the chronological attack timeline section. */
    private boolean includeTimeline = true;

    /** Whether to include the MITRE ATT&CK technique mapping section. */
    private boolean includeMitreMapping = true;

    /** Whether to include evidence SHA-256 hash table. */
    private boolean includeEvidenceHashes = true;

    /** Name of the investigating analyst — appears in the PDF header. */
    private String investigatorName;

    /** Organization name — appears in the PDF header and classification banner. */
    private String organizationName;

    // ─── Constructors ────────────────────────────────────────────────────────

    public ReportRequest() {}

    public ReportRequest(List<String> caseIds, ReportType reportType,
                         boolean includeTimeline, boolean includeMitreMapping,
                         boolean includeEvidenceHashes, String investigatorName,
                         String organizationName) {
        this.caseIds = caseIds;
        this.reportType = reportType;
        this.includeTimeline = includeTimeline;
        this.includeMitreMapping = includeMitreMapping;
        this.includeEvidenceHashes = includeEvidenceHashes;
        this.investigatorName = investigatorName;
        this.organizationName = organizationName;
    }

    // ─── Getters & Setters ───────────────────────────────────────────────────

    public List<String> getCaseIds() { return caseIds; }
    public void setCaseIds(List<String> caseIds) { this.caseIds = caseIds; }

    public ReportType getReportType() { return reportType; }
    public void setReportType(ReportType reportType) { this.reportType = reportType; }

    public boolean isIncludeTimeline() { return includeTimeline; }
    public void setIncludeTimeline(boolean includeTimeline) { this.includeTimeline = includeTimeline; }

    public boolean isIncludeMitreMapping() { return includeMitreMapping; }
    public void setIncludeMitreMapping(boolean includeMitreMapping) { this.includeMitreMapping = includeMitreMapping; }

    public boolean isIncludeEvidenceHashes() { return includeEvidenceHashes; }
    public void setIncludeEvidenceHashes(boolean includeEvidenceHashes) { this.includeEvidenceHashes = includeEvidenceHashes; }

    public String getInvestigatorName() { return investigatorName; }
    public void setInvestigatorName(String investigatorName) { this.investigatorName = investigatorName; }

    public String getOrganizationName() { return organizationName; }
    public void setOrganizationName(String organizationName) { this.organizationName = organizationName; }
}
