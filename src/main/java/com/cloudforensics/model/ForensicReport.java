package com.cloudforensics.model;

import java.time.Instant;
import java.util.List;

/**
 * Full forensic report domain object returned by POST /api/reports/generate.
 *
 * This is a pure POJO (not a JPA @Entity) — it is serialized to JSON for the
 * REST response and is also passed into the PDF renderer.
 *
 * Structure:
 *   reportId            — UUID assigned at generation time
 *   generatedAt         — UTC ISO-8601 timestamp
 *   reportType          — TECHNICAL / EXECUTIVE / COMBINED
 *   investigatorName    — from the request
 *   organizationName    — from the request
 *   cases               — all IncidentCase objects included in this report
 *   executiveSummary    — auto-generated paragraph
 *   technicalFindings   — list of alert-level finding strings (TECHNICAL+COMBINED only)
 *   attackTimeline      — chronologically sorted TimelineEvent list
 *   mitreMapping        — list of detected MITRE techniques
 *   evidenceTable       — list of EvidenceRecord with SHA-256 hashes
 */
public class ForensicReport {

    private String reportId;
    private Instant generatedAt;
    private ReportType reportType;
    private String investigatorName;
    private String organizationName;

    // Core data sections
    private List<IncidentCase> cases;
    private String executiveSummary;
    private List<String> technicalFindings;    // absent for EXECUTIVE reports
    private List<LogResponseDTO> attackTimeline;
    private List<MitreTechnique> mitreMapping;
    private List<EvidenceRecord> evidenceTable;

    // Status of the generation job
    private ReportStatus status;
    private String errorMessage;

    public ForensicReport() {}

    // ─── Getters & Setters ───────────────────────────────────────────────────

    public String getReportId() { return reportId; }
    public void setReportId(String reportId) { this.reportId = reportId; }

    public Instant getGeneratedAt() { return generatedAt; }
    public void setGeneratedAt(Instant generatedAt) { this.generatedAt = generatedAt; }

    public ReportType getReportType() { return reportType; }
    public void setReportType(ReportType reportType) { this.reportType = reportType; }

    public String getInvestigatorName() { return investigatorName; }
    public void setInvestigatorName(String investigatorName) { this.investigatorName = investigatorName; }

    public String getOrganizationName() { return organizationName; }
    public void setOrganizationName(String organizationName) { this.organizationName = organizationName; }

    public List<IncidentCase> getCases() { return cases; }
    public void setCases(List<IncidentCase> cases) { this.cases = cases; }

    public String getExecutiveSummary() { return executiveSummary; }
    public void setExecutiveSummary(String executiveSummary) { this.executiveSummary = executiveSummary; }

    public List<String> getTechnicalFindings() { return technicalFindings; }
    public void setTechnicalFindings(List<String> technicalFindings) { this.technicalFindings = technicalFindings; }

    public List<LogResponseDTO> getAttackTimeline() { return attackTimeline; }
    public void setAttackTimeline(List<LogResponseDTO> attackTimeline) { this.attackTimeline = attackTimeline; }

    public List<MitreTechnique> getMitreMapping() { return mitreMapping; }
    public void setMitreMapping(List<MitreTechnique> mitreMapping) { this.mitreMapping = mitreMapping; }

    public List<EvidenceRecord> getEvidenceTable() { return evidenceTable; }
    public void setEvidenceTable(List<EvidenceRecord> evidenceTable) { this.evidenceTable = evidenceTable; }

    public ReportStatus getStatus() { return status; }
    public void setStatus(ReportStatus status) { this.status = status; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
}
