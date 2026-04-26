package com.cloudforensics.controller;

import com.cloudforensics.model.*;
import com.cloudforensics.service.ForensicReportService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.bean.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

import static org.hamcrest.Matchers.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * JUnit 5 integration tests for ReportController.
 *
 * Tests:
 *  1. POST /api/reports/generate returns valid ForensicReport JSON
 *  2. GET /api/reports/{reportId}/pdf returns Content-Type application/pdf
 *     and Content-Disposition: attachment
 *  3. GET /api/reports returns report metadata list
 *  4. GET /api/reports/{reportId}/pdf returns 404 for unknown report
 */
@WebMvcTest(ReportController.class)
class ReportControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ForensicReportService reportService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    // ── Helper: build a complete ForensicReport ──────────────────────────────

    private ForensicReport buildCompleteReport(String reportId) {
        ForensicReport report = new ForensicReport();
        report.setReportId(reportId);
        report.setGeneratedAt(Instant.now());
        report.setReportType(ReportType.COMBINED);
        report.setInvestigatorName("Alice Smith");
        report.setOrganizationName("Acme Corp");
        report.setStatus(ReportStatus.COMPLETE);
        report.setExecutiveSummary("Test executive summary for Acme Corp.");
        report.setCases(List.of(
                new IncidentCase("CF-001", "admin-user", "198.51.100.42",
                        "CRITICAL", 5, Collections.emptyList(),
                        "Correlated activity")));
        report.setTechnicalFindings(List.of("[CRITICAL] Root login detected"));
        report.setAttackTimeline(List.of(
                new LogResponseDTO("2026-03-25T09:00:00Z", "CRITICAL",
                        "ConsoleLogin", "admin-user", "arn:aws:iam",
                        "198.51.100.42", "Success", "Root login")));
        report.setMitreMapping(List.of(
                new MitreTechnique("T1078", "Valid Accounts",
                        "ConsoleLogin", "Initial Access")));
        report.setEvidenceTable(List.of(
                new EvidenceRecord("ConsoleLogin by admin-user",
                        "abc123def456".repeat(4) + "abcd1234abcd1234",
                        true, "2026-03-25T09:00:00Z", "198.51.100.42",
                        "evidence-2026-03-25-batch-001",
                        EvidenceType.LOG_BUNDLE, "Alice Smith")));
        return report;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TEST 1: POST /api/reports/generate — returns valid JSON ForensicReport
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("POST /api/reports/generate returns completed ForensicReport JSON")
    void generateReport_returnsJson() throws Exception {
        // Arrange
        ForensicReport report = buildCompleteReport("test-report-001");
        when(reportService.generateReport(any(ReportRequest.class))).thenReturn(report);

        String requestBody = objectMapper.writeValueAsString(new ReportRequest(
                List.of("CF-001"), ReportType.COMBINED,
                true, true, true, "Alice Smith", "Acme Corp"
        ));

        // Act & Assert
        mockMvc.perform(post("/api/reports/generate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.reportId").value("test-report-001"))
                .andExpect(jsonPath("$.status").value("COMPLETE"))
                .andExpect(jsonPath("$.reportType").value("COMBINED"))
                .andExpect(jsonPath("$.investigatorName").value("Alice Smith"))
                .andExpect(jsonPath("$.organizationName").value("Acme Corp"))
                .andExpect(jsonPath("$.executiveSummary").isNotEmpty())
                .andExpect(jsonPath("$.cases").isArray())
                .andExpect(jsonPath("$.cases", hasSize(1)))
                .andExpect(jsonPath("$.technicalFindings").isArray())
                .andExpect(jsonPath("$.attackTimeline").isArray())
                .andExpect(jsonPath("$.mitreMapping").isArray())
                .andExpect(jsonPath("$.evidenceTable").isArray())
                .andExpect(jsonPath("$.evidenceTable[0].evidenceName").value("evidence-2026-03-25-batch-001"))
                .andExpect(jsonPath("$.evidenceTable[0].evidenceType").value("LOG_BUNDLE"))
                .andExpect(jsonPath("$.evidenceTable[0].collectedBy").value("Alice Smith"));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TEST 2: GET /api/reports/{reportId}/pdf — Content-Type & Disposition
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("GET /api/reports/{id}/pdf returns application/pdf with Content-Disposition: attachment")
    void downloadPdf_returnsCorrectHeaders() throws Exception {
        // Arrange
        String reportId = "test-report-pdf";
        ForensicReport report = buildCompleteReport(reportId);
        byte[] fakePdf = new byte[]{0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34}; // %PDF-1.4

        when(reportService.getReport(reportId)).thenReturn(Optional.of(report));
        when(reportService.getPdfBytes(reportId)).thenReturn(fakePdf);

        // Act & Assert
        mockMvc.perform(get("/api/reports/{reportId}/pdf", reportId)
                        .accept(MediaType.APPLICATION_PDF))
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_PDF))
                .andExpect(header().string("Content-Disposition",
                        containsString("attachment")))
                .andExpect(header().string("Content-Disposition",
                        containsString("forensic-report-" + reportId + ".pdf")));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TEST 3: GET /api/reports — returns metadata list
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("GET /api/reports returns list of report metadata")
    void listReports_returnsMetadata() throws Exception {
        // Arrange
        ForensicReportMetadata meta = new ForensicReportMetadata(
                "meta-001", Instant.now(), ReportType.COMBINED,
                ReportStatus.COMPLETE, "Alice", "Acme", 2);

        when(reportService.listReports()).thenReturn(List.of(meta));

        // Act & Assert
        mockMvc.perform(get("/api/reports")
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$", hasSize(1)))
                .andExpect(jsonPath("$[0].reportId").value("meta-001"))
                .andExpect(jsonPath("$[0].status").value("COMPLETE"));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TEST 4: GET /api/reports/{reportId}/pdf — 404 for unknown report
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("GET /api/reports/{id}/pdf returns 404 for unknown reportId")
    void downloadPdf_unknownReport_returns404() throws Exception {
        // Arrange
        when(reportService.getReport("nonexistent")).thenReturn(Optional.empty());

        // Act & Assert
        mockMvc.perform(get("/api/reports/{reportId}/pdf", "nonexistent")
                        .accept(MediaType.APPLICATION_PDF))
                .andExpect(status().isNotFound());
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TEST 5: POST /api/reports/generate with async (PENDING status) returns 202
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("POST /api/reports/generate with PENDING status returns HTTP 202")
    void generateReport_async_returns202() throws Exception {
        // Arrange — service returns a PENDING stub
        ForensicReport pendingReport = new ForensicReport();
        pendingReport.setReportId("async-report-001");
        pendingReport.setStatus(ReportStatus.PENDING);
        pendingReport.setReportType(ReportType.COMBINED);
        pendingReport.setGeneratedAt(Instant.now());

        when(reportService.generateReport(any(ReportRequest.class))).thenReturn(pendingReport);

        String requestBody = objectMapper.writeValueAsString(new ReportRequest(
                List.of("CF-001", "CF-002", "CF-003", "CF-004", "CF-005", "CF-006"),
                ReportType.COMBINED, true, true, true, "Alice", "Acme"
        ));

        // Act & Assert
        mockMvc.perform(post("/api/reports/generate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isAccepted())
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andExpect(jsonPath("$.reportId").value("async-report-001"));
    }
}
