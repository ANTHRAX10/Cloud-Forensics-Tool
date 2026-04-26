package com.cloudforensics.controller;

import com.cloudforensics.model.ForensicReport;
import com.cloudforensics.model.ForensicReportMetadata;
import com.cloudforensics.model.ReportRequest;
import com.cloudforensics.model.ReportStatus;
import com.cloudforensics.service.ForensicReportService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

/**
 * ReportController — exposes the forensic report generation REST API.
 *
 * Endpoints:
 *   POST  /api/reports/generate          → triggers JSON + PDF report generation
 *   GET   /api/reports/{reportId}/pdf    → streams the PDF binary for download
 *   GET   /api/reports/{reportId}        → returns the full JSON ForensicReport
 *   GET   /api/reports                   → lists all persisted report metadata
 *
 * Security:
 *   - PDF streaming sets Content-Disposition: attachment to force browser download.
 *   - Generation is server-side only; no client-side rendering.
 *   - Raw credentials are never included in any response.
 */
@RestController
@RequestMapping("/api/reports")
@CrossOrigin(origins = "*")
public class ReportController {

    private static final Logger log = LoggerFactory.getLogger(ReportController.class);

    private final ForensicReportService reportService;

    public ReportController(ForensicReportService reportService) {
        this.reportService = reportService;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // POST /api/reports/generate
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Initiates forensic report generation.
     *
     * If the request covers > 5 cases, the service dispatches generation
     * asynchronously and returns HTTP 202 Accepted with a PENDING report stub.
     * Otherwise, returns HTTP 200 OK with the completed ForensicReport.
     *
     * Request body example:
     * {
     *   "caseIds": ["CF-001"],
     *   "reportType": "COMBINED",
     *   "includeTimeline": true,
     *   "includeMitreMapping": true,
     *   "includeEvidenceHashes": true,
     *   "investigatorName": "Alice Smith",
     *   "organizationName": "Acme Corp"
     * }
     */
    @PostMapping("/generate")
    public ResponseEntity<?> generateReport(@RequestBody ReportRequest request) {
        log.info("Report generation requested: type={}, caseIds={}",
                request.getReportType(), request.getCaseIds());
        try {
            ForensicReport report = reportService.generateReport(request);

            // HTTP 202 for async (PENDING), HTTP 200 for sync (COMPLETE)
            HttpStatus status = report.getStatus() == ReportStatus.PENDING
                    ? HttpStatus.ACCEPTED
                    : HttpStatus.OK;

            return ResponseEntity.status(status).body(report);

        } catch (IllegalArgumentException e) {
            log.warn("Invalid report request: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorResponse(e.getMessage()));
        } catch (Exception e) {
            log.error("Report generation error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ErrorResponse("Report generation failed: " + e.getMessage()));
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GET /api/reports/{reportId}/pdf
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Streams the generated PDF binary for the specified report.
     *
     * Security: Content-Disposition is set to "attachment" to force a file
     * download rather than inline browser rendering, preventing XSS risks.
     *
     * Returns HTTP 404 if the reportId is unknown.
     * Returns HTTP 202 Accepted if generation is still in progress (async).
     */
    @GetMapping(value = "/{reportId}/pdf", produces = MediaType.APPLICATION_PDF_VALUE)
    public ResponseEntity<byte[]> downloadPdf(@PathVariable String reportId) {
        log.info("PDF download requested for report {}", reportId);

        // Check if the report exists at all
        Optional<ForensicReport> reportOpt = reportService.getReport(reportId);
        if (reportOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(("Report not found: " + reportId).getBytes());
        }

        ForensicReport report = reportOpt.get();

        // If still generating, return 202 Accepted with status hint
        if (report.getStatus() == ReportStatus.PENDING
                || report.getStatus() == ReportStatus.GENERATING) {
            return ResponseEntity.status(HttpStatus.ACCEPTED)
                    .header("X-Report-Status", report.getStatus().name())
                    .body(("Report generation in progress. Try again shortly.").getBytes());
        }

        // Check for failed report
        if (report.getStatus() == ReportStatus.FAILED) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(("Report generation failed: " + report.getErrorMessage()).getBytes());
        }

        byte[] pdfBytes = reportService.getPdfBytes(reportId);
        if (pdfBytes == null || pdfBytes.length == 0) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("PDF not yet available — report may still be generating.".getBytes());
        }

        // Build response headers:
        // Content-Disposition: attachment — forces file download (security requirement)
        // Content-Type: application/pdf
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_PDF);
        headers.add(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"forensic-report-" + reportId + ".pdf\"");
        headers.setContentLength(pdfBytes.length);

        // Cache-Control: no-store prevents PDFs from being cached in browser history
        headers.add(HttpHeaders.CACHE_CONTROL, "no-store, no-cache, must-revalidate");

        log.info("Streaming {} bytes PDF for report {}", pdfBytes.length, reportId);
        return new ResponseEntity<>(pdfBytes, headers, HttpStatus.OK);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GET /api/reports/{reportId}
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Returns the full JSON ForensicReport domain object.
     * Useful for inspecting the report data without downloading the PDF.
     */
    @GetMapping("/{reportId}")
    public ResponseEntity<?> getReport(@PathVariable String reportId) {
        Optional<ForensicReport> report = reportService.getReport(reportId);
        return report
                .<ResponseEntity<?>>map(r -> ResponseEntity.ok(r))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ErrorResponse("Report not found: " + reportId)));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // GET /api/reports
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Returns the list of ForensicReportMetadata entities, newest first.
     * Each entry contains reportId, status, type, investigator, and case count —
     * without the full report content (lightweight for the list view).
     */
    @GetMapping
    public ResponseEntity<List<ForensicReportMetadata>> listReports() {
        List<ForensicReportMetadata> reports = reportService.listReports();
        return ResponseEntity.ok(reports);
    }

    // ── Error response DTO ─────────────────────────────────────────────────────

    /** Simple error wrapper for consistent error response format. */
    public record ErrorResponse(String error) {}
}
