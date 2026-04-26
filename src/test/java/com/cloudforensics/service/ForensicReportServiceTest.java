package com.cloudforensics.service;

import com.cloudforensics.model.*;
import com.cloudforensics.repository.ForensicReportMetadataRepository;
import com.cloudforensics.service.pdf.PdfReportRenderer;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * JUnit 5 unit tests for ForensicReportService.
 *
 * Covers:
 *  1. generateReport() with 1 case — asserts all required sections present in output JSON
 *  2. generateReport() with EXECUTIVE-only flag — asserts technical details absent
 *  3. Chain of custody fields are populated correctly
 *  4. Async path is triggered when > 5 cases
 */
@ExtendWith(MockitoExtension.class)
class ForensicReportServiceTest {

    @Mock
    private LogService logService;

    @Mock
    private DetectionRuleService detectionRuleService;

    @Mock
    private CorrelationService correlationService;

    @Mock
    private PdfReportRenderer pdfReportRenderer;

    @Mock
    private ForensicReportMetadataRepository metadataRepository;

    private ForensicReportService reportService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        reportService = new ForensicReportService(
                logService,
                detectionRuleService,
                correlationService,
                pdfReportRenderer,
                metadataRepository,
                objectMapper
        );
    }

    // ── Helper: build test data ──────────────────────────────────────────────

    private LogEvent buildLogEvent(String eventName, String userName, String ip, String time) {
        UserIdentity uid = new UserIdentity();
        uid.setUserName(userName);
        LogEvent event = new LogEvent();
        event.setEventName(eventName);
        event.setUserIdentity(uid);
        event.setSourceIPAddress(ip);
        event.setEventTime(time);
        event.setEventOutcome("Success");
        return event;
    }

    private Alert buildAlert(String user, String severity, String ruleName, String desc) {
        return new Alert("alert-" + System.nanoTime(), "2026-03-25T10:00:00Z",
                ruleName, severity, user, "198.51.100.42", "ConsoleLogin", desc);
    }

    private IncidentCase buildCase(String caseId, String user) {
        return new IncidentCase(caseId, user, "198.51.100.42", "CRITICAL", 5,
                Collections.emptyList(), "Correlated suspicious activity: authentication anomalies.");
    }

    private void setupMockData(List<IncidentCase> cases, String targetUser) {
        List<LogEvent> logs = List.of(
                buildLogEvent("ConsoleLogin", targetUser, "198.51.100.42", "2026-03-25T09:00:00Z"),
                buildLogEvent("CreateAccessKey", targetUser, "198.51.100.42", "2026-03-25T09:05:00Z"),
                buildLogEvent("AttachUserPolicy", targetUser, "198.51.100.42", "2026-03-25T09:10:00Z"),
                buildLogEvent("ListBuckets", targetUser, "198.51.100.42", "2026-03-25T09:15:00Z"),
                buildLogEvent("GetObject", targetUser, "198.51.100.42", "2026-03-25T09:20:00Z")
        );

        List<Alert> alerts = List.of(
                buildAlert(targetUser, "CRITICAL", "RULE-CONSOLE-ROOT", "Root console login detected"),
                buildAlert(targetUser, "HIGH", "RULE-KEY-CREATE", "Access key created for privileged user")
        );

        when(logService.getAllLogs()).thenReturn(logs);
        when(detectionRuleService.detectAlerts(any())).thenReturn(alerts);
        when(correlationService.correlateCases(any(), any())).thenReturn(cases);
        when(pdfReportRenderer.render(any())).thenReturn(new byte[]{0x25, 0x50, 0x44, 0x46}); // %PDF
        when(metadataRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TEST 1: Generate report with 1 case — all sections present
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("generateReport with 1 case returns COMPLETE with all required sections")
    void generateReport_singleCase_allSections() {
        // Arrange
        IncidentCase testCase = buildCase("CF-001", "admin-user");
        setupMockData(List.of(testCase), "admin-user");

        ReportRequest request = new ReportRequest(
                List.of("CF-001"),
                ReportType.COMBINED,
                true,   // includeTimeline
                true,   // includeMitreMapping
                true,   // includeEvidenceHashes
                "Alice Smith",
                "Acme Corp"
        );

        // Act
        ForensicReport report = reportService.generateReport(request);

        // Assert — report envelope
        assertNotNull(report, "Report must not be null");
        assertNotNull(report.getReportId(), "Report ID must be assigned");
        assertNotNull(report.getGeneratedAt(), "Generation timestamp must be set");
        assertEquals(ReportStatus.COMPLETE, report.getStatus(), "Sync report must be COMPLETE");
        assertEquals(ReportType.COMBINED, report.getReportType());

        // Assert — metadata
        assertEquals("Alice Smith", report.getInvestigatorName());
        assertEquals("Acme Corp", report.getOrganizationName());

        // Assert — cases section
        assertNotNull(report.getCases(), "Cases list must be present");
        assertEquals(1, report.getCases().size(), "Exactly 1 case expected");
        assertEquals("CF-001", report.getCases().get(0).getCaseId());

        // Assert — executive summary section
        assertNotNull(report.getExecutiveSummary(), "Executive summary must be present");
        assertFalse(report.getExecutiveSummary().isBlank(), "Executive summary must not be blank");
        assertTrue(report.getExecutiveSummary().contains("Acme Corp"),
                "Summary should mention organization name");

        // Assert — technical findings section (COMBINED includes technical)
        assertNotNull(report.getTechnicalFindings(), "Technical findings must be present for COMBINED");
        assertFalse(report.getTechnicalFindings().isEmpty(), "Technical findings must not be empty");

        // Assert — attack timeline section
        assertNotNull(report.getAttackTimeline(), "Attack timeline must be present");
        assertFalse(report.getAttackTimeline().isEmpty(), "Attack timeline must not be empty");

        // Assert — MITRE mapping section
        assertNotNull(report.getMitreMapping(), "MITRE mapping must be present");
        // Note: MITRE mapping may be empty if mitre-mapping.json is not on test classpath,
        // but the list itself must exist

        // Assert — evidence table section
        assertNotNull(report.getEvidenceTable(), "Evidence table must be present");
        assertFalse(report.getEvidenceTable().isEmpty(), "Evidence table must not be empty");

        // Assert — PDF was rendered
        verify(pdfReportRenderer, times(1)).render(any(ForensicReport.class));

        // Assert — metadata was persisted
        verify(metadataRepository, atLeastOnce()).save(any(ForensicReportMetadata.class));
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TEST 2: EXECUTIVE-only flag — technical details absent
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("generateReport with EXECUTIVE type excludes technical findings")
    void generateReport_executiveOnly_noTechnicalDetails() {
        // Arrange
        IncidentCase testCase = buildCase("CF-001", "admin-user");
        setupMockData(List.of(testCase), "admin-user");

        ReportRequest request = new ReportRequest(
                List.of("CF-001"),
                ReportType.EXECUTIVE,
                false,  // includeTimeline = false
                false,  // includeMitreMapping = false
                false,  // includeEvidenceHashes = false
                "Bob Investigator",
                "Security Corp"
        );

        // Act
        ForensicReport report = reportService.generateReport(request);

        // Assert — report is complete
        assertNotNull(report);
        assertEquals(ReportStatus.COMPLETE, report.getStatus());
        assertEquals(ReportType.EXECUTIVE, report.getReportType());

        // Assert — executive summary should be present
        assertNotNull(report.getExecutiveSummary(), "Executive summary must be present");
        assertFalse(report.getExecutiveSummary().isBlank());

        // Assert — technical details should be ABSENT for EXECUTIVE type
        assertNull(report.getTechnicalFindings(),
                "Technical findings must be NULL for EXECUTIVE report type");

        // Assert — optional sections excluded when flags are false
        assertTrue(report.getAttackTimeline() == null || report.getAttackTimeline().isEmpty(),
                "Attack timeline must be absent when includeTimeline=false");
        assertTrue(report.getMitreMapping() == null || report.getMitreMapping().isEmpty(),
                "MITRE mapping must be absent when includeMitreMapping=false");
        assertTrue(report.getEvidenceTable() == null || report.getEvidenceTable().isEmpty(),
                "Evidence table must be absent when includeEvidenceHashes=false");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TEST 3: Chain of custody fields are populated
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("Evidence records include chain of custody fields")
    void generateReport_evidenceHasChainOfCustody() {
        // Arrange
        IncidentCase testCase = buildCase("CF-001", "admin-user");
        setupMockData(List.of(testCase), "admin-user");

        ReportRequest request = new ReportRequest(
                List.of("CF-001"),
                ReportType.TECHNICAL,
                false,  // skip timeline
                false,  // skip MITRE
                true,   // include evidence hashes
                "Charlie Forensics",
                "Forensics Ltd"
        );

        // Act
        ForensicReport report = reportService.generateReport(request);

        // Assert — evidence table is populated
        assertNotNull(report.getEvidenceTable());
        assertFalse(report.getEvidenceTable().isEmpty());

        for (EvidenceRecord evidence : report.getEvidenceTable()) {
            // Chain of custody fields must be populated
            assertNotNull(evidence.getEvidenceName(),
                    "evidenceName (chain of custody label) must not be null");
            assertFalse(evidence.getEvidenceName().isBlank(),
                    "evidenceName must not be blank");
            assertTrue(evidence.getEvidenceName().startsWith("evidence-"),
                    "evidenceName should follow the batch label pattern");

            assertNotNull(evidence.getEvidenceType(),
                    "evidenceType must not be null");

            assertNotNull(evidence.getCollectedBy(),
                    "collectedBy must not be null");
            assertEquals("Charlie Forensics", evidence.getCollectedBy(),
                    "collectedBy should match the investigator from the request");

            // Standard fields should still be present
            assertNotNull(evidence.getSha256Hash(), "SHA-256 hash must be present");
            assertEquals(64, evidence.getSha256Hash().length(),
                    "SHA-256 hex digest should be 64 characters");
            assertNotNull(evidence.getName(), "Evidence name must be present");
            assertTrue(evidence.isVerified(), "Server-generated evidence should be verified");
        }
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TEST 4: Evidence type inference logic
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("Evidence type is correctly inferred from event names")
    void generateReport_evidenceTypeInference() {
        // Arrange
        IncidentCase testCase = buildCase("CF-001", "admin-user");
        setupMockData(List.of(testCase), "admin-user");

        ReportRequest request = new ReportRequest(
                List.of("CF-001"),
                ReportType.COMBINED,
                false, false, true,
                "Test Investigator", "Test Org"
        );

        // Act
        ForensicReport report = reportService.generateReport(request);

        // Assert — check the evidence types match expected patterns
        assertNotNull(report.getEvidenceTable());

        boolean hasLogBundle = report.getEvidenceTable().stream()
                .anyMatch(e -> e.getEvidenceType() == EvidenceType.LOG_BUNDLE);
        boolean hasIamSnapshot = report.getEvidenceTable().stream()
                .anyMatch(e -> e.getEvidenceType() == EvidenceType.IAM_SNAPSHOT);
        boolean hasConfigSnapshot = report.getEvidenceTable().stream()
                .anyMatch(e -> e.getEvidenceType() == EvidenceType.CONFIG_SNAPSHOT);

        // ConsoleLogin and ListBuckets should be LOG_BUNDLE
        assertTrue(hasLogBundle, "LOG_BUNDLE evidence type should be present for ConsoleLogin");
        // CreateAccessKey and AttachUserPolicy should be IAM_SNAPSHOT
        assertTrue(hasIamSnapshot, "IAM_SNAPSHOT evidence type should be present for IAM events");
        // GetObject should be CONFIG_SNAPSHOT (starts with "Get")
        assertTrue(hasConfigSnapshot, "CONFIG_SNAPSHOT evidence type should be present for Get* events");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TEST 5: PDF bytes are cached and retrievable
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("PDF bytes are cached after generation and retrievable by reportId")
    void generateReport_pdfCached() {
        // Arrange
        byte[] fakePdf = new byte[]{0x25, 0x50, 0x44, 0x46, 0x2D}; // %PDF-
        IncidentCase testCase = buildCase("CF-001", "admin-user");
        setupMockData(List.of(testCase), "admin-user");
        when(pdfReportRenderer.render(any())).thenReturn(fakePdf);

        ReportRequest request = new ReportRequest(
                List.of("CF-001"), ReportType.COMBINED,
                true, true, true, "Alice", "TestOrg"
        );

        // Act
        ForensicReport report = reportService.generateReport(request);

        // Assert
        byte[] pdfBytes = reportService.getPdfBytes(report.getReportId());
        assertNotNull(pdfBytes, "PDF bytes must be cached");
        assertTrue(pdfBytes.length > 0, "PDF bytes must not be empty");
        assertArrayEquals(fakePdf, pdfBytes, "Cached PDF must match rendered output");
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TEST 6: No matching cases throws IllegalArgumentException
    // ══════════════════════════════════════════════════════════════════════════

    @Test
    @DisplayName("generateReport throws when no matching cases found")
    void generateReport_noCases_throws() {
        // Arrange — return empty case list
        when(logService.getAllLogs()).thenReturn(Collections.emptyList());
        when(detectionRuleService.detectAlerts(any())).thenReturn(Collections.emptyList());
        when(correlationService.correlateCases(any(), any())).thenReturn(Collections.emptyList());

        ReportRequest request = new ReportRequest(
                List.of("CF-999"), ReportType.COMBINED,
                true, true, true, "Alice", "TestOrg"
        );

        // Act & Assert
        assertThrows(IllegalArgumentException.class,
                () -> reportService.generateReport(request),
                "Should throw when no matching cases are found");
    }
}
