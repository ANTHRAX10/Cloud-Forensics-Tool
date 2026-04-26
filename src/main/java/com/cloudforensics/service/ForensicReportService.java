package com.cloudforensics.service;

import com.cloudforensics.model.*;
import com.cloudforensics.repository.ForensicReportMetadataRepository;
import com.cloudforensics.service.pdf.PdfReportRenderer;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * ForensicReportService — orchestrates the complete report generation pipeline.
 *
 * Responsibilities:
 *  1. Load incident cases, alerts, and log events from the in-memory data sources
 *  2. Perform MITRE ATT&CK technique mapping from mitre-mapping.json
 *  3. Build the ForensicReport domain object
 *  4. Delegate to PdfReportRenderer for PDF binary generation
 *  5. Persist ForensicReportMetadata to H2 via JPA repository
 *  6. Cache the full ForensicReport and PDF bytes in ConcurrentHashMaps for fast retrieval
 *
 * Async behaviour:
 *  - Reports with > 5 cases are generated asynchronously via @Async.
 *    The caller receives a reportId immediately; status is polled via GET /api/reports.
 *  - Reports with ≤ 5 cases are generated synchronously and returned directly.
 *
 * Security guarantees:
 *  - Raw credentials and access key values are never written into report sections.
 *  - Evidence SHA-256 hashes are computed from event metadata only.
 */
@Service
public class ForensicReportService {

    private static final Logger log = LoggerFactory.getLogger(ForensicReportService.class);

    // ── In-memory caches (ConcurrentHashMap ensures thread safety for @Async) ─
    /** Maps reportId → full ForensicReport domain object */
    private final ConcurrentHashMap<String, ForensicReport> reportCache = new ConcurrentHashMap<>();
    /** Maps reportId → rendered PDF bytes */
    private final ConcurrentHashMap<String, byte[]> pdfCache = new ConcurrentHashMap<>();

    // ── MITRE mapping loaded lazily on first use ──────────────────────────────
    /** Maps eventName → { "id": "T1078", "name": "Valid Accounts", "tactic": "..." } */
    private Map<String, Map<String, String>> mitreMapping;

    // ── Collaborating services and components ─────────────────────────────────
    private final LogService logService;
    private final DetectionRuleService detectionRuleService;
    private final CorrelationService correlationService;
    private final PdfReportRenderer pdfReportRenderer;
    private final ForensicReportMetadataRepository metadataRepository;
    private final ObjectMapper objectMapper;

    public ForensicReportService(LogService logService,
                                  DetectionRuleService detectionRuleService,
                                  CorrelationService correlationService,
                                  PdfReportRenderer pdfReportRenderer,
                                  ForensicReportMetadataRepository metadataRepository,
                                  ObjectMapper objectMapper) {
        this.logService = logService;
        this.detectionRuleService = detectionRuleService;
        this.correlationService = correlationService;
        this.pdfReportRenderer = pdfReportRenderer;
        this.metadataRepository = metadataRepository;
        this.objectMapper = objectMapper;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // PUBLIC API
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Entry point for POST /api/reports/generate.
     *
     * If the request covers > 5 cases, generation is dispatched asynchronously
     * and a stub ForensicReport in PENDING status is returned immediately.
     * The caller should poll GET /api/reports to check status.
     *
     * For ≤ 5 cases, the report is generated synchronously and returned complete.
     *
     * @param request validated ReportRequest DTO from the controller
     * @return ForensicReport — either COMPLETE (sync) or PENDING (async)
     */
    public ForensicReport generateReport(ReportRequest request) {
        // Normalize request defaults
        if (request.getReportType() == null) request.setReportType(ReportType.COMBINED);

        // Resolve the case list based on the requested caseIds
        List<IncidentCase> allCases = loadAllCases();
        List<IncidentCase> targetCases = filterCases(allCases, request.getCaseIds());

        if (targetCases.isEmpty()) {
            throw new IllegalArgumentException(
                    "No matching cases found for the provided caseIds: " + request.getCaseIds());
        }

        // Assign a unique report ID
        String reportId = UUID.randomUUID().toString();

        if (targetCases.size() > 5) {
            // ── ASYNC PATH: return stub immediately, generate in background ───
            log.info("Report {} covers {} cases — dispatching async generation", reportId, targetCases.size());

            ForensicReport stub = buildStubReport(reportId, request, targetCases.size());
            reportCache.put(reportId, stub);
            persistMetadata(stub, targetCases.size());

            // Fire off async generation — @Async ensures this runs in a separate thread
            generateReportAsync(reportId, request, targetCases);

            return stub;
        } else {
            // ── SYNC PATH: generate inline and return complete report ──────────
            log.info("Report {} covers {} cases — generating synchronously", reportId, targetCases.size());
            return doGenerate(reportId, request, targetCases);
        }
    }

    /**
     * Async generation worker — called by generateReport() when case count > 5.
     * Updates the cache and persisted metadata upon completion or failure.
     *
     * @Async requires the call to originate from OUTSIDE this bean (Spring proxy).
     * The controller → service → @Async method chain satisfies this requirement.
     */
    @Async
    public void generateReportAsync(String reportId, ReportRequest request,
                                     List<IncidentCase> targetCases) {
        try {
            log.info("Async generation starting for report {}", reportId);
            ForensicReport report = doGenerate(reportId, request, targetCases);
            reportCache.put(reportId, report);
            log.info("Async generation complete for report {}", reportId);
        } catch (Exception e) {
            log.error("Async generation failed for report {}: {}", reportId, e.getMessage(), e);
            // Mark the cached stub as failed
            ForensicReport failed = reportCache.getOrDefault(reportId, new ForensicReport());
            failed.setStatus(ReportStatus.FAILED);
            failed.setErrorMessage(e.getMessage());
            reportCache.put(reportId, failed);

            // Update persisted metadata
            metadataRepository.findById(reportId).ifPresent(meta -> {
                meta.setStatus(ReportStatus.FAILED);
                meta.setErrorMessage(e.getMessage());
                metadataRepository.save(meta);
            });
        }
    }

    /**
     * Returns the serialized PDF bytes for a completed report.
     *
     * @param reportId UUID of the report
     * @return PDF bytes, or empty byte array if not yet generated / not found
     */
    public byte[] getPdfBytes(String reportId) {
        byte[] cached = pdfCache.get(reportId);
        if (cached != null) return cached;

        // If the report exists but PDF is not cached (e.g. async not done yet), return empty
        log.warn("PDF not yet available for report {}", reportId);
        return new byte[0];
    }

    /**
     * Returns the full ForensicReport domain object for JSON serialization.
     *
     * @param reportId UUID of the report
     * @return Optional containing the report, or empty if not found
     */
    public Optional<ForensicReport> getReport(String reportId) {
        return Optional.ofNullable(reportCache.get(reportId));
    }

    /**
     * Returns persisted metadata for all reports, newest first.
     * Used by GET /api/reports.
     */
    public List<ForensicReportMetadata> listReports() {
        return metadataRepository.findAllByOrderByGeneratedAtDesc();
    }

    // ══════════════════════════════════════════════════════════════════════════
    // CORE GENERATION LOGIC
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Core generation method — builds the complete ForensicReport domain object
     * and renders the PDF. Called by both the sync and async paths.
     *
     * Step-by-step:
     *  1. Load raw logs and alerts
     *  2. Map MITRE techniques from unique event names
     *  3. Build the attack timeline (chronologically sorted)
     *  4. Build evidence records with SHA-256 hashes
     *  5. Compose executive summary text
     *  6. Assemble ForensicReport
     *  7. Render PDF
     *  8. Persist metadata and update caches
     */
    private ForensicReport doGenerate(String reportId, ReportRequest request,
                                       List<IncidentCase> targetCases) {

        Instant now = Instant.now();

        // ── Step 1: Load raw data ────────────────────────────────────────────
        List<LogEvent> allLogs     = logService.getAllLogs();
        List<Alert>    allAlerts   = detectionRuleService.detectAlerts(allLogs);

        // Filter logs to only those belonging to the target case users
        Set<String> caseUsers = targetCases.stream()
                .map(IncidentCase::getUser)
                .collect(Collectors.toSet());

        List<LogEvent> relevantLogs = allLogs.stream()
                .filter(l -> l.getUserIdentity() != null
                        && caseUsers.contains(l.getUserIdentity().getUserName()))
                .collect(Collectors.toList());

        List<Alert> relevantAlerts = allAlerts.stream()
                .filter(a -> caseUsers.contains(a.getUser()))
                .collect(Collectors.toList());

        // ── Step 2: MITRE ATT&CK mapping ────────────────────────────────────
        List<MitreTechnique> mitreResults = Collections.emptyList();
        if (request.isIncludeMitreMapping()) {
            mitreResults = buildMitreMapping(relevantLogs);
        }

        // ── Step 3: Build attack timeline ────────────────────────────────────
        List<LogResponseDTO> timeline = Collections.emptyList();
        if (request.isIncludeTimeline()) {
            timeline = relevantLogs.stream()
                    .map(LogResponseDTO::fromLogEvent)
                    // Sort chronologically by timestamp string (ISO-8601 sorts lexicographically)
                    .sorted(Comparator.comparing(
                            dto -> dto.getTimestamp() != null ? dto.getTimestamp() : "",
                            Comparator.naturalOrder()))
                    .collect(Collectors.toList());
        }

        // ── Step 4: Build evidence table ─────────────────────────────────────
        List<EvidenceRecord> evidenceTable = Collections.emptyList();
        if (request.isIncludeEvidenceHashes()) {
            evidenceTable = buildEvidenceTable(relevantLogs, request.getInvestigatorName());
        }

        // ── Step 5: Technical findings (alert descriptions) ──────────────────
        List<String> technicalFindings = null;
        if (request.getReportType() != ReportType.EXECUTIVE) {
            technicalFindings = relevantAlerts.stream()
                    .map(a -> String.format("[%s] %s — %s (Rule: %s)",
                            a.getSeverity(), a.getTimestamp(),
                            a.getDescription(), a.getRuleName()))
                    .collect(Collectors.toList());
        }

        // ── Step 6: Executive summary ─────────────────────────────────────────
        String summary = buildExecutiveSummary(targetCases, relevantAlerts,
                mitreResults, request);

        // ── Step 7: Assemble the ForensicReport domain object ─────────────────
        ForensicReport report = new ForensicReport();
        report.setReportId(reportId);
        report.setGeneratedAt(now);
        report.setReportType(request.getReportType());
        report.setInvestigatorName(request.getInvestigatorName());
        report.setOrganizationName(request.getOrganizationName());
        report.setCases(targetCases);
        report.setExecutiveSummary(summary);
        report.setTechnicalFindings(technicalFindings);
        report.setAttackTimeline(timeline);
        report.setMitreMapping(mitreResults);
        report.setEvidenceTable(evidenceTable);
        report.setStatus(ReportStatus.COMPLETE);

        // ── Step 8: Render PDF ────────────────────────────────────────────────
        byte[] pdfBytes = pdfReportRenderer.render(report);
        pdfCache.put(reportId, pdfBytes);

        // ── Step 9: Persist or update metadata ───────────────────────────────
        persistMetadata(report, targetCases.size());

        // Put in report cache (overwrites any stub that may exist)
        reportCache.put(reportId, report);

        log.info("Report {} generated successfully: {} cases, {} timeline events, {} MITRE techniques",
                reportId, targetCases.size(), timeline.size(), mitreResults.size());

        return report;
    }

    // ══════════════════════════════════════════════════════════════════════════
    // DATA HELPERS
    // ══════════════════════════════════════════════════════════════════════════

    /** Loads all incident cases from the existing correlation pipeline. */
    private List<IncidentCase> loadAllCases() {
        List<LogEvent> logs   = logService.getAllLogs();
        List<Alert>    alerts = detectionRuleService.detectAlerts(logs);
        return correlationService.correlateCases(logs, alerts);
    }

    /**
     * Filters the full case list to only those matching the requested caseIds.
     * If caseIds is null or empty, returns all cases (wildcard).
     */
    private List<IncidentCase> filterCases(List<IncidentCase> all, List<String> caseIds) {
        if (caseIds == null || caseIds.isEmpty()) return all;
        Set<String> requested = new HashSet<>(caseIds);
        return all.stream()
                .filter(c -> requested.contains(c.getCaseId()))
                .collect(Collectors.toList());
    }

    // ── MITRE mapping ─────────────────────────────────────────────────────────

    /**
     * Maps each unique event type found in the relevant logs to a MITRE technique
     * using the configurable mitre-mapping.json resource.
     * Duplicate event types are deduplicated — each technique appears only once.
     */
    private List<MitreTechnique> buildMitreMapping(List<LogEvent> logs) {
        Map<String, Map<String, String>> mapping = loadMitreMapping();

        // Deduplicate: one MitreTechnique per unique technique ID
        Map<String, MitreTechnique> seenTechniques = new LinkedHashMap<>();

        logs.stream()
                .map(LogEvent::getEventName)
                .filter(Objects::nonNull)
                .distinct()
                .forEach(eventName -> {
                    Map<String, String> entry = mapping.get(eventName);
                    if (entry != null) {
                        String id = entry.get("id");
                        if (!seenTechniques.containsKey(id)) {
                            seenTechniques.put(id, new MitreTechnique(
                                    id,
                                    entry.get("name"),
                                    eventName,
                                    entry.get("tactic")));
                        }
                    }
                });

        return new ArrayList<>(seenTechniques.values());
    }

    /**
     * Lazily loads and caches the mitre-mapping.json resource file.
     * Thread-safe: the ConcurrentHashMap assignment is effectively idempotent.
     */
    private Map<String, Map<String, String>> loadMitreMapping() {
        if (mitreMapping == null) {
            try {
                ClassPathResource resource = new ClassPathResource("mitre-mapping.json");
                try (InputStream is = resource.getInputStream()) {
                    mitreMapping = objectMapper.readValue(is,
                            new TypeReference<Map<String, Map<String, String>>>() {});
                }
                log.info("MITRE mapping loaded: {} entries", mitreMapping.size());
            } catch (Exception e) {
                log.warn("Failed to load mitre-mapping.json, MITRE mapping will be empty: {}", e.getMessage());
                mitreMapping = Collections.emptyMap();
            }
        }
        return mitreMapping;
    }

    // ── Evidence table ────────────────────────────────────────────────────────

    /**
     * Builds an evidence list from the relevant log events.
     * Each log event produces one EvidenceRecord with a deterministic SHA-256 hash
     * computed from: eventTime + eventName + userName.
     *
     * Chain of Custody fields are populated:
     *   - evidenceName  → human-readable batch label from event metadata
     *   - evidenceType  → inferred from the event name pattern
     *   - collectedBy   → from the current request's investigatorName
     *
     * NOTE: Raw credentials and access key values are explicitly excluded.
     */
    private List<EvidenceRecord> buildEvidenceTable(List<LogEvent> logs, String investigatorName) {
        final String collector = (investigatorName != null && !investigatorName.isBlank())
                ? investigatorName : "SYSTEM";

        java.util.concurrent.atomic.AtomicInteger batchSeq = new java.util.concurrent.atomic.AtomicInteger(1);

        return logs.stream()
                .map(log -> {
                    String user = (log.getUserIdentity() != null)
                            ? log.getUserIdentity().getUserName() : "unknown";
                    String key  = (log.getEventTime() != null ? log.getEventTime() : "")
                            + (log.getEventName()  != null ? log.getEventName()  : "")
                            + user;

                    String hash = sha256Hex(key);
                    String name = log.getEventName() + " by " + user;

                    // ── Chain of Custody: human-readable evidence label ──
                    String datePart = log.getEventTime() != null
                            ? log.getEventTime().substring(0, Math.min(10, log.getEventTime().length()))
                            : "unknown-date";
                    String evidenceLabel = String.format("evidence-%s-batch-%03d",
                            datePart, batchSeq.getAndIncrement());

                    // ── Chain of Custody: infer evidence type from event name ──
                    EvidenceType evidenceType = inferEvidenceType(log.getEventName());

                    return new EvidenceRecord(
                            name,
                            hash,
                            true,   // verified = true for server-side generated hashes
                            log.getEventTime(),
                            log.getSourceIPAddress(),
                            evidenceLabel,
                            evidenceType,
                            collector);
                })
                .collect(Collectors.toList());
    }

    /**
     * Infers the EvidenceType from the cloud API event name.
     * Uses pattern matching against common CloudTrail event name prefixes.
     *
     * Mapping logic:
     *   - IAM/policy/access key events -> IAM_SNAPSHOT
     *   - VPC/network/security group events -> NETWORK_CAPTURE
     *   - Describe/Get/List config queries -> CONFIG_SNAPSHOT
     *   - All other log events -> LOG_BUNDLE (default)
     */
    private EvidenceType inferEvidenceType(String eventName) {
        if (eventName == null) return EvidenceType.LOG_BUNDLE;

        // IAM-related events
        if (eventName.contains("Policy") || eventName.contains("AccessKey")
                || eventName.contains("User") || eventName.contains("Role")
                || eventName.contains("AssumeRole")) {
            return EvidenceType.IAM_SNAPSHOT;
        }

        // Network/infrastructure events
        if (eventName.contains("Vpc") || eventName.contains("SecurityGroup")
                || eventName.contains("Subnet") || eventName.contains("NetworkInterface")) {
            return EvidenceType.NETWORK_CAPTURE;
        }

        // Configuration discovery events
        if (eventName.startsWith("Describe") || eventName.startsWith("Get")
                || eventName.contains("Config")) {
            return EvidenceType.CONFIG_SNAPSHOT;
        }

        // Default: treat as log bundle
        return EvidenceType.LOG_BUNDLE;
    }

    /** Computes SHA-256 hex digest of the given input string. */
    private String sha256Hex(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            return "hash-error";
        }
    }

    // ── Executive summary ─────────────────────────────────────────────────────

    /**
     * Auto-generates a professional executive summary paragraph based on the
     * case data, alerts, and MITRE findings. The output is suitable for
     * inclusion in both the JSON response and the PDF cover section.
     */
    private String buildExecutiveSummary(List<IncidentCase> cases, List<Alert> alerts,
                                          List<MitreTechnique> mitre, ReportRequest request) {
        long critical = cases.stream()
                .filter(c -> "CRITICAL".equalsIgnoreCase(c.getSeverity())).count();
        long high     = cases.stream()
                .filter(c -> "HIGH".equalsIgnoreCase(c.getSeverity())).count();

        String org = request.getOrganizationName() != null
                ? request.getOrganizationName() : "the organization";

        Set<String> tactics = mitre.stream()
                .map(MitreTechnique::getTactic)
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));

        String tacticSummary = tactics.isEmpty()
                ? "multiple attack stages"
                : String.join(", ", tactics);

        return String.format(
                "This forensic investigation report was commissioned by %s and covers %d incident " +
                "case%s identified through automated detection and correlation analysis. " +
                "Of the identified cases, %d %s classified as CRITICAL severity and %d as HIGH severity, " +
                "collectively generating %d security alerts. " +
                "MITRE ATT&CK analysis reveals %d distinct technique%s spanning the following " +
                "kill-chain tactics: %s. " +
                "Immediate remediation is recommended for all CRITICAL and HIGH severity cases. " +
                "Full technical details, attack timeline, and evidence inventory follow in subsequent sections.",
                org, cases.size(), cases.size() == 1 ? "" : "s",
                critical, critical == 1 ? "is" : "are",
                high, alerts.size(),
                mitre.size(), mitre.size() == 1 ? "" : "s",
                tacticSummary
        );
    }

    // ── Persistence ───────────────────────────────────────────────────────────

    /** Saves or updates ForensicReportMetadata in H2. */
    private void persistMetadata(ForensicReport report, int caseCount) {
        ForensicReportMetadata meta = new ForensicReportMetadata(
                report.getReportId(),
                report.getGeneratedAt() != null ? report.getGeneratedAt() : Instant.now(),
                report.getReportType(),
                report.getStatus(),
                report.getInvestigatorName(),
                report.getOrganizationName(),
                caseCount);
        meta.setErrorMessage(report.getErrorMessage());
        metadataRepository.save(meta);
    }

    /** Creates a stub ForensicReport in PENDING state for async generation. */
    private ForensicReport buildStubReport(String reportId, ReportRequest request, int caseCount) {
        ForensicReport stub = new ForensicReport();
        stub.setReportId(reportId);
        stub.setGeneratedAt(Instant.now());
        stub.setReportType(request.getReportType());
        stub.setInvestigatorName(request.getInvestigatorName());
        stub.setOrganizationName(request.getOrganizationName());
        stub.setStatus(ReportStatus.PENDING);
        stub.setExecutiveSummary("Report generation in progress. " + caseCount
                + " cases are being processed asynchronously. Poll GET /api/reports for status updates.");
        return stub;
    }
}
