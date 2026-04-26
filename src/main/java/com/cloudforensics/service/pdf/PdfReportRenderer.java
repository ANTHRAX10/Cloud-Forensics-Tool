package com.cloudforensics.service.pdf;

import com.cloudforensics.model.ForensicReport;
import com.cloudforensics.model.ReportType;
import com.cloudforensics.service.pdf.sections.EvidenceTableSection;
import com.cloudforensics.service.pdf.sections.ExecutiveSummarySection;
import com.cloudforensics.service.pdf.sections.MitreMappingSection;
import com.cloudforensics.service.pdf.sections.ReportSection;
import com.cloudforensics.service.pdf.sections.TimelineSection;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.events.Event;
import com.itextpdf.kernel.events.IEventHandler;
import com.itextpdf.kernel.events.PdfDocumentEvent;
import com.itextpdf.kernel.geom.PageSize;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfPage;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.layout.Canvas;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.AreaBreak;
import com.itextpdf.layout.properties.AreaBreakType;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

/**
 * PdfReportRenderer — assembles the full multi-section PDF for a ForensicReport.
 *
 * Architecture:
 *   • Uses iText 8's PdfDocument + high-level Document API
 *   • Page events handle running headers and footers on every page
 *   • Sections are wired via Strategy Pattern: each ReportSection is pluggable
 *   • The section execution order is controlled here (table of contents order)
 *
 * Section order:
 *   COVER PAGE → TABLE OF CONTENTS → EXECUTIVE SUMMARY → TIMELINE
 *   → MITRE MAPPING → EVIDENCE TABLE
 *
 * For EXECUTIVE reports: only the EXECUTIVE SUMMARY section is included.
 * For TECHNICAL reports: TIMELINE + MITRE + EVIDENCE sections are included.
 * For COMBINED: all sections are included.
 */
@Component
public class PdfReportRenderer {

    private static final Logger log = LoggerFactory.getLogger(PdfReportRenderer.class);

    // Colour palette
    private static final DeviceRgb NAVY       = new DeviceRgb(30, 39, 73);
    private static final DeviceRgb ACCENT_RED = new DeviceRgb(180, 30, 30);

    private static final DateTimeFormatter DATE_FMT =
            DateTimeFormatter.ofPattern("dd MMMM yyyy HH:mm 'UTC'").withZone(ZoneOffset.UTC);

    // Section renderers — injected via constructor (Spring wires these)
    private final ExecutiveSummarySection executiveSummarySection;
    private final TimelineSection         timelineSection;
    private final MitreMappingSection     mitreMappingSection;
    private final EvidenceTableSection    evidenceTableSection;

    public PdfReportRenderer(ExecutiveSummarySection executiveSummarySection,
                              TimelineSection timelineSection,
                              MitreMappingSection mitreMappingSection,
                              EvidenceTableSection evidenceTableSection) {
        this.executiveSummarySection = executiveSummarySection;
        this.timelineSection         = timelineSection;
        this.mitreMappingSection     = mitreMappingSection;
        this.evidenceTableSection    = evidenceTableSection;
    }

    /**
     * Renders the full forensic report to a PDF byte array.
     *
     * @param report fully assembled ForensicReport domain object
     * @return PDF binary bytes suitable for streaming via HTTP response
     */
    public byte[] render(ForensicReport report) {
        log.info("Starting PDF render for report {}", report.getReportId());

        // ── 1. Set up in-memory output stream ───────────────────────────────
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try (PdfDocument pdfDoc = new PdfDocument(new PdfWriter(baos));
             Document doc = new Document(pdfDoc, PageSize.A4)) {

            // ── 2. Register page event handler for running header/footer ────
            pdfDoc.addEventHandler(PdfDocumentEvent.END_PAGE,
                    new HeaderFooterEventHandler(report, pdfDoc));

            // Leave margin at top for the running header (40pt) and bottom for footer
            doc.setMargins(60f, 40f, 50f, 40f);

            // ── 3. Cover page ────────────────────────────────────────────────
            renderCoverPage(doc, report);

            // ── 4. Determine which sections to include based on report type ─
            //    Strategy Pattern: EXECUTIVE vs TECHNICAL vs COMBINED controls
            //    which ReportSection implementations are called.
            List<ReportSection> sections = buildSectionList(report.getReportType(), report);

            // ── 5. Table of contents ─────────────────────────────────────────
            renderTableOfContents(doc, sections, report);

            // ── 6. Render each section in order ──────────────────────────────
            for (ReportSection section : sections) {
                section.render(doc, report);
            }

            // ── 7. Case detail pages (one per case, TECHNICAL + COMBINED) ───
            if (report.getReportType() != ReportType.EXECUTIVE && report.getCases() != null) {
                renderCaseDetailsSection(doc, report);
            }

        } catch (Exception e) {
            log.error("PDF rendering failed for report {}: {}", report.getReportId(), e.getMessage(), e);
            throw new RuntimeException("PDF generation failed: " + e.getMessage(), e);
        }

        log.info("PDF render complete for report {}, size {} bytes",
                report.getReportId(), baos.size());
        return baos.toByteArray();
    }

    // ── Cover page ────────────────────────────────────────────────────────────

    /**
     * Renders a professional cover page with:
     *  - CONFIDENTIAL classification banner (red)
     *  - Organization name and report title
     *  - Report metadata (ID, date, investigator)
     */
    private void renderCoverPage(Document doc, ForensicReport report) {
        // CONFIDENTIAL classification banner at top of cover
        doc.add(new Paragraph("⚠ CONFIDENTIAL — FORENSIC INVESTIGATION REPORT ⚠")
                .setFontSize(11f)
                .setBold()
                .setFontColor(ColorConstants.WHITE)
                .setBackgroundColor(ACCENT_RED)
                .setTextAlignment(TextAlignment.CENTER)
                .setPadding(8f)
                .setMarginBottom(40f));

        // Organization name
        String org = report.getOrganizationName() != null ? report.getOrganizationName() : "N/A";
        doc.add(new Paragraph(org)
                .setFontSize(22f)
                .setBold()
                .setFontColor(NAVY)
                .setTextAlignment(TextAlignment.CENTER));

        // Report title
        doc.add(new Paragraph("Cloud Forensics Investigation Report")
                .setFontSize(18f)
                .setFontColor(NAVY)
                .setTextAlignment(TextAlignment.CENTER)
                .setMarginBottom(60f));

        // Metadata block
        doc.add(new Paragraph("Report ID: " + report.getReportId())
                .setFontSize(10f).setTextAlignment(TextAlignment.CENTER));
        doc.add(new Paragraph("Generated: " + DATE_FMT.format(report.getGeneratedAt()))
                .setFontSize(10f).setTextAlignment(TextAlignment.CENTER));
        doc.add(new Paragraph("Report Type: " + report.getReportType())
                .setFontSize(10f).setTextAlignment(TextAlignment.CENTER));
        doc.add(new Paragraph("Cases Analysed: " +
                (report.getCases() != null ? report.getCases().size() : 0))
                .setFontSize(10f).setTextAlignment(TextAlignment.CENTER));

        String inv = report.getInvestigatorName() != null ? report.getInvestigatorName() : "N/A";
        doc.add(new Paragraph("Lead Investigator: " + inv)
                .setFontSize(10f).setTextAlignment(TextAlignment.CENTER).setMarginBottom(60f));

        // Legal disclaimer
        doc.add(new Paragraph(
                "This report contains privileged and confidential information intended solely for "
                + "the named recipient. Any unauthorized disclosure, copying, or distribution is "
                + "strictly prohibited. Report content does not include raw credentials or cloud "
                + "access keys.")
                .setFontSize(8f)
                .setItalic()
                .setFontColor(ColorConstants.GRAY)
                .setTextAlignment(TextAlignment.CENTER));

        // Force a new page after the cover
        doc.add(new AreaBreak(AreaBreakType.NEXT_PAGE));
    }

    // ── Table of contents ─────────────────────────────────────────────────────

    /** Renders a simple Table of Contents page listing active sections. */
    private void renderTableOfContents(Document doc, List<ReportSection> sections,
                                        ForensicReport report) {
        doc.add(new Paragraph("Table of Contents")
                .setFontSize(16f)
                .setBold()
                .setFontColor(NAVY)
                .setMarginBottom(12f));

        // Build TOC entries matching active sections
        String[] tocEntries = buildTocEntries(report.getReportType());
        int entryNum = 1;
        for (String entry : tocEntries) {
            doc.add(new Paragraph(entryNum + ".  " + entry)
                    .setFontSize(11f)
                    .setMarginBottom(6f));
            entryNum++;
        }

        // Case detail entries
        if (report.getReportType() != ReportType.EXECUTIVE && report.getCases() != null) {
            for (var c : report.getCases()) {
                doc.add(new Paragraph("      Case " + c.getCaseId() + " — " + c.getUser())
                        .setFontSize(10f)
                        .setFontColor(ColorConstants.GRAY));
            }
        }

        doc.add(new AreaBreak(AreaBreakType.NEXT_PAGE));
    }

    // ── Per-case detail section ───────────────────────────────────────────────

    /**
     * Renders one detailed subsection per IncidentCase showing:
     *  - Case metadata (ID, user, severity, IP, event count)
     *  - Correlation reason
     *  - Related events table
     */
    private void renderCaseDetailsSection(Document doc, ForensicReport report) {
        doc.add(new Paragraph("5. Case Details")
                .setFontSize(16f)
                .setBold()
                .setFontColor(NAVY)
                .setMarginTop(20f)
                .setMarginBottom(8f));

        for (var cas : report.getCases()) {
            // Case sub-heading
            doc.add(new Paragraph("Case " + cas.getCaseId() + " — " + cas.getUser())
                    .setFontSize(13f)
                    .setBold()
                    .setFontColor(NAVY)
                    .setMarginTop(12f)
                    .setMarginBottom(6f));

            // Metadata table
            Table meta = new Table(UnitValue.createPercentArray(new float[]{30, 70}))
                    .useAllAvailableWidth().setMarginBottom(8f);
            addMetaRow(meta, "Case ID", cas.getCaseId());
            addMetaRow(meta, "User", cas.getUser());
            addMetaRow(meta, "Primary IP", cas.getIp());
            addMetaRow(meta, "Severity", cas.getSeverity());
            addMetaRow(meta, "Event Count", String.valueOf(cas.getLinkedEventCount()));
            addMetaRow(meta, "Correlation Reason", cas.getCorrelationReason());
            doc.add(meta);

            // Related events sub-table
            if (cas.getRelatedEvents() != null && !cas.getRelatedEvents().isEmpty()) {
                doc.add(new Paragraph("Related Events:").setFontSize(9f).setBold().setMarginBottom(4f));
                Table evtTable = new Table(UnitValue.createPercentArray(new float[]{20, 18, 15, 12, 35}))
                        .useAllAvailableWidth();

                evtTable.addHeaderCell(makeHeaderCell("Timestamp"));
                evtTable.addHeaderCell(makeHeaderCell("Event Type"));
                evtTable.addHeaderCell(makeHeaderCell("User"));
                evtTable.addHeaderCell(makeHeaderCell("Status"));
                evtTable.addHeaderCell(makeHeaderCell("Detection Reason"));

                for (var evt : cas.getRelatedEvents()) {
                    evtTable.addCell(new Paragraph(safe(evt.getTimestamp())).setFontSize(8f));
                    evtTable.addCell(new Paragraph(safe(evt.getEventType())).setFontSize(8f));
                    evtTable.addCell(new Paragraph(safe(evt.getUser())).setFontSize(8f));
                    evtTable.addCell(new Paragraph(safe(evt.getStatus())).setFontSize(8f));
                    evtTable.addCell(new Paragraph(safe(evt.getDetectionReason())).setFontSize(7f));
                }
                doc.add(evtTable);
            }
        }
    }

    // ── Section list factory (Strategy Pattern) ───────────────────────────────

    /**
     * Builds the ordered list of ReportSection implementations to execute,
     * based on the requested report type.
     *
     * EXECUTIVE  → [ExecutiveSummary]
     * TECHNICAL  → [Timeline, MitreMapping, EvidenceTable]
     * COMBINED   → [ExecutiveSummary, Timeline, MitreMapping, EvidenceTable]
     */
    private List<ReportSection> buildSectionList(ReportType type, ForensicReport report) {
        List<ReportSection> sections = new ArrayList<>();
        if (type == null) type = ReportType.COMBINED;

        boolean includeExecutive = type == ReportType.EXECUTIVE || type == ReportType.COMBINED;
        boolean includeTechnical = type == ReportType.TECHNICAL || type == ReportType.COMBINED;

        if (includeExecutive) sections.add(executiveSummarySection);

        if (includeTechnical) {
            if (report.getAttackTimeline() != null) sections.add(timelineSection);
            if (report.getMitreMapping() != null)   sections.add(mitreMappingSection);
            if (report.getEvidenceTable() != null)  sections.add(evidenceTableSection);
        }

        return sections;
    }

    private String[] buildTocEntries(ReportType type) {
        if (type == ReportType.EXECUTIVE) {
            return new String[]{"Executive Summary"};
        } else if (type == ReportType.TECHNICAL) {
            return new String[]{"Attack Timeline", "MITRE ATT&CK Mapping",
                    "Evidence Hash Table", "Case Details"};
        }
        return new String[]{"Executive Summary", "Attack Timeline",
                "MITRE ATT&CK Mapping", "Evidence Hash Table", "Case Details"};
    }

    // ── iText helper utilities ────────────────────────────────────────────────

    private void addMetaRow(Table table, String key, String value) {
        table.addCell(new Paragraph(key).setFontSize(9f).setBold());
        table.addCell(new Paragraph(value != null ? value : "—").setFontSize(9f));
    }

    private Cell makeHeaderCell(String text) {
        return new Cell()
                .add(new Paragraph(text).setFontSize(8f).setBold()
                        .setFontColor(ColorConstants.WHITE))
                .setBackgroundColor(NAVY);
    }

    private String safe(String s) { return s != null ? s : "—"; }

    // ── Page Event Handler — running header and page number footer ─────────────

    /**
     * Adds a CONFIDENTIAL header banner and page number footer to every page.
     * Implemented as an IEventHandler registered on PdfDocumentEvent.END_PAGE.
     */
    private static class HeaderFooterEventHandler implements IEventHandler {

        private final ForensicReport report;
        private final PdfDocument pdfDoc;
        private static final DeviceRgb ACCENT_RED = new DeviceRgb(180, 30, 30);
        private static final DeviceRgb NAVY       = new DeviceRgb(30, 39, 73);

        HeaderFooterEventHandler(ForensicReport report, PdfDocument pdfDoc) {
            this.report = report;
            this.pdfDoc = pdfDoc;
        }

        @Override
        public void handleEvent(Event event) {
            PdfDocumentEvent docEvent = (PdfDocumentEvent) event;
            PdfPage page = docEvent.getPage();
            Rectangle pageSize = page.getPageSize();
            PdfCanvas pdfCanvas = new PdfCanvas(page);

            // ── Running header — CONFIDENTIAL banner ───────────────────────
            try (Canvas headerCanvas = new Canvas(pdfCanvas, pageSize)) {
                headerCanvas.add(new Paragraph("CONFIDENTIAL — Cloud Forensics Report — " +
                        (report.getOrganizationName() != null ? report.getOrganizationName() : ""))
                        .setFontSize(7f)
                        .setBold()
                        .setFontColor(ACCENT_RED)
                        .setFixedPosition(40f, pageSize.getTop() - 20f, pageSize.getWidth() - 80f)
                        .setTextAlignment(TextAlignment.CENTER));
            }

            // ── Footer — page number ─────────────────────────────────────
            int pageNum = pdfDoc.getPageNumber(page);
            try (Canvas footerCanvas = new Canvas(pdfCanvas, pageSize)) {
                footerCanvas.add(new Paragraph("Page " + pageNum +
                        " | Report ID: " + report.getReportId())
                        .setFontSize(7f)
                        .setFontColor(NAVY)
                        .setFixedPosition(40f, 15f, pageSize.getWidth() - 80f)
                        .setTextAlignment(TextAlignment.CENTER));
            }
        }
    }
}
