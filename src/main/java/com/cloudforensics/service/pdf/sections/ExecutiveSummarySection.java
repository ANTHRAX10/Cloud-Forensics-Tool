package com.cloudforensics.service.pdf.sections;

import com.cloudforensics.model.ForensicReport;
import com.cloudforensics.model.IncidentCase;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import org.springframework.stereotype.Component;

/**
 * PDF Section — Executive Summary
 *
 * Renders:
 *  1. A section heading "Executive Summary"
 *  2. The auto-generated executiveSummary paragraph from ForensicReport
 *  3. A compact case-overview table (case ID | user | severity | event count)
 *
 * Strategy: For EXECUTIVE reports, show only this section.
 *           For TECHNICAL/COMBINED, this section appears first.
 */
@Component
public class ExecutiveSummarySection extends ReportSection {

    // Colour palette for severity cells
    private static final DeviceRgb CRITICAL_COLOR = new DeviceRgb(220, 53, 69);   // red
    private static final DeviceRgb HIGH_COLOR      = new DeviceRgb(255, 140, 0);  // orange
    private static final DeviceRgb MEDIUM_COLOR    = new DeviceRgb(255, 193, 7);  // amber
    private static final DeviceRgb LOW_COLOR       = new DeviceRgb(40, 167, 69);  // green
    private static final DeviceRgb HEADER_COLOR    = new DeviceRgb(30, 39, 73);   // navy

    @Override
    public void render(Document doc, ForensicReport report) {
        // ── Section heading ──────────────────────────────────────────────────
        doc.add(new Paragraph("1. Executive Summary")
                .setFontSize(16f)
                .setBold()
                .setFontColor(HEADER_COLOR)
                .setMarginTop(20f)
                .setMarginBottom(8f));

        // ── Auto-generated executive summary paragraph ───────────────────────
        String summary = report.getExecutiveSummary() != null
                ? report.getExecutiveSummary()
                : "No summary available.";

        doc.add(new Paragraph(summary)
                .setFontSize(10f)
                .setTextAlignment(TextAlignment.JUSTIFIED)
                .setMarginBottom(16f));

        // ── Case overview table ──────────────────────────────────────────────
        if (report.getCases() == null || report.getCases().isEmpty()) {
            doc.add(new Paragraph("No incident cases were included in this report.")
                    .setFontSize(10f)
                    .setItalic());
            return;
        }

        // Build a 4-column table spanning the full page width
        Table table = new Table(UnitValue.createPercentArray(new float[]{15, 30, 20, 15, 20}))
                .useAllAvailableWidth();

        // Table header row
        addHeaderCell(table, "Case ID");
        addHeaderCell(table, "User");
        addHeaderCell(table, "Severity");
        addHeaderCell(table, "Events");
        addHeaderCell(table, "Correlation Reason");

        // Data rows — one per IncidentCase
        for (IncidentCase ic : report.getCases()) {
            table.addCell(new Cell().add(new Paragraph(ic.getCaseId()).setFontSize(9f)));
            table.addCell(new Cell().add(new Paragraph(ic.getUser()).setFontSize(9f)));

            // Severity cell gets a background colour appropriate to its level
            Cell severityCell = new Cell().add(
                    new Paragraph(ic.getSeverity()).setFontSize(9f).setBold()
                            .setFontColor(ColorConstants.WHITE)
                            .setTextAlignment(TextAlignment.CENTER));
            severityCell.setBackgroundColor(resolveSeverityColor(ic.getSeverity()));
            table.addCell(severityCell);

            table.addCell(new Cell().add(
                    new Paragraph(String.valueOf(ic.getLinkedEventCount())).setFontSize(9f)
                            .setTextAlignment(TextAlignment.CENTER)));
            table.addCell(new Cell().add(
                    new Paragraph(truncate(ic.getCorrelationReason(), 60)).setFontSize(8f)));
        }

        doc.add(table);
        doc.add(new Paragraph("\n"));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void addHeaderCell(Table table, String text) {
        table.addHeaderCell(new Cell()
                .add(new Paragraph(text).setFontSize(9f).setBold().setFontColor(ColorConstants.WHITE))
                .setBackgroundColor(HEADER_COLOR));
    }

    private DeviceRgb resolveSeverityColor(String severity) {
        if (severity == null) return LOW_COLOR;
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> CRITICAL_COLOR;
            case "HIGH"     -> HIGH_COLOR;
            case "MEDIUM"   -> MEDIUM_COLOR;
            default         -> LOW_COLOR;
        };
    }

    private String truncate(String text, int max) {
        if (text == null) return "";
        return text.length() > max ? text.substring(0, max) + "…" : text;
    }
}
