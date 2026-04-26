package com.cloudforensics.service.pdf.sections;

import com.cloudforensics.model.ForensicReport;
import com.cloudforensics.model.LogResponseDTO;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;

import com.itextpdf.layout.properties.UnitValue;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * PDF Section — Attack Timeline
 *
 * Renders a chronologically ordered table of all log events across the included
 * cases. Each row shows: timestamp | eventType | user | IP | outcome | detection reason.
 *
 * The timeline data (attackTimeline) is pre-sorted by ForensicReportService
 * before being stored in ForensicReport, so this section just renders row by row.
 */
@Component
public class TimelineSection extends ReportSection {

    private static final DeviceRgb HEADER_COLOR  = new DeviceRgb(30, 39, 73);
    private static final DeviceRgb ROW_ALT_COLOR = new DeviceRgb(240, 244, 255); // light blue-grey

    @Override
    public void render(Document doc, ForensicReport report) {
        // ── Section heading ──────────────────────────────────────────────────
        doc.add(new Paragraph("2. Attack Timeline")
                .setFontSize(16f)
                .setBold()
                .setFontColor(HEADER_COLOR)
                .setMarginTop(20f)
                .setMarginBottom(8f));

        List<LogResponseDTO> timeline = report.getAttackTimeline();

        if (timeline == null || timeline.isEmpty()) {
            doc.add(new Paragraph("No timeline events available for this report.")
                    .setFontSize(10f).setItalic());
            return;
        }

        // 6-column timeline table
        Table table = new Table(UnitValue.createPercentArray(new float[]{18, 18, 15, 13, 12, 24}))
                .useAllAvailableWidth();

        // Header row
        addHeaderCell(table, "Timestamp");
        addHeaderCell(table, "Event Type");
        addHeaderCell(table, "User");
        addHeaderCell(table, "IP Address");
        addHeaderCell(table, "Outcome");
        addHeaderCell(table, "Detection Reason");

        // Data rows — alternate background for readability
        boolean alternate = false;
        for (LogResponseDTO event : timeline) {
            DeviceRgb rowBg = alternate ? ROW_ALT_COLOR : null;
            alternate = !alternate;

            addDataCell(table, event.getTimestamp(), rowBg);
            addDataCell(table, event.getEventType(), rowBg);
            addDataCell(table, event.getUser(), rowBg);
            addDataCell(table, event.getIp(), rowBg);
            addDataCell(table, event.getStatus(), rowBg);
            addDataCell(table, truncate(event.getDetectionReason(), 60), rowBg);
        }

        doc.add(table);
        doc.add(new Paragraph("\n")); // spacing after section
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void addHeaderCell(Table table, String text) {
        table.addHeaderCell(new Cell()
                .add(new Paragraph(text).setFontSize(8f).setBold()
                        .setFontColor(ColorConstants.WHITE))
                .setBackgroundColor(HEADER_COLOR));
    }

    private void addDataCell(Table table, String text, DeviceRgb bg) {
        Cell cell = new Cell().add(new Paragraph(text != null ? text : "—").setFontSize(8f));
        if (bg != null) cell.setBackgroundColor(bg);
        table.addCell(cell);
    }

    private String truncate(String text, int max) {
        if (text == null) return "—";
        return text.length() > max ? text.substring(0, max) + "…" : text;
    }
}
