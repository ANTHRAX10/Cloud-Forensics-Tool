package com.cloudforensics.service.pdf.sections;

import com.cloudforensics.model.EvidenceRecord;
import com.cloudforensics.model.ForensicReport;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;
import com.itextpdf.layout.properties.TextAlignment;
import com.itextpdf.layout.properties.UnitValue;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * PDF Section — Evidence Hash Table (with Chain of Custody)
 *
 * Renders the evidence inventory showing each artifact's:
 *  - Evidence name (chain of custody label)
 *  - Evidence type (LOG_BUNDLE, CONFIG_SNAPSHOT, etc.)
 *  - Collector (investigator who captured this evidence)
 *  - SHA-256 digest
 *  - Source timestamp and originating IP
 *  - Verification status (✓ / ✗)
 *
 * The SHA-256 column uses a smaller font to fit the 64-char hex digest.
 * The verified status is displayed as ✓ (green) or ✗ (red).
 */
@Component
public class EvidenceTableSection extends ReportSection {

    private static final DeviceRgb HEADER_COLOR   = new DeviceRgb(30, 39, 73);
    private static final DeviceRgb VERIFIED_COLOR = new DeviceRgb(40, 167, 69);   // green
    private static final DeviceRgb FAILED_COLOR   = new DeviceRgb(220, 53, 69);   // red
    private static final DeviceRgb ROW_ALT_COLOR  = new DeviceRgb(245, 247, 255); // very light blue

    @Override
    public void render(Document doc, ForensicReport report) {
        // ── Section heading ──────────────────────────────────────────────────
        doc.add(new Paragraph("4. Evidence Hash Table & Chain of Custody")
                .setFontSize(16f)
                .setBold()
                .setFontColor(HEADER_COLOR)
                .setMarginTop(20f)
                .setMarginBottom(8f));

        List<EvidenceRecord> evidence = report.getEvidenceTable();

        if (evidence == null || evidence.isEmpty()) {
            doc.add(new Paragraph("No evidence records available for this report.")
                    .setFontSize(10f).setItalic());
            return;
        }

        // ── Evidence Hash Table ──────────────────────────────────────────────
        // 5-column table: name | SHA-256 hash | timestamp | source IP | verified
        doc.add(new Paragraph("Evidence Integrity Records")
                .setFontSize(12f).setBold().setFontColor(HEADER_COLOR).setMarginBottom(6f));

        Table hashTable = new Table(UnitValue.createPercentArray(new float[]{20, 35, 17, 15, 13}))
                .useAllAvailableWidth();

        // Header row
        addHeaderCell(hashTable, "Evidence Name");
        addHeaderCell(hashTable, "SHA-256 Hash");
        addHeaderCell(hashTable, "Timestamp");
        addHeaderCell(hashTable, "Source IP");
        addHeaderCell(hashTable, "Verified");

        // Data rows with alternating background
        boolean alternate = false;
        for (EvidenceRecord rec : evidence) {
            DeviceRgb rowBg = alternate ? ROW_ALT_COLOR : null;
            alternate = !alternate;

            // Evidence name
            addDataCell(hashTable, rec.getName(), rowBg, false);

            // SHA-256 hash — rendered in smaller font to fit the 64-char hex
            Cell hashCell = new Cell()
                    .add(new Paragraph(rec.getSha256Hash() != null ? rec.getSha256Hash() : "\u2014")
                            .setFontSize(7f));
            if (rowBg != null) hashCell.setBackgroundColor(rowBg);
            hashTable.addCell(hashCell);

            // Timestamp
            addDataCell(hashTable, rec.getTimestamp(), rowBg, false);

            // Source IP
            addDataCell(hashTable, rec.getSourceIp(), rowBg, false);

            // Verification status — colour-coded tick or cross
            boolean verified = rec.isVerified();
            Cell verifiedCell = new Cell()
                    .add(new Paragraph(verified ? "\u2713 Yes" : "\u2717 No")
                            .setFontSize(9f).setBold()
                            .setFontColor(verified ? VERIFIED_COLOR : FAILED_COLOR)
                            .setTextAlignment(TextAlignment.CENTER));
            if (rowBg != null) verifiedCell.setBackgroundColor(rowBg);
            hashTable.addCell(verifiedCell);
        }

        doc.add(hashTable);

        // ── Chain of Custody sub-section ─────────────────────────────────────
        doc.add(new Paragraph("Chain of Custody Log")
                .setFontSize(12f).setBold().setFontColor(HEADER_COLOR)
                .setMarginTop(14f).setMarginBottom(6f));

        // 4-column chain of custody table: evidence label | type | collected by | timestamp
        Table cocTable = new Table(UnitValue.createPercentArray(new float[]{30, 20, 25, 25}))
                .useAllAvailableWidth();

        addHeaderCell(cocTable, "Evidence Label");
        addHeaderCell(cocTable, "Evidence Type");
        addHeaderCell(cocTable, "Collected By");
        addHeaderCell(cocTable, "Collection Time");

        alternate = false;
        for (EvidenceRecord rec : evidence) {
            DeviceRgb rowBg = alternate ? ROW_ALT_COLOR : null;
            alternate = !alternate;

            // Evidence label (chain of custody identifier)
            addDataCell(cocTable, rec.getEvidenceName(), rowBg, false);

            // Evidence type enum
            String typeLabel = rec.getEvidenceType() != null
                    ? rec.getEvidenceType().name().replace("_", " ") : "LOG BUNDLE";
            addDataCell(cocTable, typeLabel, rowBg, true);

            // Collected by (investigator)
            addDataCell(cocTable, rec.getCollectedBy(), rowBg, false);

            // Collection timestamp
            addDataCell(cocTable, rec.getTimestamp(), rowBg, false);
        }

        doc.add(cocTable);

        // Chain-of-custody legal note
        doc.add(new Paragraph(
                "Chain of Custody: All SHA-256 hashes were computed server-side at report generation "
                + "time from in-memory event data. Evidence marked \u2713 has been verified against "
                + "the original log source. Raw credentials and access keys are excluded from all "
                + "evidence entries in compliance with security policy. Each evidence item is tracked "
                + "with a unique label, evidence classification, and collector identity to maintain "
                + "a complete chain of custody suitable for legal proceedings.")
                .setFontSize(8f).setItalic().setFontColor(ColorConstants.GRAY).setMarginTop(6f));

        doc.add(new Paragraph("\n"));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void addHeaderCell(Table table, String text) {
        table.addHeaderCell(new Cell()
                .add(new Paragraph(text).setFontSize(9f).setBold()
                        .setFontColor(ColorConstants.WHITE))
                .setBackgroundColor(HEADER_COLOR));
    }

    private void addDataCell(Table table, String text, DeviceRgb bg, boolean bold) {
        Paragraph p = new Paragraph(text != null ? text : "\u2014").setFontSize(9f);
        if (bold) p.setBold();
        Cell cell = new Cell().add(p);
        if (bg != null) cell.setBackgroundColor(bg);
        table.addCell(cell);
    }
}
