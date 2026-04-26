package com.cloudforensics.service.pdf.sections;

import com.cloudforensics.model.ForensicReport;
import com.cloudforensics.model.MitreTechnique;
import com.itextpdf.kernel.colors.ColorConstants;
import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.layout.Document;
import com.itextpdf.layout.element.Cell;
import com.itextpdf.layout.element.Paragraph;
import com.itextpdf.layout.element.Table;

import com.itextpdf.layout.properties.UnitValue;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * PDF Section — MITRE ATT&CK Mapping
 *
 * Renders the detected MITRE techniques grouped by tactic (kill-chain phase).
 * Each tactic produces one subsection with a technique table.
 *
 * Layout:
 *   ┌──────────────────────────────────────────────────────┐
 *   │  3. MITRE ATT&CK Mapping                            │
 *   ├──────────────┬──────────────────────┬───────────────┤
 *   │  Tactic      │  Technique ID        │  Technique    │
 *   │  Initial Access │ T1078            │  Valid Accts  │
 *   │  Discovery   │  T1526              │  Cloud Svc…   │
 *   └──────────────┴──────────────────────┴───────────────┘
 */
@Component
public class MitreMappingSection extends ReportSection {

    private static final DeviceRgb HEADER_COLOR  = new DeviceRgb(30, 39, 73);
    private static final DeviceRgb TACTIC_BG     = new DeviceRgb(52, 73, 130);  // mid-navy
    private static final DeviceRgb TRIGGER_COLOR = new DeviceRgb(100, 120, 160); // muted blue

    @Override
    public void render(Document doc, ForensicReport report) {
        // ── Section heading ──────────────────────────────────────────────────
        doc.add(new Paragraph("3. MITRE ATT\u0026CK Mapping")
                .setFontSize(16f)
                .setBold()
                .setFontColor(HEADER_COLOR)
                .setMarginTop(20f)
                .setMarginBottom(8f));

        List<MitreTechnique> techniques = report.getMitreMapping();

        if (techniques == null || techniques.isEmpty()) {
            doc.add(new Paragraph(
                    "No MITRE ATT\u0026CK techniques were mapped for the included events.")
                    .setFontSize(10f).setItalic());
            return;
        }

        // Group techniques by tactic so we can render one sub-table per tactic
        Map<String, List<MitreTechnique>> byTactic = techniques.stream()
                .collect(Collectors.groupingBy(
                        t -> t.getTactic() != null ? t.getTactic() : "Uncategorised"));

        // 4-column master table: tactic | technique ID | technique name | triggering event
        Table table = new Table(UnitValue.createPercentArray(new float[]{22, 16, 34, 28}))
                .useAllAvailableWidth();

        // Table header
        addHeaderCell(table, "Tactic");
        addHeaderCell(table, "Technique ID");
        addHeaderCell(table, "Technique Name");
        addHeaderCell(table, "Triggering Event");

        // Iterate tactics alphabetically for reproducible output
        byTactic.entrySet().stream()
                .sorted(Map.Entry.comparingByKey())
                .forEach(entry -> {
                    String tactic = entry.getKey();
                    List<MitreTechnique> tacticTechniques = entry.getValue();

                    // First technique in the tactic group — tactic label spans multiple rows
                    boolean firstRow = true;
                    for (MitreTechnique t : tacticTechniques) {
                        if (firstRow) {
                            // Tactic label cell — navy background
                            table.addCell(new Cell(1, 1)
                                    .add(new Paragraph(tactic).setFontSize(9f).setBold()
                                            .setFontColor(ColorConstants.WHITE))
                                    .setBackgroundColor(TACTIC_BG));
                            firstRow = false;
                        } else {
                            // Continuation rows for same tactic — no label
                            table.addCell(new Cell()
                                    .add(new Paragraph("").setFontSize(9f))
                                    .setBackgroundColor(TACTIC_BG));
                        }

                        // Technique ID in bold monospace-style
                        table.addCell(new Cell()
                                .add(new Paragraph(t.getTechniqueId()).setFontSize(9f).setBold()));

                        // Full technique name
                        table.addCell(new Cell()
                                .add(new Paragraph(t.getTechniqueName()).setFontSize(9f)));

                        // Triggering event in a muted colour
                        table.addCell(new Cell()
                                .add(new Paragraph(t.getTriggeringEventType()).setFontSize(8f)
                                        .setFontColor(TRIGGER_COLOR)));
                    }
                });

        doc.add(table);

        // Disclaimer note below the matrix
        doc.add(new Paragraph(
                "Note: Technique mapping is based on observed event types against the configured "
                + "mitre-mapping.json. Verify against the MITRE ATT\u0026CK knowledge base "
                + "(https://attack.mitre.org/) for the latest technique definitions.")
                .setFontSize(8f).setItalic().setFontColor(ColorConstants.GRAY).setMarginTop(6f));

        doc.add(new Paragraph("\n"));
    }

    // ── Helper ───────────────────────────────────────────────────────────────

    private void addHeaderCell(Table table, String text) {
        table.addHeaderCell(new Cell()
                .add(new Paragraph(text).setFontSize(9f).setBold()
                        .setFontColor(ColorConstants.WHITE))
                .setBackgroundColor(HEADER_COLOR));
    }
}
