package com.cloudforensics.service.pdf.sections;

import com.cloudforensics.model.ForensicReport;
import com.itextpdf.layout.Document;

/**
 * Abstract base class implementing the Template Method Pattern for PDF sections.
 *
 * Each concrete section (ExecutiveSummary, Timeline, etc.) overrides render()
 * to inject its content into the iText Document at the appropriate position.
 * The addSectionHeading() helper ensures consistent heading typography.
 *
 * Template Method contract:
 *   1. PdfReportRenderer calls render(doc, report) on each registered section.
 *   2. Each section writes its content using the provided Document handle.
 *   3. Sections do NOT close the document — only the renderer does that.
 */
public abstract class ReportSection {

    /**
     * Render this section's content into the provided iText Document.
     *
     * @param doc    the live iText Document (page already set up by renderer)
     * @param report the fully assembled ForensicReport domain object
     */
    public abstract void render(Document doc, ForensicReport report);
}
