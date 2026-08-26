"""One-page forensic PDF.   OWNER: M4.

Uses reportlab (already in requirements.txt).

PRIORITY WARNING: the JSON report satisfies the deliverable on its own.  Get
report_builder.py + custody_log.py fully working FIRST, and only then spend time
here.  PDF layout is the single easiest place in this project to lose four hours
to nothing.  If it is Day 2 afternoon and the PDF is not done, ship JSON and
say "PDF export is wired but we prioritised evidence integrity" - that is a
perfectly good answer.
"""
from __future__ import annotations

IS_STUB = True   # <-- M4: set False when render_pdf is implemented

PAGE_TITLE = "EMAIL FORENSIC ANALYSIS REPORT"
TOOL_NAME = "SIH26106 Email Forensic Analyzer v1.0"

BAND_COLOURS = {   # hex, shared with the frontend palette so PDF matches screen
    "low": "#1a7f37", "medium": "#9a6700", "high": "#bc4c00", "critical": "#b3261e",
}


def render_pdf(payload: dict, out_path: str) -> str:
    """Render build_report_payload() output to a PDF.  -> out_path

    TODO(M4) - simplest reliable approach with reportlab:
      from reportlab.lib.pagesizes import A4
      from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, Spacer
      from reportlab.lib.styles import getSampleStyleSheet

      story = []  then append in the payload's section order.
      Table() for the routing chain and the auth results - Table handles column
      widths for you and looks far more "forensic" than paragraphs.
      Put the risk band colour behind the score cell via TableStyle BACKGROUND.
      doc.build(story)

    Non-negotiable content requirements:
      * origin["statement"] printed VERBATIM, in the summary, in full
      * every confidence_reason as its own bullet
      * the full LIMITATIONS_TEXT section - do not trim it to fit one page;
        let it run to page 2 rather than cutting a limitation
      * evidence_sha256 in a monospace font in the footer of every page, plus
        the custody entry number

    Use Paragraph() for anything user-supplied (subject lines, display names) -
    reportlab interprets a bare '&' or '<' as markup and will raise on real
    phishing subject lines.  Escape with xml.sax.saxutils.escape() first.
    That crash WILL happen with a real sample; escape from the start.
    """
    raise NotImplementedError("M4: implement render_pdf")
