"""Forensic PDF report.   OWNER: M4.

Uses reportlab (already in requirements.txt).

PRIORITY WARNING: the JSON report satisfies the deliverable on its own.  Get
report_builder.py + custody_log.py fully working FIRST, and only then spend time
here.  PDF layout is the single easiest place in this project to lose four hours
to nothing.  If it is Day 2 afternoon and the PDF is not done, ship JSON and
say "PDF export is wired but we prioritised evidence integrity" - that is a
perfectly good answer.

Two deliberate design choices worth knowing about:

  * reportlab is imported INSIDE render_pdf(), not at module top level.  If the
    package is missing, we raise NotImplementedError, which main.py already
    catches and turns into a clean 501 "use the JSON report".  A top-level
    import would make the whole app fail to start on a teammate's machine that
    has not run pip install yet - one member's missing dependency would take
    down everyone's demo.
  * every piece of message-derived text goes through _p(), which escapes it.
    reportlab parses Paragraph content as markup, so a bare '&' or '<' in a real
    phishing subject line raises.  That WILL happen with a real sample.
"""
from __future__ import annotations

from xml.sax.saxutils import escape

from .report_builder import LIMITATIONS_TEXT, TOOL_NAME, TOOL_VERSION

IS_STUB = False   # implemented

PAGE_TITLE = "EMAIL FORENSIC ANALYSIS REPORT"

BAND_COLOURS = {   # hex, shared with the frontend palette so PDF matches screen
    "low": "#1a7f37", "medium": "#9a6700", "high": "#bc4c00", "critical": "#b3261e",
}
CONFIDENCE_COLOURS = {   # high CONFIDENCE is good; high RISK is bad. Different scales.
    "high": "#1a7f37", "medium": "#9a6700", "low": "#b3261e",
}
INK = "#1b1b1b"
MUTED = "#5c5c5c"
RULE = "#d0d0d0"
BAND_BG = "#f4f4f5"


def _fmt(value, default: str = "—") -> str:
    """Display value.  None, empty string and empty list all collapse to the
    placeholder so the PDF never prints a bare 'None'."""
    if value is None or value == "" or value == []:
        return default
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return str(value)


def render_pdf(payload: dict, out_path: str) -> str:
    """Render build_report_payload() output to a PDF.  -> out_path

    `payload` is the dict from report_builder.build_report_payload().  Both
    files are M4-owned, so if you change that shape, change it here in the same
    commit.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (CondPageBreak, HRFlowable, KeepTogether,
                                        Paragraph, SimpleDocTemplate, Spacer,
                                        Table, TableStyle)
    except ImportError as exc:   # main.py already turns this into a clean 501
        raise NotImplementedError(
            "reportlab is not installed; run pip install -r backend/requirements.txt"
        ) from exc

    header = payload.get("case_header") or {}
    summary = payload.get("summary") or {}
    sender = payload.get("sender_identity") or {}
    auth = payload.get("authentication") or {}
    routing = payload.get("routing") or {}
    origin = payload.get("origin_analysis") or {}
    integrity = payload.get("integrity") or {}
    limitations = payload.get("limitations") or LIMITATIONS_TEXT

    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["Normal"], fontName="Helvetica",
                          fontSize=9, leading=13, textColor=colors.HexColor(INK),
                          alignment=TA_LEFT)
    small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=10,
                           textColor=colors.HexColor(MUTED))
    mono = ParagraphStyle("mono", parent=body, fontName="Courier", fontSize=8,
                          leading=11)
    h1 = ParagraphStyle("h1", parent=body, fontName="Helvetica-Bold",
                        fontSize=15, leading=19, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=body, fontName="Helvetica-Bold",
                        fontSize=10.5, leading=14, spaceBefore=11, spaceAfter=4,
                        textColor=colors.HexColor(INK))
    bullet = ParagraphStyle("bullet", parent=body, leftIndent=10, bulletIndent=1,
                            spaceAfter=2)
    statement = ParagraphStyle("statement", parent=body, fontSize=9.5, leading=14,
                              leftIndent=8, rightIndent=8, spaceBefore=4,
                              spaceAfter=4, borderPadding=6,
                              backColor=colors.HexColor(BAND_BG))

    def _p(text, style=body):
        """The escaping choke point. Everything message-derived goes through here."""
        return Paragraph(escape(_fmt(text)), style)

    def _kv_table(rows, key_width=42*mm):
        """Two-column label/value table used for most sections."""
        data = [[_p(k, small), _p(v)] for k, v in rows]
        t = Table(data, colWidths=[key_width, None], hAlign="LEFT")
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("LINEBELOW", (0, 0), (-1, -2), 0.25, colors.HexColor(RULE)),
        ]))
        return t

    def _grid_table(head, rows, widths=None, highlight_rows=()):
        """Bordered data table for the routing chain, auth results, candidates."""
        data = [[_p(c, small) for c in head]]
        data += [[_p(c, small) for c in row] for row in rows]
        t = Table(data, colWidths=widths, hAlign="LEFT", repeatRows=1)
        style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(BAND_BG)),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor(RULE)),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]
        for r in highlight_rows:
            style.append(("TEXTCOLOR", (0, r + 1), (-1, r + 1),
                          colors.HexColor(MUTED)))
        t.setStyle(TableStyle(style))
        return t

    story: list = []

    # ---- title block -------------------------------------------------------
    story.append(Paragraph(PAGE_TITLE, h1))
    story.append(Paragraph(
        escape(f"{TOOL_NAME} v{TOOL_VERSION} · report {_fmt(header.get('report_id'))} "
               f"· generated {_fmt(header.get('generated_at'))}"), small))
    story.append(Spacer(1, 4))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor(INK),
                            spaceBefore=0, spaceAfter=0))

    # ---- 1. case header ----------------------------------------------------
    inp = header.get("input") or {}
    story.append(Paragraph("1. Case header", h2))
    story.append(_kv_table([
        ("Report ID", header.get("report_id")),
        ("Analysis ID", header.get("analysis_id")),
        ("Analysed at (UTC)", header.get("analyzed_at")),
        ("Report generated (UTC)", header.get("generated_at")),
        ("Tool", f"{TOOL_NAME} v{TOOL_VERSION}"),
        ("Input source", inp.get("source")),
        ("Original filename", inp.get("filename")),
        ("Input size (bytes)", inp.get("byte_size")),
        ("Input SHA-256", inp.get("sha256")),
    ]))

    # ---- 2. summary --------------------------------------------------------
    story.append(Paragraph("2. Summary of findings", h2))
    band = str(summary.get("risk_band") or "low").lower()
    conf = str(summary.get("confidence") or "low").lower()
    verdict = str(summary.get("verdict") or "inconclusive").replace("_", " ")
    score_tbl = Table(
        [[_p(f"RISK {_fmt(summary.get('risk_score'))}/100", mono),
          _p(band.upper(), mono),
          _p(f"VERDICT: {verdict.upper()}", mono),
          _p(f"ORIGIN CONFIDENCE: {conf.upper()}", mono)]],
        colWidths=[32*mm, 26*mm, 56*mm, None], hAlign="LEFT")
    score_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (1, 0),
         colors.HexColor(BAND_COLOURS.get(band, BAND_COLOURS["low"]))),
        ("TEXTCOLOR", (0, 0), (1, 0), colors.white),
        ("BACKGROUND", (3, 0), (3, 0),
         colors.HexColor(CONFIDENCE_COLOURS.get(conf, CONFIDENCE_COLOURS["low"]))),
        ("TEXTCOLOR", (3, 0), (3, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor(RULE)),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 6))

    # origin statement, VERBATIM and in full - API_CONTRACT.md section 6
    story.append(_p(summary.get("origin_statement"), statement))

    triggered = summary.get("signals_triggered") or []
    story.append(Spacer(1, 4))
    story.append(_p(
        f"{len(triggered)} of {_fmt(summary.get('signals_evaluated_count'), '0')} "
        f"risk signals triggered.", small))
    if triggered:
        story.append(Spacer(1, 3))
        story.append(_grid_table(
            ["Signal", "Points", "Evidence"],
            [[s.get("label"), s.get("points"), s.get("evidence")] for s in triggered],
            widths=[52*mm, 16*mm, None]))

    # ---- 3. sender identity ------------------------------------------------
    story.append(Paragraph("3. Sender identity", h2))
    fr = sender.get("from") or {}
    rt = sender.get("reply_to") or {}
    rp = sender.get("return_path") or {}
    story.append(_kv_table([
        ("From", fr.get("display")),
        ("From domain", fr.get("domain")),
        ("Reply-To", rt.get("display") if rt else "not present"),
        ("Return-Path", rp.get("display") if rp else "not present"),
        ("Subject", sender.get("subject")),
        ("Message-ID", sender.get("message_id")),
        ("Message-ID domain", sender.get("message_id_domain")),
        ("Date", sender.get("date_raw") or sender.get("date")),
        ("X-Mailer", sender.get("x_mailer")),
        ("Headers present", sender.get("raw_header_count")),
        ("Headers missing", ", ".join(sender.get("missing_headers") or []) or "none"),
    ]))
    anomalies = sender.get("anomalies") or []
    if anomalies:
        story.append(Spacer(1, 5))
        story.append(_grid_table(
            ["Anomaly", "Severity", "Detail"],
            [[a.get("code"), a.get("severity"), a.get("detail")] for a in anomalies],
            widths=[58*mm, 20*mm, None]))

    # ---- 4. authentication -------------------------------------------------
    story.append(Paragraph("4. Authentication results", h2))
    if auth.get("self_asserted_only"):
        warn = Table([[_p(auth.get("self_asserted_warning"), body)]],
                     colWidths=[None], hAlign="LEFT")
        warn.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff4e5")),
            ("BOX", (0, 0), (-1, -1), 0.75, colors.HexColor(BAND_COLOURS["high"])),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(warn)
        story.append(Spacer(1, 5))
    story.append(_p(f"Results as recorded by: {_fmt(auth.get('verified_by'), 'no trusted receiver')}",
                    small))
    story.append(Spacer(1, 3))
    story.append(_grid_table(
        ["Mechanism", "Result", "Domain", "Detail"],
        [[m.get("name"), m.get("result"), m.get("domain"),
          m.get("selector") or m.get("policy") or m.get("raw")]
         for m in (auth.get("mechanisms") or [])],
        widths=[24*mm, 22*mm, 42*mm, None]))
    align = auth.get("alignment") or {}
    if align:
        story.append(Spacer(1, 4))
        story.append(_kv_table([
            ("SPF aligned with From", align.get("spf_aligned")),
            ("DKIM aligned with From", align.get("dkim_aligned")),
            ("From matches Return-Path", align.get("from_vs_returnpath_match")),
            ("Envelope-From domain", align.get("envelope_from_domain")),
        ]))

    # ---- 5. routing --------------------------------------------------------
    story.append(Paragraph("5. Delivery routing chain", h2))
    story.append(_p(routing.get("note"), small))
    story.append(Spacer(1, 3))
    hops = routing.get("hops") or []
    if hops:
        story.append(_grid_table(
            ["Hop", "Timestamp (UTC)", "From host", "From IP", "Received by", "TLS"],
            [[h.get("hop"), h.get("timestamp"), h.get("from_host"),
              (f"{h.get('from_ip')} (private)" if h.get("is_private_ip")
               else h.get("from_ip")),
              h.get("by_host"), h.get("tls")] for h in hops],
            widths=[11*mm, 33*mm, 38*mm, 33*mm, None, 12*mm],
            highlight_rows=[i for i, h in enumerate(hops) if h.get("is_private_ip")]))
    else:
        story.append(_p("No Received headers were recoverable from this message.", body))
    ri = routing.get("integrity") or {}
    story.append(Spacer(1, 4))
    story.append(_kv_table([
        ("Hops recorded", routing.get("hop_count")),
        ("Timestamps in order", ri.get("timestamps_monotonic")),
        ("Backward time jumps", ri.get("backward_time_jumps")),
        ("Largest gap (seconds)", ri.get("largest_gap_seconds")),
        ("Gaps suspected", ri.get("gaps_suspected")),
        ("Malformed hops", ri.get("malformed_hops")),
    ]))
    for note in (ri.get("notes") or []):
        story.append(Paragraph(escape(_fmt(note)), bullet, bulletText="·"))

    # ---- 6. origin analysis ------------------------------------------------
    story.append(Paragraph("6. Origin analysis", h2))
    geo = origin.get("geo") or {}
    story.append(_kv_table([
        ("Selected IP", origin.get("selected_ip")),
        ("Selected from hop", origin.get("selected_from_hop")),
        ("Location", origin.get("location")),
        ("Coordinates", (f"{geo.get('lat')}, {geo.get('lon')}"
                         if geo.get("lat") is not None and geo.get("lon") is not None
                         else None)),
        ("ISP", geo.get("isp")),
        ("Organisation", geo.get("org")),
        ("ASN", geo.get("asn")),
        ("Infrastructure type", origin.get("infrastructure_type")),
        ("Datacenter / proxy / mobile",
         f"{_fmt(geo.get('is_datacenter'))} / {_fmt(geo.get('is_proxy'))} / "
         f"{_fmt(geo.get('is_mobile'))}"),
        ("Geolocation source", geo.get("lookup_source")),
        ("Confidence", str(origin.get("confidence") or "low").upper()),
    ]))

    # EVERY reason, never truncated - they are why the confidence is credible
    story.append(Spacer(1, 4))
    story.append(_p("Basis for the confidence assessment:", small))
    for reason in (origin.get("confidence_reasons") or ["No basis recorded."]):
        story.append(Paragraph(escape(_fmt(reason)), bullet, bulletText="·"))

    candidates = origin.get("candidates") or []
    if candidates:
        story.append(Spacer(1, 6))
        story.append(_p("Candidate origin addresses, ranked by how much the "
                        "recording server can be trusted. Excluded candidates "
                        "are retained for completeness.", small))
        story.append(Spacer(1, 3))
        story.append(_grid_table(
            ["#", "IP", "Hop", "Trust tier", "Score", "Recorded by", "Assessment"],
            [[c.get("rank"), c.get("ip"), c.get("hop"), c.get("trust_tier"),
              c.get("trust_score"), c.get("observed_by"),
              c.get("exclusion_reason") if c.get("excluded")
              else "; ".join(c.get("reasons") or [])] for c in candidates],
            widths=[8*mm, 30*mm, 11*mm, 27*mm, 13*mm, 34*mm, None],
            highlight_rows=[i for i, c in enumerate(candidates) if c.get("excluded")]))

    # ---- 7. limitations ----------------------------------------------------
    # Never trimmed to make the document fit. A report that states what it
    # cannot prove is a report someone can act on.
    # CondPageBreak, not PageBreak: start a fresh page only if there is not
    # enough room left to keep the limitations together, rather than always
    # burning half a page.
    story.append(CondPageBreak(75*mm))
    story.append(Paragraph("7. Limitations of this analysis", h2))
    for i, item in enumerate(limitations, start=1):
        story.append(Paragraph(escape(_fmt(item)), bullet, bulletText=f"{i}."))
        story.append(Spacer(1, 2))

    # ---- 8. integrity ------------------------------------------------------
    story.append(Paragraph("8. Evidence integrity", h2))
    story.append(KeepTogether([
        _kv_table([
            ("Hash algorithm", integrity.get("hash_algorithm")),
            ("Canonicalisation", integrity.get("canonicalisation")),
            ("Fields excluded from hash",
             ", ".join(integrity.get("excluded_fields") or [])),
            ("Custody log entry", integrity.get("custody_log_entry")),
            ("Previous entry hash", integrity.get("previous_entry_hash")),
        ]),
        Spacer(1, 4),
        _p("Evidence SHA-256", small),
        _p(integrity.get("evidence_sha256"), mono),
        Spacer(1, 4),
        _p(integrity.get("statement"), body),
    ]))

    # ---- page furniture ----------------------------------------------------
    digest = str(integrity.get("evidence_sha256") or "")
    entry_no = integrity.get("custody_log_entry")
    report_id = str(header.get("report_id") or "")

    def _furniture(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor(RULE))
        canvas.setLineWidth(0.25)
        canvas.line(18*mm, 14*mm, A4[0] - 18*mm, 14*mm)
        canvas.setFont("Courier", 6.5)
        canvas.setFillColor(colors.HexColor(MUTED))
        canvas.drawString(18*mm, 10*mm, f"SHA-256 {digest}")
        canvas.drawString(18*mm, 7*mm, (
            f"{report_id} · custody entry "
            f"{entry_no if entry_no else 'not logged'} · {TOOL_NAME} v{TOOL_VERSION}"))
        canvas.setFont("Helvetica", 7)
        canvas.drawRightString(A4[0] - 18*mm, 10*mm, f"page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(out_path), pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm, topMargin=16*mm, bottomMargin=20*mm,
        title=f"{PAGE_TITLE} {report_id}".strip(),
        author=f"{TOOL_NAME} v{TOOL_VERSION}",
        subject="Email header forensic analysis with confidence-scored geolocation",
    )
    doc.build(story, onFirstPage=_furniture, onLaterPages=_furniture)
    return str(out_path)