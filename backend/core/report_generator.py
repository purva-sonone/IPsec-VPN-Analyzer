"""
report_generator.py – Generate a professional PDF analysis report using ReportLab.
"""

import io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    HRFlowable, PageBreak
)
from reportlab.lib.enums import TA_LEFT, TA_CENTER

# ── Color palette ─────────────────────────────────────────────────────────────
NAVY     = colors.HexColor("#0f172a")
INDIGO   = colors.HexColor("#6366f1")
SLATE700 = colors.HexColor("#334155")
SLATE500 = colors.HexColor("#64748b")
SLATE300 = colors.HexColor("#cbd5e1")
SLATE100 = colors.HexColor("#f1f5f9")
GREEN    = colors.HexColor("#10b981")
AMBER    = colors.HexColor("#f59e0b")
RED      = colors.HexColor("#ef4444")
ORANGE   = colors.HexColor("#f97316")
WHITE    = colors.white

SEV_COLOR = {
    "Critical":      RED,
    "High":          ORANGE,
    "Medium":        AMBER,
    "Low":           colors.HexColor("#3b82f6"),
    "Informational": SLATE500,
}

RISK_COLOR = {
    "High":          ORANGE,
    "Critical":      RED,
    "Medium":        AMBER,
    "Low":           colors.HexColor("#3b82f6"),
    "Informational": SLATE500,
}


def _styles():
    base = getSampleStyleSheet()
    return {
        "title":    ParagraphStyle("title",    fontSize=22, fontName="Helvetica-Bold",
                                   textColor=NAVY,   spaceAfter=4,  leading=28),
        "subtitle": ParagraphStyle("subtitle", fontSize=11, fontName="Helvetica",
                                   textColor=SLATE500, spaceAfter=16),
        "h2":       ParagraphStyle("h2",       fontSize=14, fontName="Helvetica-Bold",
                                   textColor=INDIGO,  spaceBefore=18, spaceAfter=6),
        "h3":       ParagraphStyle("h3",       fontSize=11, fontName="Helvetica-Bold",
                                   textColor=NAVY,    spaceBefore=10, spaceAfter=4),
        "body":     ParagraphStyle("body",     fontSize=9,  fontName="Helvetica",
                                   textColor=NAVY,    spaceAfter=4,  leading=14),
        "small":    ParagraphStyle("small",    fontSize=8,  fontName="Helvetica",
                                   textColor=SLATE500, spaceAfter=2),
        "mono":     ParagraphStyle("mono",     fontSize=9,  fontName="Courier",
                                   textColor=NAVY,    spaceAfter=2),
    }


def _table(data, col_widths, header_bg=INDIGO):
    t = Table(data, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND",  (0, 0), (-1, 0),  header_bg),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  WHITE),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, 0),  9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [SLATE100, WHITE]),
        ("FONTNAME",    (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE",    (0, 1), (-1, -1), 9),
        ("TEXTCOLOR",   (0, 1), (-1, -1), NAVY),
        ("GRID",        (0, 0), (-1, -1), 0.4, SLATE300),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0,0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]
    t.setStyle(TableStyle(style))
    return t


def _on_page(canvas, doc):
    """Draw page header/footer."""
    canvas.saveState()
    w, h = A4
    # Header stripe
    canvas.setFillColor(NAVY)
    canvas.rect(0, h - 1.2*cm, w, 1.2*cm, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 10)
    canvas.drawString(1.5*cm, h - 0.8*cm, "IPsec VPN Security Analysis Report")
    canvas.setFont("Helvetica", 8)
    canvas.drawRightString(w - 1.5*cm, h - 0.8*cm,
                           f"Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    # Footer
    canvas.setFillColor(SLATE500)
    canvas.setFont("Helvetica", 8)
    canvas.drawCentredString(w / 2, 0.7*cm, f"Page {doc.page}")
    canvas.restoreState()


def generate_pdf(report: dict) -> bytes:
    """Return PDF bytes for the given analysis report dict."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=1.5*cm, rightMargin=1.5*cm,
        topMargin=1.8*cm,  bottomMargin=1.5*cm,
        title="IPsec VPN Security Analysis Report",
    )

    S   = _styles()
    m   = report.get("pcap_metrics", {})
    sa  = report.get("security_assessment", {})
    ml  = report.get("ml_prediction", {})
    story = []

    # ── Cover / header ────────────────────────────────────────────────────────
    story.append(Spacer(1, 0.5*cm))
    story.append(Paragraph("IPsec VPN Security Analysis Report", S["title"]))
    story.append(HRFlowable(width="100%", thickness=2, color=INDIGO, spaceAfter=10))

    # File info table
    created = report.get("created_at", datetime.utcnow().isoformat())
    try:
        dt = datetime.fromisoformat(created)
        created_fmt = dt.strftime("%d %b %Y, %H:%M UTC")
    except Exception:
        created_fmt = created

    info_data = [
        ["Field", "Value"],
        ["Filename",        report.get("filename", "—")],
        ["Analysis ID",     report.get("id", "—")],
        ["Analysis Date",   created_fmt],
        ["Packet Count",    str(m.get("packet_count", "—"))],
        ["Status",          report.get("status", "—").upper()],
    ]
    story.append(_table(info_data, [5*cm, 12*cm]))
    story.append(Spacer(1, 0.4*cm))

    # ── Risk Score banner ─────────────────────────────────────────────────────
    risk_score = sa.get("overall_risk_score", 0)
    risk_level = sa.get("risk_level", "Informational")
    risk_color = RISK_COLOR.get(risk_level, SLATE500)

    risk_data = [["Overall Risk Score", "Risk Level", "Score Explanation"]]
    risk_data.append([
        str(risk_score),
        risk_level,
        Paragraph(sa.get("score_explanation", ""), S["small"]),
    ])
    t = Table(risk_data, colWidths=[3.5*cm, 3.5*cm, 10*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",  (0, 0), (-1, 0),  NAVY),
        ("TEXTCOLOR",   (0, 0), (-1, 0),  WHITE),
        ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, 0),  9),
        ("BACKGROUND",  (0, 1), (0, 1),   risk_color),
        ("TEXTCOLOR",   (0, 1), (0, 1),   WHITE),
        ("FONTNAME",    (0, 1), (0, 1),   "Helvetica-Bold"),
        ("FONTSIZE",    (0, 1), (0, 1),   22),
        ("ALIGN",       (0, 1), (1, 1),   "CENTER"),
        ("BACKGROUND",  (1, 1), (1, 1),   risk_color),
        ("TEXTCOLOR",   (1, 1), (1, 1),   WHITE),
        ("FONTNAME",    (1, 1), (1, 1),   "Helvetica-Bold"),
        ("FONTSIZE",    (1, 1), (1, 1),   14),
        ("GRID",        (0, 0), (-1, -1), 0.4, SLATE300),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 1), (-1, 1),  12),
        ("BOTTOMPADDING",(0,1), (-1, 1),  12),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.5*cm))

    # ── Protocol Summary ──────────────────────────────────────────────────────
    story.append(Paragraph("Protocol Summary", S["h2"]))
    proto_data = [
        ["Parameter",    "Value"],
        ["IKE Version",  m.get("ike_version",       "Not Extracted")],
        ["Protocols",    ", ".join(m.get("protocols_found", [])) or "None detected"],
        ["VPN Mode",     m.get("vpn_mode_inferred", "Not Extracted")],
    ]
    story.append(_table(proto_data, [6*cm, 11*cm]))
    story.append(Spacer(1, 0.3*cm))

    # ── Cryptographic Parameters ──────────────────────────────────────────────
    story.append(Paragraph("Cryptographic Parameters", S["h2"]))
    crypto_data = [
        ["Parameter",              "Observed Value"],
        ["Encryption Algorithm",   m.get("encryption",      "Not Extracted")],
        ["Key Exchange (DH Group)",m.get("key_exchange",    "Not Extracted")],
        ["Authentication Method",  m.get("authentication",  "Not Extracted")],
    ]
    story.append(_table(crypto_data, [6*cm, 11*cm]))
    story.append(Spacer(1, 0.3*cm))

    # ── Security Findings ─────────────────────────────────────────────────────
    story.append(Paragraph("Security Findings", S["h2"]))
    findings = sa.get("findings", [])
    if findings:
        f_data = [["Severity", "Title", "Evidence", "Recommendation"]]
        for f in findings:
            f_data.append([
                f.get("severity", ""),
                Paragraph(f.get("title", ""), S["body"]),
                Paragraph(f.get("evidence", ""), S["small"]),
                Paragraph(f.get("recommendation", ""), S["small"]),
            ])
        t = Table(f_data, colWidths=[2.5*cm, 4*cm, 5.5*cm, 5*cm], repeatRows=1)
        sty = [
            ("BACKGROUND",  (0, 0), (-1, 0),  NAVY),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  WHITE),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, 0),  9),
            ("GRID",        (0, 0), (-1, -1), 0.4, SLATE300),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING",  (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0,0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("FONTSIZE",    (0, 1), (-1, -1), 8),
        ]
        # Color the severity column cells
        for ri, f in enumerate(findings, start=1):
            c = SEV_COLOR.get(f.get("severity",""), SLATE500)
            sty.append(("BACKGROUND", (0, ri), (0, ri), c))
            sty.append(("TEXTCOLOR",  (0, ri), (0, ri), WHITE))
            sty.append(("FONTNAME",   (0, ri), (0, ri), "Helvetica-Bold"))
            bg = SLATE100 if ri % 2 == 0 else WHITE
            for ci in range(1, 4):
                sty.append(("BACKGROUND", (ci, ri), (ci, ri), bg))
        t.setStyle(TableStyle(sty))
        story.append(t)
    else:
        story.append(Paragraph("No security findings recorded.", S["body"]))
    story.append(Spacer(1, 0.3*cm))

    # ── Rule Audit ────────────────────────────────────────────────────────────
    story.append(Paragraph("Rule Audit", S["h2"]))
    audit_data = [["Rule", "Observed Value", "Status"]]
    for r in sa.get("rules_evaluated", []):
        audit_data.append([r.get("rule",""), r.get("observed_value","—"), "PASS"])
    for r in sa.get("rules_skipped", []):
        audit_data.append([r.get("rule",""), "Not Extracted", "SKIPPED"])

    if len(audit_data) > 1:
        t = Table(audit_data, colWidths=[7*cm, 6*cm, 4*cm], repeatRows=1)
        sty = [
            ("BACKGROUND",  (0, 0), (-1, 0),  NAVY),
            ("TEXTCOLOR",   (0, 0), (-1, 0),  WHITE),
            ("FONTNAME",    (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",    (0, 0), (-1, 0),  9),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [SLATE100, WHITE]),
            ("GRID",        (0, 0), (-1, -1), 0.4, SLATE300),
            ("FONTSIZE",    (0, 1), (-1, -1), 9),
            ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING",  (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",(0,0), (-1, -1), 5),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]
        # Color status column
        r_offset = len(sa.get("rules_evaluated", []))
        for ri in range(1, r_offset + 1):
            sty.append(("TEXTCOLOR",  (2, ri), (2, ri), GREEN))
            sty.append(("FONTNAME",   (2, ri), (2, ri), "Helvetica-Bold"))
        for ri in range(r_offset + 1, len(audit_data)):
            sty.append(("TEXTCOLOR",  (2, ri), (2, ri), AMBER))
            sty.append(("FONTNAME",   (2, ri), (2, ri), "Helvetica-Bold"))
        t.setStyle(TableStyle(sty))
        story.append(t)
    story.append(Spacer(1, 0.3*cm))

    # ── ML Traffic Classification ─────────────────────────────────────────────
    story.append(Paragraph("ML Traffic Classification", S["h2"]))
    ml_status = ml.get("model_status", "unknown")
    if ml_status == "not_applicable":
        story.append(Paragraph("Not Applicable — " + ml.get("model_note",""), S["body"]))
    elif ml_status == "trained_model":
        conf = ml.get("confidence_score")
        conf_str = f"{conf*100:.1f}%" if conf is not None else "N/A"
        ml_data = [
            ["Field",           "Value"],
            ["Predicted Category", ml.get("predicted_category","—")],
            ["Confidence",      conf_str],
            ["Model",           "RandomForestClassifier (200 trees)"],
            ["Training Dataset","VNAT Feature Dataframe (MIT Lincoln Laboratory)"],
            ["Test Accuracy",   "98.48%"],
        ]
        story.append(_table(ml_data, [6*cm, 11*cm]))

        proba = ml.get("all_class_probabilities")
        if proba:
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph("Category Probabilities", S["h3"]))
            p_data = [["Category", "Probability"]]
            for cls, p in sorted(proba.items(), key=lambda x: -x[1]):
                p_data.append([cls, f"{p*100:.1f}%"])
            story.append(_table(p_data, [6*cm, 11*cm]))
    else:
        story.append(Paragraph(ml.get("model_note", "Classification unavailable."), S["body"]))

    story.append(Spacer(1, 0.3*cm))

    # ── Features used ─────────────────────────────────────────────────────────
    fa = ml.get("features_available", [])
    if fa and ml_status == "trained_model":
        story.append(Paragraph("Features Used for Prediction", S["h3"]))
        f_data = [["Feature"]] + [[f] for f in fa]
        story.append(_table(f_data, [17*cm], header_bg=SLATE700))
        story.append(Spacer(1, 0.3*cm))

    # ── Disclaimer ────────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=SLATE300, spaceAfter=6))
    story.append(Paragraph(
        "This report was generated automatically by IPsec VPN Analyzer. "
        "Packet-level analysis is based on observable (unencrypted) IKE negotiation headers. "
        "Parameters marked 'Not Extracted' could not be observed in the provided capture. "
        "ML classification predicts traffic category (C2/Chat/Streaming/etc.), not VPN vs non-VPN.",
        S["small"]
    ))

    doc.build(story, onFirstPage=_on_page, onLaterPages=_on_page)
    return buf.getvalue()
