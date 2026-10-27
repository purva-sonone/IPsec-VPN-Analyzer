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

# Rule Audit status colors:
# PASS = green, FAIL = red/orange, REVIEW = amber, NOT OBSERVED / SKIPPED = neutral grey
AUDIT_STATUS_COLOR = {
    "RULE PASSED":       GREEN,
    "PASS":              GREEN,
    "WEAKNESS DETECTED": RED,
    "FAIL":              RED,
    "HIGH":              RED,
    "REVIEW":            AMBER,
    "NOT OBSERVED":      SLATE500,
    "SKIPPED":           SLATE500,
}


def _audit_status_color(status: str) -> colors.HexColor:
    """Return the designated color for a Rule Audit status value."""
    s = str(status).strip().upper()
    return AUDIT_STATUS_COLOR.get(s, SLATE500)



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


def _resolve_model_metadata(ml: dict) -> dict:
    """
    Resolve model version, architecture display, and validation scope from the prediction result.

    Adheres to strict validation principles:
      - Explicit model_version ('v1' or 'v2') is the sole authoritative source.
        Conflicting dataset_note text never overrides an explicit model_version.
      - V1: 17 features, 98.74% held-out VNAT test-set accuracy.
      - V2: 11 verified features, 98.76% held-out VNAT test-set accuracy.
      - Figures are clearly labeled as held-out VNAT test-set accuracy, NOT real-world PCAP accuracy.
      - If model_version is missing or unknown, exact verified legacy signatures are checked.
        Arbitrary or unverified text safely falls back to unknown and is NEVER labeled as V2.
    """
    raw_version = str(ml.get("model_version") or "").strip().lower()
    dataset_note = str(ml.get("dataset_note") or "").strip()

    # 1. Authoritative explicit version check
    if raw_version == "v2":
        return {
            "version": "v2",
            "version_display": "V2 (11 verified features)",
            "model_name": "RandomForestClassifier (500 trees, V2)",
            "accuracy_display": "98.76% (held-out VNAT test-set accuracy; not real-world PCAP accuracy)",
            "dataset": "VNAT Feature Dataframe (MIT Lincoln Laboratory)",
        }
    elif raw_version == "v1":
        return {
            "version": "v1",
            "version_display": "V1 (17 features)",
            "model_name": "RandomForestClassifier (500 trees, V1)",
            "accuracy_display": "98.74% (held-out VNAT test-set accuracy; not real-world PCAP accuracy)",
            "dataset": "VNAT Feature Dataframe (MIT Lincoln Laboratory)",
        }

    # 2. Legacy fallback for historical database records lacking model_version field.
    # Only exact verified legacy signatures from database inspection are recognized.
    _VERIFIED_LEGACY_V1_500 = "Model: RandomForestClassifier (500 trees), trained on VNAT Feature Dataframe (15,093 samples), test accuracy 98.74%."
    _VERIFIED_LEGACY_V1_200 = "Model: RandomForestClassifier (200 trees), trained on VNAT Feature Dataframe (15,093 samples), test accuracy 98.48%."

    if not raw_version and dataset_note == _VERIFIED_LEGACY_V1_500:
        return {
            "version": "v1",
            "version_display": "V1 (17 features, legacy record)",
            "model_name": "RandomForestClassifier (500 trees, legacy V1)",
            "accuracy_display": "98.74% (held-out VNAT test-set accuracy; not real-world PCAP accuracy)",
            "dataset": "VNAT Feature Dataframe (MIT Lincoln Laboratory)",
        }
    elif not raw_version and dataset_note == _VERIFIED_LEGACY_V1_200:
        return {
            "version": "v1",
            "version_display": "V1 (17 features, legacy record)",
            "model_name": "RandomForestClassifier (200 trees, legacy V1)",
            "accuracy_display": "98.48% (held-out VNAT test-set accuracy; not real-world PCAP accuracy)",
            "dataset": "VNAT Feature Dataframe (MIT Lincoln Laboratory)",
        }

    # 3. Safe fallback for missing, unknown, or unverified metadata (never guess V2)
    return {
        "version": "unknown",
        "version_display": "Unknown / Unspecified Version",
        "model_name": "RandomForestClassifier (unspecified)",
        "accuracy_display": "Held-out VNAT test-set accuracy unavailable (model version unspecified)",
        "dataset": "VNAT Feature Dataframe (MIT Lincoln Laboratory)",
    }


def _build_rule_audit_table(rules_evaluated: list, rules_skipped: list):
    """
    Build the Rule Audit Table with standard status color coding:
      - PASS -> green
      - FAIL -> red
      - REVIEW -> amber
      - NOT OBSERVED / SKIPPED -> neutral grey (SLATE500)
    """
    audit_data = [["Rule", "Observed Value", "Status"]]
    for r in rules_evaluated:
        raw_st = (r.get("status") or "UNKNOWN").strip().upper()
        if raw_st == "PASS":
            disp_st = "RULE PASSED"
        elif raw_st == "FAIL":
            disp_st = "WEAKNESS DETECTED"
        elif raw_st == "NOT OBSERVED":
            disp_st = "NOT OBSERVED"
        elif raw_st == "REVIEW":
            disp_st = "REVIEW"
        else:
            disp_st = r.get("status") or "UNKNOWN"
        audit_data.append([r.get("rule", ""), r.get("observed_value", "—"), disp_st])

    for r in rules_skipped:
        audit_data.append([r.get("rule", ""), "Not Extracted", "SKIPPED"])

    if len(audit_data) <= 1:
        return None

    t = Table(audit_data, colWidths=[6.5*cm, 5.5*cm, 5.0*cm], repeatRows=1)
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
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]

    # Color status column: PASS=green, FAIL=red, REVIEW=amber, NOT OBSERVED/SKIPPED=neutral grey
    for ri in range(1, len(audit_data)):
        st = audit_data[ri][2]
        c = _audit_status_color(st)
        sty.append(("TEXTCOLOR",  (2, ri), (2, ri), c))
        sty.append(("FONTNAME",   (2, ri), (2, ri), "Helvetica-Bold"))

    table_style = TableStyle(sty)
    t.setStyle(table_style)
    t._table_style = table_style
    return t


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
        t = Table(f_data, colWidths=[2.3*cm, 4.7*cm, 5.0*cm, 5.0*cm], repeatRows=1)
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
    audit_table = _build_rule_audit_table(
        sa.get("rules_evaluated", []),
        sa.get("rules_skipped", []),
    )
    if audit_table is not None:
        story.append(audit_table)
    story.append(Spacer(1, 0.3*cm))

    # ── ML Traffic Classification ─────────────────────────────────────────────
    story.append(Paragraph("ML Traffic Classification", S["h2"]))
    ml_status = ml.get("model_status", "unknown")
    if ml_status == "not_applicable":
        story.append(Paragraph("Not Applicable — " + ml.get("model_note",""), S["body"]))
    elif ml_status == "trained_model":
        conf = ml.get("confidence_score")
        conf_str = f"{conf*100:.1f}%" if conf is not None else "N/A"
        meta = _resolve_model_metadata(ml)
        ml_data = [
            ["Field",                   "Value"],
            ["Predicted Category",      ml.get("predicted_category", "—")],
            ["Confidence",              conf_str],
            ["Model Version",           meta["version_display"]],
            ["Model",                   meta["model_name"]],
            ["Training Dataset",        meta["dataset"]],
            ["Held-Out Test Accuracy",  Paragraph(meta["accuracy_display"], S["body"])],
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

    # ── Behavioral Timing & Beaconing Analysis ────────────────────────────────
    ba = m.get("beaconing_analysis")
    if ba and ba.get("status") == "evaluated":
        story.append(Paragraph("Behavioral Timing & Beaconing Analysis", S["h2"]))
        b_interval = f"{ba.get('estimated_interval_sec')}s" if ba.get('estimated_interval_sec') else "N/A"
        b_jitter = f"±{ba.get('jitter_sec')}s" if ba.get('jitter_sec') else "N/A"
        b_data = [
            ["Metric", "Observed Value"],
            ["Beaconing Anomaly Score", f"{ba.get('anomaly_score', 0)}/100 ({ba.get('anomaly_level', 'LOW')})"],
            ["Timing Regularity", f"{ba.get('timing_regularity_pct', 0)}%"],
            ["Estimated Periodicity", f"{b_interval} (Jitter: {b_jitter})"],
            ["Forensic Verdict", Paragraph(ba.get("verdict", "—"), S["body"])],
        ]
        story.append(_table(b_data, [6*cm, 11*cm]))
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
