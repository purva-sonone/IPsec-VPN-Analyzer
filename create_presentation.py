"""
create_presentation.py
Generates a modern, enterprise-grade PowerPoint presentation (16:9 widescreen)
for the 'AI-Powered IPsec VPN Analyzer' project.
"""

import os
import pptx
from pptx.util import Inches, Pt
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE
from pptx.dml.color import RGBColor

# ── Color Palette Definitions ────────────────────────────────────────────────
COLOR_BG_DARK        = RGBColor(11, 17, 32)     # #0B1120 Deep Midnight Navy
COLOR_BG_LIGHT       = RGBColor(248, 250, 252)  # #F8FAFC Crisp Light Slate
COLOR_SURFACE_WHITE  = RGBColor(255, 255, 255)  # #FFFFFF Card Surface
COLOR_CARD_BORDER    = RGBColor(226, 232, 240)  # #E2E8F0 Subtle Border

COLOR_PRIMARY_NAVY   = RGBColor(15, 23, 42)     # #0F172A Dark Slate Header
COLOR_TEXT_MUTED     = RGBColor(100, 116, 139)  # #64748B Secondary Text
COLOR_TEXT_BODY      = RGBColor(51, 65, 85)     # #334155 Body Text

COLOR_ACCENT_BLUE    = RGBColor(37, 99, 235)    # #2563EB Electric Blue
COLOR_ACCENT_CYAN    = RGBColor(6, 182, 212)    # #06B6D4 Vibrant Cyan
COLOR_ACCENT_GREEN   = RGBColor(16, 185, 129)   # #10B981 Emerald
COLOR_ACCENT_AMBER   = RGBColor(245, 158, 11)   # #F59E0B Amber / Warning
COLOR_ACCENT_RED     = RGBColor(239, 68, 68)    # #EF4444 Crimson
COLOR_ACCENT_PURPLE  = RGBColor(124, 58, 237)   # #7C3AED Purple

FONT_HEADING = "Segoe UI"
FONT_BODY    = "Segoe UI"

def set_bg(slide, rgb_color):
    """Set slide background color with a full-bleed rectangle."""
    bg = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(7.5))
    bg.fill.solid()
    bg.fill.fore_color.rgb = rgb_color
    bg.line.fill.background()
    return bg

def add_header(slide, category, title, dark_mode=False):
    """Adds a standard structured header with category pill and main title."""
    # Category Pill
    pill = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.45), Inches(2.8), Inches(0.35))
    pill.fill.solid()
    pill.fill.fore_color.rgb = RGBColor(30, 41, 59) if dark_mode else RGBColor(239, 246, 255)
    pill.line.fill.background()
    tf_pill = pill.text_frame
    tf_pill.word_wrap = False
    tf_pill.vertical_anchor = MSO_ANCHOR.MIDDLE
    p_pill = tf_pill.paragraphs[0]
    p_pill.text = category.upper()
    p_pill.alignment = PP_ALIGN.CENTER
    p_pill.font.name = FONT_HEADING
    p_pill.font.size = Pt(9.5)
    p_pill.font.bold = True
    p_pill.font.color.rgb = COLOR_ACCENT_CYAN if dark_mode else COLOR_ACCENT_BLUE

    # Main Title
    tb = slide.shapes.add_textbox(Inches(0.8), Inches(0.85), Inches(11.7), Inches(0.75))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.text = title
    p.font.name = FONT_HEADING
    p.font.size = Pt(22)
    p.font.bold = True
    p.font.color.rgb = RGBColor(255, 255, 255) if dark_mode else COLOR_PRIMARY_NAVY

def create_card(slide, left, top, width, height, bg_color=COLOR_SURFACE_WHITE, border_color=COLOR_CARD_BORDER):
    """Creates a modern rounded card container."""
    card = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, top, width, height)
    card.fill.solid()
    card.fill.fore_color.rgb = bg_color
    if border_color:
        card.line.color.rgb = border_color
        card.line.width = Pt(1)
    else:
        card.line.fill.background()
    return card

def add_bullet_point(text_frame, bold_prefix, text, pt_size=11, color=COLOR_TEXT_BODY, space_after=6):
    """Helper to add clean bullet paragraph with bold prefix."""
    p = text_frame.add_paragraph() if len(text_frame.paragraphs[0].text.strip()) > 0 else text_frame.paragraphs[0]
    p.space_after = Pt(space_after)
    p.font.name = FONT_BODY
    p.font.size = Pt(pt_size)
    
    r1 = p.add_run()
    r1.text = bold_prefix + " " if bold_prefix else ""
    r1.font.bold = True
    r1.font.color.rgb = COLOR_PRIMARY_NAVY if color == COLOR_TEXT_BODY else color
    
    r2 = p.add_run()
    r2.text = text
    r2.font.bold = False
    r2.font.color.rgb = color


def build_deck():
    prs = pptx.Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank = prs.slide_layouts[6]

    # =========================================================================
    # SLIDE 1: Title Slide (Dark Mode)
    # =========================================================================
    s1 = prs.slides.add_slide(blank)
    set_bg(s1, COLOR_BG_DARK)

    # Accent glow top bar
    bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(0.1))
    bar.fill.solid()
    bar.fill.fore_color.rgb = COLOR_ACCENT_CYAN
    bar.line.fill.background()

    # Category Badge
    pill = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.2), Inches(1.6), Inches(3.6), Inches(0.42))
    pill.fill.solid()
    pill.fill.fore_color.rgb = RGBColor(30, 41, 59)
    pill.line.color.rgb = RGBColor(56, 189, 248)
    pill.line.width = Pt(1)
    tf = pill.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.text = "NETWORK SECURITY & AI FORENSICS"
    p.alignment = PP_ALIGN.CENTER
    p.font.name = FONT_HEADING
    p.font.size = Pt(10)
    p.font.bold = True
    p.font.color.rgb = RGBColor(56, 189, 248)

    # Main Project Title
    tb_title = s1.shapes.add_textbox(Inches(1.2), Inches(2.2), Inches(10.8), Inches(1.4))
    tf_t = tb_title.text_frame
    tf_t.word_wrap = True
    p_t = tf_t.paragraphs[0]
    p_t.text = "AI-Powered IPsec VPN Analyzer"
    p_t.font.name = FONT_HEADING
    p_t.font.size = Pt(40)
    p_t.font.bold = True
    p_t.font.color.rgb = RGBColor(255, 255, 255)

    # Subtitle
    tb_sub = s1.shapes.add_textbox(Inches(1.2), Inches(3.6), Inches(10.8), Inches(1.0))
    tf_sub = tb_sub.text_frame
    tf_sub.word_wrap = True
    p_sub = tf_sub.paragraphs[0]
    p_sub.text = "Automated Cryptographic Auditing, Rule-Based Compliance & Encrypted Traffic Behavioral Classification"
    p_sub.font.name = FONT_BODY
    p_sub.font.size = Pt(17)
    p_sub.font.color.rgb = RGBColor(148, 163, 184)

    # Feature Highlights Grid (3 cards)
    highlights = [
        ("NIST & RFC Audit Engine", "Deterministic evaluation of DH groups, ciphers, and hash functions with coverage trail.", COLOR_ACCENT_CYAN),
        ("ML Behavioral Classifier", "Random Forest model trained on VNAT dataset classifying encrypted traffic patterns.", COLOR_ACCENT_BLUE),
        ("Evidence-to-Report", "Interactive React UI, packet-level telemetry & automated ReportLab PDF reports.", COLOR_ACCENT_GREEN),
    ]
    for i, (head, desc, color) in enumerate(highlights):
        c_left = Inches(1.2 + i * 3.75)
        card = create_card(s1, c_left, Inches(4.9), Inches(3.5), Inches(1.7), bg_color=RGBColor(15, 23, 42), border_color=RGBColor(30, 41, 59))
        tb_c = s1.shapes.add_textbox(c_left + Inches(0.2), Inches(5.05), Inches(3.1), Inches(1.4))
        tf_c = tb_c.text_frame
        tf_c.word_wrap = True
        p_c1 = tf_c.paragraphs[0]
        p_c1.text = head
        p_c1.font.bold = True
        p_c1.font.size = Pt(13)
        p_c1.font.color.rgb = color
        p_c1.space_after = Pt(4)
        p_c2 = tf_c.add_paragraph()
        p_c2.text = desc
        p_c2.font.size = Pt(10.5)
        p_c2.font.color.rgb = RGBColor(203, 213, 225)

    # =========================================================================
    # SLIDE 2: Problem Statement & Motivation
    # =========================================================================
    s2 = prs.slides.add_slide(blank)
    set_bg(s2, COLOR_BG_LIGHT)
    add_header(s2, "Background & Motivation", "The Challenge of Auditing Encrypted IPsec VPN Traffic")

    problems = [
        ("Payload Opacity Blindspot", "Traditional firewalls & IDS are completely blind once ESP encryption activates. Security teams cannot inspect packet payloads to verify data authenticity or classify communication.", COLOR_ACCENT_RED, "ESP Payload Encryption"),
        ("Cryptographic Misconfigurations", "VPN tunnels frequently use deprecated legacy crypto (3DES, MD5, DH Groups 1/2) due to backward compatibility, leaving organizations vulnerable to eavesdropping and downgrade attacks.", COLOR_ACCENT_AMBER, "Silent Vulnerabilities"),
        ("Manual & Error-Prone Forensics", "Manually parsing multi-megabyte PCAP captures in Wireshark requires scarce crypto expertise, lacks automated NIST compliance scoring, and provides no statistical behavioral context.", COLOR_ACCENT_PURPLE, "Operational Bottleneck"),
    ]

    for i, (title, desc, color, tag) in enumerate(problems):
        c_left = Inches(0.8 + i * 3.95)
        create_card(s2, c_left, Inches(1.8), Inches(3.75), Inches(4.8))
        
        # Tag bar
        tag_box = s2.shapes.add_shape(MSO_SHAPE.RECTANGLE, c_left, Inches(1.8), Inches(3.75), Inches(0.1))
        tag_box.fill.solid()
        tag_box.fill.fore_color.rgb = color
        tag_box.line.fill.background()

        tb = s2.shapes.add_textbox(c_left + Inches(0.25), Inches(2.1), Inches(3.25), Inches(4.3))
        tf = tb.text_frame
        tf.word_wrap = True
        
        p_tag = tf.paragraphs[0]
        p_tag.text = tag.upper()
        p_tag.font.bold = True
        p_tag.font.size = Pt(9.5)
        p_tag.font.color.rgb = color
        p_tag.space_after = Pt(6)

        p_title = tf.add_paragraph()
        p_title.text = title
        p_title.font.bold = True
        p_title.font.size = Pt(15)
        p_title.font.color.rgb = COLOR_PRIMARY_NAVY
        p_title.space_after = Pt(12)

        p_desc = tf.add_paragraph()
        p_desc.text = desc
        p_desc.font.size = Pt(11.5)
        p_desc.font.color.rgb = COLOR_TEXT_BODY
        p_desc.line_spacing = 1.25

    # =========================================================================
    # SLIDE 3: Proposed Solution
    # =========================================================================
    s3 = prs.slides.add_slide(blank)
    set_bg(s3, COLOR_BG_LIGHT)
    add_header(s3, "Proposed Solution", "AI-Powered IPsec VPN Analyzer: Unified Evidence Platform")

    # Banner Card across top
    banner = create_card(s3, Inches(0.8), Inches(1.7), Inches(11.733), Inches(1.1), bg_color=RGBColor(15, 23, 42))
    tb_b = s3.shapes.add_textbox(Inches(1.05), Inches(1.8), Inches(11.2), Inches(0.9))
    tf_b = tb_b.text_frame
    tf_b.word_wrap = True
    p1 = tf_b.paragraphs[0]
    p1.text = "CORE MISSION & INNOVATION"
    p1.font.bold = True
    p1.font.size = Pt(10)
    p1.font.color.rgb = COLOR_ACCENT_CYAN
    p1.space_after = Pt(2)
    p2 = tf_b.add_paragraph()
    p2.text = "A centralized, dual-engine analysis platform that transforms raw, unintelligible IPsec packet captures into transparent, evidence-backed security insights and automated compliance audits."
    p2.font.size = Pt(13)
    p2.font.color.rgb = RGBColor(255, 255, 255)

    # 3 Solution Pillars
    pillars = [
        ("1. Deterministic Security Engine", "RFC 8221 / NIST SP 800-77", [
            ("Cryptographic Auditing:", "Validates IKEv1/IKEv2 SA proposals against modern NIST standards."),
            ("Coverage Summary:", "Tracks passed, failed, and skipped checks with explicit capture root causes."),
            ("Risk Score (0–100):", "Calculates evidence-based score weighted by vulnerability severity."),
        ]),
        ("2. Machine Learning Behavioral Engine", "VNAT Feature Classification", [
            ("Zero Decryption Needed:", "Extracts inter-arrival timing and packet-size distribution metrics."),
            ("Random Forest Model:", "Classifies encrypted flows into Chat, Streaming, VoIP, File Transfer, C2."),
            ("Interpretation Layer:", "Provides confidence thresholds, ambiguity spreads, and false-positive cautions."),
        ]),
        ("3. Enterprise Telemetry & Reporting", "Operational Readiness", [
            ("Interactive React Dashboard:", "Visualizes probability distributions and packet-size histograms via Recharts."),
            ("Dual Persistence:", "SQLite for local zero-config usage with MongoDB Atlas cloud sync."),
            ("Automated PDF Generator:", "Generates audit-ready executive reports via ReportLab with one click."),
        ]),
    ]

    for i, (title, subtitle, items) in enumerate(pillars):
        c_left = Inches(0.8 + i * 3.95)
        create_card(s3, c_left, Inches(3.05), Inches(3.75), Inches(3.85))
        tb = s3.shapes.add_textbox(c_left + Inches(0.2), Inches(3.2), Inches(3.35), Inches(3.55))
        tf = tb.text_frame
        tf.word_wrap = True

        p_t = tf.paragraphs[0]
        p_t.text = title
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = COLOR_PRIMARY_NAVY
        
        p_s = tf.add_paragraph()
        p_s.text = subtitle.upper()
        p_s.font.bold = True
        p_s.font.size = Pt(9)
        p_s.font.color.rgb = COLOR_ACCENT_BLUE
        p_s.space_after = Pt(8)

        for bold_text, normal_text in items:
            add_bullet_point(tf, "• " + bold_text, normal_text, pt_size=10.5, space_after=6)

    # =========================================================================
    # SLIDE 4: Architecture & Pipeline Diagram (Embeds Generated Image!)
    # =========================================================================
    s4 = prs.slides.add_slide(blank)
    set_bg(s4, COLOR_BG_LIGHT)
    add_header(s4, "System Architecture", "End-to-End Analysis Pipeline & Technical Workflow")

    # Embed the high-resolution generated pipeline image if available
    img_path = r"C:\Users\PURVA\.gemini\antigravity-ide\brain\50394f46-5af0-4e34-96dd-2798eb4f69a1\accurate_vpn_pipeline_1792080609766.jpg"
    if os.path.exists(img_path):
        s4.shapes.add_picture(img_path, Inches(0.8), Inches(1.65), Inches(11.733), Inches(5.35))
    else:
        # Fallback card
        create_card(s4, Inches(0.8), Inches(1.8), Inches(11.733), Inches(5.0))

    # =========================================================================
    # SLIDE 5: Technology Stack & Implementation
    # =========================================================================
    s5 = prs.slides.add_slide(blank)
    set_bg(s5, COLOR_BG_LIGHT)
    add_header(s5, "Technical Implementation", "Production-Ready Technology Stack & Architecture")

    tech_layers = [
        ("Frontend Application", "React 19 • Tailwind CSS • Recharts", [
            ("Modern SPA Architecture:", "Built with Vite, React Router, and responsive glassmorphic cards."),
            ("Data Visualizations:", "Interactive horizontal bar charts and histograms using Recharts 3.10."),
            ("Security Feedback:", "Color-coded risk badges, severity icons, and rule audit navigation."),
        ], COLOR_ACCENT_CYAN),
        ("Backend REST Services", "Python 3.13 • FastAPI • Uvicorn", [
            ("Asynchronous Endpoints:", "Fast non-blocking file upload, validation, and multi-threaded packet jobs."),
            ("Type-Safe Schemas:", "Pydantic models ensuring reliable input validation and structured API responses."),
            ("Cross-Platform Daemon:", "Automated TShark path discovery across Windows, Linux, and macOS."),
        ], COLOR_ACCENT_BLUE),
        ("Packet Forensics Engine", "TShark • PyShark Parser", [
            ("Dual-Protocol Decoding:", "Native extraction of IKEv1 (ISAKMP) and IKEv2 security associations."),
            ("Cryptographic Telemetry:", "Parses encryption transforms, hash algorithms, and DH key-exchange groups."),
            ("Flow Statistical Extraction:", "Computes packet length distributions, inter-arrival timing, and jitter."),
        ], COLOR_ACCENT_PURPLE),
        ("AI / ML & Storage Layer", "Scikit-Learn • SQLite • MongoDB Atlas", [
            ("Pre-Trained Classifier:", "Random Forest multi-class model trained on MIT Lincoln Lab VNAT dataset."),
            ("Dual Persistence:", "Local zero-configuration SQLite (ipsec_history.db) with MongoDB Atlas cloud sync."),
            ("Report Generation:", "ReportLab canvas engine generating multi-page executive PDF security briefs."),
        ], COLOR_ACCENT_GREEN),
    ]

    for i, (title, sub, items, color) in enumerate(tech_layers):
        r = i // 2
        c = i % 2
        c_left = Inches(0.8 + c * 5.95)
        c_top  = Inches(1.75 + r * 2.65)
        create_card(s5, c_left, c_top, Inches(5.75), Inches(2.45))
        
        # Color bar
        bar = s5.shapes.add_shape(MSO_SHAPE.RECTANGLE, c_left, c_top, Inches(0.12), Inches(2.45))
        bar.fill.solid()
        bar.fill.fore_color.rgb = color
        bar.line.fill.background()

        tb = s5.shapes.add_textbox(c_left + Inches(0.25), c_top + Inches(0.15), Inches(5.35), Inches(2.2))
        tf = tb.text_frame
        tf.word_wrap = True

        p_t = tf.paragraphs[0]
        p_t.text = title
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = COLOR_PRIMARY_NAVY

        p_s = tf.add_paragraph()
        p_s.text = sub
        p_s.font.bold = True
        p_s.font.size = Pt(9.5)
        p_s.font.color.rgb = color
        p_s.space_after = Pt(4)

        for bold_t, norm_t in items:
            add_bullet_point(tf, "• " + bold_t, norm_t, pt_size=10, space_after=3)

    # =========================================================================
    # SLIDE 6: Deterministic Security Rules Engine
    # =========================================================================
    s6 = prs.slides.add_slide(blank)
    set_bg(s6, COLOR_BG_LIGHT)
    add_header(s6, "Security Rules Engine", "Deterministic Cryptographic Verification & Risk Scoring")

    # Left: Rule Dimensions
    create_card(s6, Inches(0.8), Inches(1.75), Inches(6.8), Inches(5.1))
    tb_l = s6.shapes.add_textbox(Inches(1.05), Inches(1.9), Inches(6.3), Inches(4.8))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True

    p = tf_l.paragraphs[0]
    p.text = "RFC 8221 / NIST SP 800-77 Cryptographic Verification"
    p.font.bold = True
    p.font.size = Pt(14)
    p.font.color.rgb = COLOR_PRIMARY_NAVY
    p.space_after = Pt(8)

    rules_data = [
        ("Encryption Ciphers", "Flags broken ciphers (DES, 3DES, RC4) as High/Critical. Enforces AES-GCM (AEAD) or AES-CBC >= 128-bit."),
        ("Diffie-Hellman Groups", "Requires MODP >= 2048-bit (Group 14+) or ECP (Groups 19/20). Rejects legacy MODP-768/1024 (Groups 1 & 2)."),
        ("Integrity & Hash", "Detects obsolete MD5 & SHA1. Mandates SHA-256/384/512 or authenticated encryption."),
        ("Authentication Methods", "Verifies Pre-Shared Key (PSK) hygiene or digital certificate (RSA/ECDSA) exchange."),
        ("Analysis Coverage Summary", "Transparently reports Evaluated vs. Skipped rules with root-cause reasons (e.g. unobservable in capture)."),
    ]

    for dim, desc in rules_data:
        add_bullet_point(tf_l, "✔ " + dim + ":", desc, pt_size=10.5, space_after=7)

    # Right: Risk Matrix & Severity Scoring
    create_card(s6, Inches(7.8), Inches(1.75), Inches(4.733), Inches(5.1))
    tb_r = s6.shapes.add_textbox(Inches(8.05), Inches(1.9), Inches(4.2), Inches(4.8))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True

    p_r = tf_r.paragraphs[0]
    p_r.text = "Dynamic Risk Score Model (0–100)"
    p_r.font.bold = True
    p_r.font.size = Pt(14)
    p_r.font.color.rgb = COLOR_PRIMARY_NAVY
    p_r.space_after = Pt(8)

    severities = [
        ("Critical (Risk +40)", "Known broken crypto (DES, MD5, DH Group 1). Direct exploit vulnerability.", COLOR_ACCENT_RED),
        ("High (Risk +25)", "Deprecated ciphers (3DES, SHA-1, DH Group 2). Vulnerable to Sweet32 / collision.", COLOR_ACCENT_AMBER),
        ("Medium (Risk +15)", "Suboptimal parameters (DH Group 5 MODP-1536). Below modern recommendations.", COLOR_ACCENT_BLUE),
        ("Low / Info (Risk +0)", "Informational notices, protocol version notes, or unextracted telemetry.", COLOR_ACCENT_GREEN),
    ]

    for s_title, s_desc, col in severities:
        p_s = tf_r.add_paragraph()
        p_s.text = s_title
        p_s.font.bold = True
        p_s.font.size = Pt(11)
        p_s.font.color.rgb = col
        p_d = tf_r.add_paragraph()
        p_d.text = s_desc
        p_d.font.size = Pt(10)
        p_d.font.color.rgb = COLOR_TEXT_BODY
        p_d.space_after = Pt(6)

    # =========================================================================
    # SLIDE 7: AI/ML Behavioral Classification
    # =========================================================================
    s7 = prs.slides.add_slide(blank)
    set_bg(s7, COLOR_BG_LIGHT)
    add_header(s7, "AI / Machine Learning Engine", "Behavioral Encrypted Traffic Characterization (VNAT)")

    # 3 Horizontal Cards
    ml_cards = [
        ("1. Dataset & Training", "MIT Lincoln Laboratory VNAT", [
            ("15,093 Flow Samples:", "Real-world encrypted VPN traffic dataset captured over multi-protocol sessions."),
            ("Feature Engineering:", "Inter-arrival timing, flow volume, burst duration, packet size distributions."),
            ("Model Architecture:", "Optimized Scikit-learn Random Forest Classifier with calibrated probabilities."),
        ]),
        ("2. 5 Classified Traffic Categories", "Behavioral Fingerprints", [
            ("CHAT:", "Low-bandwidth, sporadic burst inter-arrival bursts (e.g. instant messaging)."),
            ("STREAMING:", "Continuous unidirectional high-volume throughput with uniform packet sizing."),
            ("FILE TRANSFER:", "Sustained maximum-segment packet streams with high byte transfer rates."),
            ("VOIP & C2:", "Low-latency symmetric packet cadence (VoIP) and periodic beaconing signals (C2)."),
        ]),
        ("3. Model Interpretation & Guardrails", "Transparency & Safety", [
            ("Confidence Threshold (< 50%):", "Flags predictions where model certainty is low, warning analyst."),
            ("Ambiguity Spread (< 15 pp):", "Alerts when top-two class scores are close, indicating dual behaviors."),
            ("C2 Advisory Notice:", "Explicit disclaimer that C2 is a traffic category label, not confirmed cyberattack."),
        ]),
    ]

    for i, (title, sub, items) in enumerate(ml_cards):
        c_left = Inches(0.8 + i * 3.95)
        create_card(s7, c_left, Inches(1.75), Inches(3.75), Inches(5.1))
        tb = s7.shapes.add_textbox(c_left + Inches(0.2), Inches(1.95), Inches(3.35), Inches(4.7))
        tf = tb.text_frame
        tf.word_wrap = True

        p_t = tf.paragraphs[0]
        p_t.text = title
        p_t.font.bold = True
        p_t.font.size = Pt(13)
        p_t.font.color.rgb = COLOR_PRIMARY_NAVY

        p_s = tf.add_paragraph()
        p_s.text = sub.upper()
        p_s.font.bold = True
        p_s.font.size = Pt(9)
        p_s.font.color.rgb = COLOR_ACCENT_PURPLE
        p_s.space_after = Pt(10)

        for bold_t, norm_t in items:
            add_bullet_point(tf, "• " + bold_t, norm_t, pt_size=10.5, space_after=8)

    # =========================================================================
    # SLIDE 8: Experimental Results & Demonstration
    # =========================================================================
    s8 = prs.slides.add_slide(blank)
    set_bg(s8, COLOR_BG_LIGHT)
    add_header(s8, "Testing & Validation", "Experimental Validation on strongSwan IPsec Testbed")

    # 4 Metric Outcome Boxes
    metrics = [
        ("IKEv1 & IKEv2", "Full Protocol Support", "Tested with strongSwan Linux IPsec tunnels across main mode, aggressive mode & IKEv2."),
        ("100% Detection", "Weak Cipher Identification", "Accurately flagged 3DES-CBC and MODP-1024 proposals with critical severity alerts."),
        ("Zero Decryption", "Payload Privacy Preserved", "Classified traffic patterns purely using outer packet headers and timing telemetry."),
        ("< 3.0 Seconds", "Fast Analysis Runtime", "High-throughput packet parsing pipeline processing multi-megabyte captures rapidly."),
    ]

    for i, (stat, title, desc) in enumerate(metrics):
        c_left = Inches(0.8 + i * 2.95)
        create_card(s8, c_left, Inches(1.75), Inches(2.8), Inches(2.2))
        tb = s8.shapes.add_textbox(c_left + Inches(0.15), Inches(1.9), Inches(2.5), Inches(1.9))
        tf = tb.text_frame
        tf.word_wrap = True
        
        p_stat = tf.paragraphs[0]
        p_stat.text = stat
        p_stat.font.bold = True
        p_stat.font.size = Pt(18)
        p_stat.font.color.rgb = COLOR_ACCENT_BLUE
        
        p_t = tf.add_paragraph()
        p_t.text = title
        p_t.font.bold = True
        p_t.font.size = Pt(10.5)
        p_t.font.color.rgb = COLOR_PRIMARY_NAVY
        p_t.space_after = Pt(4)

        p_d = tf.add_paragraph()
        p_d.text = desc
        p_d.font.size = Pt(9.5)
        p_d.font.color.rgb = COLOR_TEXT_BODY

    # Comparison Table / Real-world Impact
    create_card(s8, Inches(0.8), Inches(4.2), Inches(11.733), Inches(2.65))
    tb_table = s8.shapes.add_textbox(Inches(1.05), Inches(4.35), Inches(11.2), Inches(2.35))
    tf_tab = tb_table.text_frame
    tf_tab.word_wrap = True

    p = tf_tab.paragraphs[0]
    p.text = "Key Operational Differentiators"
    p.font.bold = True
    p.font.size = Pt(13)
    p.font.color.rgb = COLOR_PRIMARY_NAVY
    p.space_after = Pt(6)

    diffs = [
        ("Automated Compliance Scoring:", "Unlike manual Wireshark packet inspection, computes an objective risk score based on NIST guidelines."),
        ("Analysis Coverage Summary:", "Explicitly distinguishes between passed rules and skipped rules where parameters were absent in capture."),
        ("Actionable Remediation Guidance:", "Provides concrete configuration fixes (e.g. 'Upgrade to AES-256-GCM and DH Group 14') for each finding."),
        ("Dual-Output Architecture:", "Combines deterministic cryptography verification with statistical ML traffic characterization."),
    ]
    for bold_t, norm_t in diffs:
        add_bullet_point(tf_tab, "✔ " + bold_t, norm_t, pt_size=10.5, space_after=4)

    # =========================================================================
    # SLIDE 9: Conclusion & Future Scope (Dark Mode Bookend)
    # =========================================================================
    s9 = prs.slides.add_slide(blank)
    set_bg(s9, COLOR_BG_DARK)
    add_header(s9, "Summary & Roadmap", "Conclusion & Future Scope", dark_mode=True)

    # Left Card: Summary
    create_card(s9, Inches(0.8), Inches(1.8), Inches(5.7), Inches(5.0), bg_color=RGBColor(15, 23, 42), border_color=RGBColor(30, 41, 59))
    tb_sum = s9.shapes.add_textbox(Inches(1.05), Inches(2.0), Inches(5.2), Inches(4.6))
    tf_sum = tb_sum.text_frame
    tf_sum.word_wrap = True

    p_s = tf_sum.paragraphs[0]
    p_s.text = "Project Summary & Impact"
    p_s.font.bold = True
    p_s.font.size = Pt(16)
    p_s.font.color.rgb = COLOR_ACCENT_CYAN
    p_s.space_after = Pt(10)

    sum_items = [
        ("Complete End-to-End Pipeline:", "Successfully integrates PCAP upload, TShark extraction, NIST security auditing, and ML classification."),
        ("Evidence-Based Security:", "Replaces guesswork with strict cryptographic rule evaluation and an auditable findings trail."),
        ("Analyst-Friendly Interface:", "Intuitive React dashboard with coverage summaries, interactive probability charts, and PDF exports."),
    ]
    for b_t, n_t in sum_items:
        add_bullet_point(tf_sum, "✔ " + b_t, n_t, pt_size=11, color=RGBColor(203, 213, 225), space_after=12)

    # Right Card: Future Scope
    create_card(s9, Inches(6.8), Inches(1.8), Inches(5.7), Inches(5.0), bg_color=RGBColor(15, 23, 42), border_color=RGBColor(30, 41, 59))
    tb_fut = s9.shapes.add_textbox(Inches(7.05), Inches(2.0), Inches(5.2), Inches(4.6))
    tf_fut = tb_fut.text_frame
    tf_fut.word_wrap = True

    p_f = tf_fut.paragraphs[0]
    p_f.text = "Future Roadmap & Enhancements"
    p_f.font.bold = True
    p_f.font.size = Pt(16)
    p_f.font.color.rgb = COLOR_ACCENT_BLUE
    p_f.space_after = Pt(10)

    fut_items = [
        ("Live Interface Sniffing:", "Support real-time streaming packet capture from live network interfaces (AF_PACKET / WinPcap)."),
        ("Post-Quantum Crypto (PQC) Auditing:", "Add verification rules for NIST Post-Quantum Algorithms (ML-KEM / Kyber, ML-DSA)."),
        ("Fine-Grained Threat Modeling:", "Train transformer/deep-learning models on expanded multi-vendor VPN datasets."),
    ]
    for b_t, n_t in fut_items:
        add_bullet_point(tf_fut, "➔ " + b_t, n_t, pt_size=11, color=RGBColor(203, 213, 225), space_after=12)

    # Save presentation
    output_path = "IPsec_VPN_Analyzer_Presentation_v2.pptx"
    prs.save(output_path)
    print(f"Presentation successfully created at: {output_path}")

if __name__ == "__main__":
    build_deck()
