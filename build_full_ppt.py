"""
build_full_ppt.py
Generates the complete 13-slide PowerPoint presentation matching PPT_Content_IPsec_VPN_Analyzer.md
for Minor Project Presentation | SIH Problem Statement 2616 | NTRO.
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
    pill = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(0.8), Inches(0.4), Inches(3.2), Inches(0.35))
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

    tb = slide.shapes.add_textbox(Inches(0.8), Inches(0.78), Inches(11.7), Inches(0.7))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_top = tf.margin_right = tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.text = title
    p.font.name = FONT_HEADING
    p.font.size = Pt(21)
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

def add_bullet_point(text_frame, bold_prefix, text, pt_size=10.5, color=COLOR_TEXT_BODY, space_after=5):
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

def set_notes(slide, notes_text):
    """Adds speaker notes to slide."""
    slide.notes_slide.notes_text_frame.text = notes_text


def generate_deck():
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
    bar = s1.shapes.add_shape(MSO_SHAPE.RECTANGLE, 0, 0, Inches(13.333), Inches(0.12))
    bar.fill.solid()
    bar.fill.fore_color.rgb = COLOR_ACCENT_CYAN
    bar.line.fill.background()

    # Category Badge
    pill = s1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.0), Inches(1.1), Inches(4.5), Inches(0.42))
    pill.fill.solid()
    pill.fill.fore_color.rgb = RGBColor(30, 41, 59)
    pill.line.color.rgb = RGBColor(56, 189, 248)
    pill.line.width = Pt(1)
    tf = pill.text_frame
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.text = "SIH PROBLEM STATEMENT 2616 • NTRO"
    p.alignment = PP_ALIGN.CENTER
    p.font.name = FONT_HEADING
    p.font.size = Pt(10)
    p.font.bold = True
    p.font.color.rgb = RGBColor(56, 189, 248)

    # Title
    tb_title = s1.shapes.add_textbox(Inches(1.0), Inches(1.65), Inches(11.3), Inches(1.4))
    tf_t = tb_title.text_frame
    tf_t.word_wrap = True
    p_t = tf_t.paragraphs[0]
    p_t.text = "AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework"
    p_t.font.name = FONT_HEADING
    p_t.font.size = Pt(32)
    p_t.font.bold = True
    p_t.font.color.rgb = RGBColor(255, 255, 255)

    # Subtitle
    tb_sub = s1.shapes.add_textbox(Inches(1.0), Inches(3.1), Inches(11.3), Inches(0.6))
    tf_sub = tb_sub.text_frame
    p_sub = tf_sub.paragraphs[0]
    p_sub.text = "Minor Project Presentation | Category: Cybersecurity"
    p_sub.font.name = FONT_BODY
    p_sub.font.size = Pt(16)
    p_sub.font.color.rgb = RGBColor(148, 163, 184)

    # Info Grid (4 Cards)
    meta = [
        ("Problem Statement", "SIH 2616", "National Technical Research Organisation (NTRO)"),
        ("Focus Area", "IPsec Forensics", "Deep packet analysis, crypto auditing & ML traffic classification"),
        ("Project Scope", "Minor Project", "Dual-engine architecture, React dashboard & PDF reporting"),
        ("Session Date", "October 2026", "Team Presentation & Viva Review"),
    ]
    for i, (m_tag, m_title, m_desc) in enumerate(meta):
        c_left = Inches(1.0 + i * 2.85)
        create_card(s1, c_left, Inches(4.0), Inches(2.7), Inches(2.2), bg_color=RGBColor(15, 23, 42), border_color=RGBColor(30, 41, 59))
        tb_m = s1.shapes.add_textbox(c_left + Inches(0.18), Inches(4.15), Inches(2.34), Inches(1.9))
        tf_m = tb_m.text_frame
        tf_m.word_wrap = True
        
        p1 = tf_m.paragraphs[0]
        p1.text = m_tag.upper()
        p1.font.bold = True
        p1.font.size = Pt(8.5)
        p1.font.color.rgb = COLOR_ACCENT_CYAN
        p1.space_after = Pt(4)

        p2 = tf_m.add_paragraph()
        p2.text = m_title
        p2.font.bold = True
        p2.font.size = Pt(13)
        p2.font.color.rgb = RGBColor(255, 255, 255)
        p2.space_after = Pt(4)

        p3 = tf_m.add_paragraph()
        p3.text = m_desc
        p3.font.size = Pt(9.5)
        p3.font.color.rgb = RGBColor(148, 163, 184)

    set_notes(s1, "Title slide: Introduce project under SIH Problem Statement 2616 for NTRO. Focus on IPsec VPN security assessment combining static cryptography rules with ML traffic classification.")

    # =========================================================================
    # SLIDE 2: Agenda
    # =========================================================================
    s2 = prs.slides.add_slide(blank)
    set_bg(s2, COLOR_BG_LIGHT)
    add_header(s2, "Overview", "Presentation Agenda")

    agenda_items = [
        ("01", "Introduction / Background", "IPsec VPN fundamentals, IKEv1/v2, ESP & why crypto configuration matters"),
        ("02", "Problem Statement", "Official SIH 2616 mandate by NTRO & key packet inspection challenges"),
        ("03", "Project Objectives", "Primary detection goals, crypto extraction, ML classification & reporting"),
        ("04", "Existing System / Literature", "Limitations of Wireshark, Zeek, tcpdump & our novel dual-engine contribution"),
        ("05", "Proposed Solution", "Dual-engine architecture: Static security engine & ML behavioral classifier"),
        ("06", "Methodology / Workflow", "Step-by-step pipeline, TShark auto-discovery & dual database strategy"),
        ("07", "Technologies / Tools Used", "Full-stack implementation details: React, FastAPI, PyShark, Scikit-learn"),
        ("08", "Results & Key Features", "Risk scoring, security rules matrix, ML output & packet forensics table"),
        ("09", "Conclusion & Future Scope", "Project achievements, cloud deployment & future research roadmap"),
    ]

    for i, (num, title, desc) in enumerate(agenda_items):
        r = i // 3
        c = i % 3
        c_left = Inches(0.8 + c * 3.95)
        c_top  = Inches(1.65 + r * 1.75)
        
        create_card(s2, c_left, c_top, Inches(3.75), Inches(1.55))
        
        # Number badge
        nb = s2.shapes.add_shape(MSO_SHAPE.RECTANGLE, c_left, c_top, Inches(0.65), Inches(1.55))
        nb.fill.solid()
        nb.fill.fore_color.rgb = COLOR_PRIMARY_NAVY
        nb.line.fill.background()
        tf_nb = nb.text_frame
        tf_nb.vertical_anchor = MSO_ANCHOR.MIDDLE
        p_nb = tf_nb.paragraphs[0]
        p_nb.text = num
        p_nb.alignment = PP_ALIGN.CENTER
        p_nb.font.bold = True
        p_nb.font.size = Pt(13)
        p_nb.font.color.rgb = COLOR_ACCENT_CYAN

        tb = s2.shapes.add_textbox(c_left + Inches(0.8), c_top + Inches(0.12), Inches(2.8), Inches(1.3))
        tf = tb.text_frame
        tf.word_wrap = True
        p_t = tf.paragraphs[0]
        p_t.text = title
        p_t.font.bold = True
        p_t.font.size = Pt(11.5)
        p_t.font.color.rgb = COLOR_PRIMARY_NAVY
        p_t.space_after = Pt(2)
        p_d = tf.add_paragraph()
        p_d.text = desc
        p_d.font.size = Pt(9)
        p_d.font.color.rgb = COLOR_TEXT_BODY

    set_notes(s2, "Walk through the agenda covering background, problem statement, objectives, existing tools, solution, workflow, tech stack, results, and conclusion.")

    # =========================================================================
    # SLIDE 3: Introduction / Background
    # =========================================================================
    s3 = prs.slides.add_slide(blank)
    set_bg(s3, COLOR_BG_LIGHT)
    add_header(s3, "Background", "What is IPsec VPN & Why Configuration Matters")

    # Left Card: IPsec Fundamentals
    create_card(s3, Inches(0.8), Inches(1.65), Inches(5.75), Inches(5.2))
    tb_l = s3.shapes.add_textbox(Inches(1.05), Inches(1.85), Inches(5.25), Inches(4.8))
    tf_l = tb_l.text_frame
    tf_l.word_wrap = True

    p = tf_l.paragraphs[0]
    p.text = "IPsec Protocol Architecture"
    p.font.bold = True
    p.font.size = Pt(14)
    p.font.color.rgb = COLOR_PRIMARY_NAVY
    p.space_after = Pt(8)

    add_bullet_point(tf_l, "IPsec Suite:", "A framework of open standards securing IP communications via packet-by-packet authentication and encryption.")
    add_bullet_point(tf_l, "VPN Tunnels:", "Creates encrypted tunnels across untrusted public networks, protecting confidential enterprise communications.")
    add_bullet_point(tf_l, "IKE (Internet Key Exchange):", "Negotiates cryptographic parameters, exchanges keys, and establishes Security Associations (SAs).")
    add_bullet_point(tf_l, "ESP (Encapsulating Security Payload):", "Encrypts and optionally authenticates the actual payload data flowing through the tunnel.")
    add_bullet_point(tf_l, "Protocol Evolution:", "IKEv1 (legacy, complex, susceptible to aggressive-mode attacks) vs IKEv2 (modern, efficient, standardized standard).")
    add_bullet_point(tf_l, "Core Truth:", "Even when encryption is active, *how* the VPN is configured dictates real-world security.")

    # Right Card: Why It Matters
    create_card(s3, Inches(6.8), Inches(1.65), Inches(5.75), Inches(5.2))
    tb_r = s3.shapes.add_textbox(Inches(7.05), Inches(1.85), Inches(5.25), Inches(4.8))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True

    p_r = tf_r.paragraphs[0]
    p_r.text = "Critical Security Implications"
    p_r.font.bold = True
    p_r.font.size = Pt(14)
    p_r.font.color.rgb = COLOR_ACCENT_RED
    p_r.space_after = Pt(8)

    add_bullet_point(tf_r, "Weak Ciphers (3DES, DES):", "Prone to birthday collision attacks (Sweet32) and direct cryptanalysis, breaking confidentiality.", color=COLOR_TEXT_BODY)
    add_bullet_point(tf_r, "Deprecated DH Groups (1, 2, 5):", "Vulnerable to Logjam attack; nation-state adversaries can precompute discrete logarithms for 1024-bit primes.", color=COLOR_TEXT_BODY)
    add_bullet_point(tf_r, "Legacy IKEv1 Tunnels:", "Susceptible to offline dictionary attacks against Pre-Shared Keys in Aggressive Mode exchanges.", color=COLOR_TEXT_BODY)
    add_bullet_point(tf_r, "Silent Misconfigurations:", "Tunnels continue functioning normally even when utilizing dangerously degraded cryptographic suites.", color=COLOR_TEXT_BODY)
    add_bullet_point(tf_r, "Automated Audit Necessity:", "Organizations urgently require automated tools to inspect captured traffic and audit compliance without payload exposure.", color=COLOR_TEXT_BODY)

    set_notes(s3, "IPsec ka basic concept explain karo — IKE negotiates keys, ESP encrypts data. IKEv1 old hai, IKEv2 modern. Weak cipher ya weak DH group use hua toh encryption easily break ho sakti hai.")

    # =========================================================================
    # SLIDE 4: Problem Statement
    # =========================================================================
    s4 = prs.slides.add_slide(blank)
    set_bg(s4, COLOR_BG_LIGHT)
    add_header(s4, "Problem Statement", "SIH Problem 2616 & Industry Challenges")

    # Official mandate quote banner
    banner = create_card(s4, Inches(0.8), Inches(1.65), Inches(11.733), Inches(1.3), bg_color=RGBColor(15, 23, 42))
    tb_q = s4.shapes.add_textbox(Inches(1.05), Inches(1.75), Inches(11.2), Inches(1.1))
    tf_q = tb_q.text_frame
    tf_q.word_wrap = True
    p1 = tf_q.paragraphs[0]
    p1.text = "OFFICIAL PROBLEM STATEMENT — NTRO (SIH 2616)"
    p1.font.bold = True
    p1.font.size = Pt(9.5)
    p1.font.color.rgb = COLOR_ACCENT_CYAN
    p1.space_after = Pt(3)
    p2 = tf_q.add_paragraph()
    p2.text = "\"Develop an AI-powered tool to analyze IPsec VPN traffic from PCAP files, identify protocol characteristics, evaluate cryptographic configurations, and generate security assessment reports.\""
    p2.font.italic = True
    p2.font.size = Pt(13)
    p2.font.color.rgb = RGBColor(255, 255, 255)

    # 5 Challenge Cards
    challenges = [
        ("Manual Analysis Bottleneck", "Tools like Wireshark require deep cryptographic expertise to decode IKE payload transforms manually.", COLOR_ACCENT_AMBER),
        ("Hidden Cryptographic Flaws", "Deprecated algorithms remain invisible unless full IKE negotiation handshakes are dissected.", COLOR_ACCENT_RED),
        ("No Automated Compliance", "Security analysts lack automated tools scoring risk against NIST/RFC security benchmarks.", COLOR_ACCENT_PURPLE),
        ("Unknown Encrypted Traffic", "Traditional tools cannot categorize what type of application runs inside an encrypted tunnel.", COLOR_ACCENT_BLUE),
        ("Enterprise Scalability Gap", "Manually inspecting hundreds of PCAP captures is slow, inconsistent, and highly error-prone.", COLOR_ACCENT_CYAN),
    ]

    for i, (title, desc, col) in enumerate(challenges):
        c_left = Inches(0.8 + i * 2.37)
        create_card(s4, c_left, Inches(3.15), Inches(2.25), Inches(3.7))
        
        # Color bar
        cb = s4.shapes.add_shape(MSO_SHAPE.RECTANGLE, c_left, Inches(3.15), Inches(2.25), Inches(0.08))
        cb.fill.solid()
        cb.fill.fore_color.rgb = col
        cb.line.fill.background()

        tb = s4.shapes.add_textbox(c_left + Inches(0.12), Inches(3.3), Inches(2.0), Inches(3.4))
        tf = tb.text_frame
        tf.word_wrap = True
        p_t = tf.paragraphs[0]
        p_t.text = title
        p_t.font.bold = True
        p_t.font.size = Pt(11)
        p_t.font.color.rgb = COLOR_PRIMARY_NAVY
        p_t.space_after = Pt(8)
        p_d = tf.add_paragraph()
        p_d.text = desc
        p_d.font.size = Pt(9.5)
        p_d.font.color.rgb = COLOR_TEXT_BODY

    set_notes(s4, "Manual Wireshark analysis me expert chahiye. Automated tool nahi tha jo crypto weakness + ML dono kare. NTRO mandate addresses this exact gap.")

    # =========================================================================
    # SLIDE 5: Objectives
    # =========================================================================
    s5 = prs.slides.add_slide(blank)
    set_bg(s5, COLOR_BG_LIGHT)
    add_header(s5, "Project Goals", "Primary & Secondary Project Objectives")

    # Primary Objectives Card (Left)
    create_card(s5, Inches(0.8), Inches(1.65), Inches(7.5), Inches(5.2))
    tb_p = s5.shapes.add_textbox(Inches(1.05), Inches(1.85), Inches(7.0), Inches(4.8))
    tf_p = tb_p.text_frame
    tf_p.word_wrap = True

    p = tf_p.paragraphs[0]
    p.text = "Primary Objectives (Delivered)"
    p.font.bold = True
    p.font.size = Pt(14)
    p.font.color.rgb = COLOR_PRIMARY_NAVY
    p.space_after = Pt(8)

    primaries = [
        ("PCAP / PCAPNG Ingestion:", "Accept, validate, and parse raw capture files up to 100MB containing IPsec traffic."),
        ("IKE Version Auto-Detection:", "Distinguish IKEv1 (ISAKMP) vs IKEv2 using version byte & exchange type telemetry."),
        ("Crypto Parameter Extraction:", "Extract encryption ciphers (AES/3DES), auth methods, DH groups, and ESP SPIs."),
        ("Deterministic Security Scoring:", "Evaluate extracted parameters against rule-based engine to generate Risk Score (0–100)."),
        ("ML Behavioral Classification:", "Classify encrypted flow traffic into 5 behavioral classes without decrypting payloads."),
        ("Interactive Web Dashboard:", "Display metrics, Recharts distribution charts, rule audit trail, and packet forensics."),
        ("Executive PDF Reporting:", "Generate audit-ready security reports with findings, evidence, and remediation steps."),
    ]
    for b_t, n_t in primaries:
        add_bullet_point(tf_p, "✔ " + b_t, n_t, pt_size=10, space_after=5)

    # Secondary Objectives Card (Right)
    create_card(s5, Inches(8.5), Inches(1.65), Inches(4.033), Inches(5.2))
    tb_s = s5.shapes.add_textbox(Inches(8.75), Inches(1.85), Inches(3.5), Inches(4.8))
    tf_s = tb_s.text_frame
    tf_s.word_wrap = True

    p_s = tf_s.paragraphs[0]
    p_s.text = "Core Principles & Architecture"
    p_s.font.bold = True
    p_s.font.size = Pt(14)
    p_s.font.color.rgb = COLOR_ACCENT_BLUE
    p_s.space_after = Pt(8)

    secondaries = [
        ("Evidence-Based Findings:", "Only flag issues backed by observed packets; zero speculation."),
        ("Honest Uncertainty:", "Clearly label unobserved items as 'Not Extracted' rather than fabricating data."),
        ("Cross-Platform Daemon:", "Full execution on Windows, Linux, and Cloud (Render / Docker)."),
        ("Dual Database Support:", "Local SQLite fallback + MongoDB Atlas cloud sync."),
    ]
    for b_t, n_t in secondaries:
        add_bullet_point(tf_s, "★ " + b_t, n_t, pt_size=10, space_after=8)

    set_notes(s5, "7 primary goals complete hue: detection, parameter extraction, risk scoring, ML classification, dashboard, forensics, reporting. Plus honest reporting principle.")

    # =========================================================================
    # SLIDE 6: Existing System / Literature Review
    # =========================================================================
    s6 = prs.slides.add_slide(blank)
    set_bg(s6, COLOR_BG_LIGHT)
    add_header(s6, "Literature Review", "Existing Tools vs. Our Novel Contribution")

    # Table of existing tools
    create_card(s6, Inches(0.8), Inches(1.65), Inches(6.8), Inches(5.2))
    tb_tab = s6.shapes.add_textbox(Inches(1.0), Inches(1.85), Inches(6.4), Inches(4.8))
    tf_tab = tb_tab.text_frame
    tf_tab.word_wrap = True

    p = tf_tab.paragraphs[0]
    p.text = "Limitations of Existing Network Forensics Tools"
    p.font.bold = True
    p.font.size = Pt(13)
    p.font.color.rgb = COLOR_PRIMARY_NAVY
    p.space_after = Pt(8)

    tools = [
        ("Wireshark", "Deep packet inspection", "Requires rare crypto expertise; no automated compliance scoring."),
        ("tcpdump", "CLI packet capture", "Console stream only; zero cryptographic or behavioral assessment."),
        ("strongSwan / Logs", "Daemon endpoint logs", "Analyzes local configs only; cannot audit third-party captures."),
        ("Zeek (Bro IDS)", "Broad network monitor", "Monitors general traffic; lacks dedicated IPsec crypto depth."),
        ("Manual Pentesting", "Human security audit", "Expensive, slow, unscalable for continuous security postures."),
        ("Commercial SIEMs", "Enterprise event logging", "Cost-prohibitive overkill; lacks granular IKE packet analysis."),
    ]
    for name, what, limit in tools:
        add_bullet_point(tf_tab, f"• {name} ({what}):", limit, pt_size=9.5, space_after=4)

    # Right Card: Novel Contribution
    create_card(s6, Inches(7.8), Inches(1.65), Inches(4.733), Inches(5.2))
    tb_nov = s6.shapes.add_textbox(Inches(8.05), Inches(1.85), Inches(4.2), Inches(4.8))
    tf_nov = tb_nov.text_frame
    tf_nov.word_wrap = True

    p_n = tf_nov.paragraphs[0]
    p_n.text = "Our Novel Contribution"
    p_n.font.bold = True
    p_n.font.size = Pt(13)
    p_n.font.color.rgb = COLOR_ACCENT_GREEN
    p_n.space_after = Pt(8)

    contributions = [
        ("Dual-Engine Architecture:", "First open-source platform combining deterministic crypto audit with statistical ML."),
        ("Observable Evidence Policy:", "Flags issues solely from observed packets. Zero false assumptions."),
        ("Analysis Coverage Summary:", "Transparently reports skipped rules with capture root-cause explanations."),
        ("Accessible Web Dashboard:", "Intuitive visualization for both technical analysts and executive decision-makers."),
    ]
    for b_t, n_t in contributions:
        add_bullet_point(tf_nov, "✔ " + b_t, n_t, pt_size=10, space_after=8)

    set_notes(s6, "Existing tools like Wireshark manual hain, Zeek IPsec crypto check nahi karta, SIEMs expensive hain. Humne dual-engine approach se gap fill kiya.")

    # =========================================================================
    # SLIDE 7: Proposed Solution (Dual-Engine)
    # =========================================================================
    s7 = prs.slides.add_slide(blank)
    set_bg(s7, COLOR_BG_LIGHT)
    add_header(s7, "Solution Architecture", "Dual-Engine Analysis Framework")

    # Left Engine Card (Engine A: Static)
    create_card(s7, Inches(0.8), Inches(1.65), Inches(5.75), Inches(5.2))
    tb_ea = s7.shapes.add_textbox(Inches(1.05), Inches(1.85), Inches(5.25), Inches(4.8))
    tf_ea = tb_ea.text_frame
    tf_ea.word_wrap = True

    p = tf_ea.paragraphs[0]
    p.text = "Engine A: Static Security Analysis"
    p.font.bold = True
    p.font.size = Pt(14)
    p.font.color.rgb = COLOR_ACCENT_BLUE
    p.space_after = Pt(6)

    add_bullet_point(tf_ea, "Deep IKE/ESP Inspection:", "Parses ISAKMP and IKEv2 payloads, extracting transform attributes.")
    add_bullet_point(tf_ea, "Extracted Cryptographic Suite:", "Identifies Encryption Ciphers, Integrity Hashes, DH Key-Exchange Groups & Auth Methods.")
    add_bullet_point(tf_ea, "Deterministic Rule Engine:", "Evaluates observed transforms against RFC 8221 / NIST SP 800-77 security benchmarks.")
    add_bullet_point(tf_ea, "Weighted Risk Score:", "Calculates 0–100 risk score with clear severity classification (Critical, High, Medium, Low).")
    add_bullet_point(tf_ea, "Explainable Findings:", "Each finding pairs supporting packet evidence with actionable remediation advice.")

    # Right Engine Card (Engine B: ML)
    create_card(s7, Inches(6.8), Inches(1.65), Inches(5.75), Inches(5.2))
    tb_eb = s7.shapes.add_textbox(Inches(7.05), Inches(1.85), Inches(5.25), Inches(4.8))
    tf_eb = tb_eb.text_frame
    tf_eb.word_wrap = True

    p = tf_eb.paragraphs[0]
    p.text = "Engine B: ML Traffic Classification"
    p.font.bold = True
    p.font.size = Pt(14)
    p.font.color.rgb = COLOR_ACCENT_PURPLE
    p.space_after = Pt(6)

    add_bullet_point(tf_eb, "Zero-Decryption Behavioral Analysis:", "Characterizes traffic solely via flow timing, packet sizes, and burst dynamics.")
    add_bullet_point(tf_eb, "MIT Lincoln Lab VNAT Dataset:", "Trained on 15,093 multi-protocol real-world encrypted VPN sessions.")
    add_bullet_point(tf_eb, "RandomForest Classifier (200 Trees):", "Achieves 98.48% test accuracy across 5 distinct application categories.")
    add_bullet_point(tf_eb, "5 Predicted Categories:", "CHAT, STREAMING, FILE_TRANSFER, VOIP, C2 (Command & Control).")
    add_bullet_point(tf_eb, "Transparency Guardrails:", "Displays confidence percentage, ambiguity spread (<15 pp), and short-capture alerts.")

    set_notes(s7, "Do engines explain karo: Engine A static crypto rules check karta hai NIST compliance ke hisab se. Engine B bina decrypt kiye ML se traffic category predict karta hai (98.48% accuracy).")

    # =========================================================================
    # SLIDE 8: Methodology & Workflow (Embeds Diagram)
    # =========================================================================
    s8 = prs.slides.add_slide(blank)
    set_bg(s8, COLOR_BG_LIGHT)
    add_header(s8, "Methodology", "System Workflow & Pipeline Execution")

    # Embed generated image
    img_path = r"C:\Users\PURVA\.gemini\antigravity-ide\brain\50394f46-5af0-4e34-96dd-2798eb4f69a1\accurate_vpn_pipeline_1792080609766.jpg"
    if os.path.exists(img_path):
        s8.shapes.add_picture(img_path, Inches(0.8), Inches(1.65), Inches(11.733), Inches(5.25))

    set_notes(s8, "Methodology slide: Step-by-step pipeline from PCAP upload, TShark extraction, IKE protocol identification, crypto analysis, dual-engine assessment, to dashboard & PDF report.")

    # =========================================================================
    # SLIDE 9: Technologies / Tools Used
    # =========================================================================
    s9 = prs.slides.add_slide(blank)
    set_bg(s9, COLOR_BG_LIGHT)
    add_header(s9, "Technologies", "Full-Stack Technology Stack & Key Design Choices")

    stacks = [
        ("Frontend Application", "React.js • Tailwind CSS • Recharts", [
            ("React 19 + Vite:", "Ultra-responsive single page app with fast HMR."),
            ("Tailwind CSS:", "Utility-first styling with custom dark/light theme tokens."),
            ("Recharts:", "Dynamic horizontal probability bar charts & size histograms."),
        ], COLOR_ACCENT_CYAN),
        ("Backend Services", "Python 3.13 • FastAPI • Uvicorn", [
            ("FastAPI:", "High-throughput asynchronous REST API endpoints."),
            ("Pydantic:", "Strict schema validation for all requests and responses."),
            ("TShark Auto-Discovery:", "Dynamically finds TShark on Windows, Linux, and Mac."),
        ], COLOR_ACCENT_BLUE),
        ("Packet Forensics & ML", "PyShark • TShark • Scikit-learn", [
            ("PyShark + TShark:", "Dual-layer packet extraction with subprocess fallback."),
            ("ThreadPoolExecutor:", "Isolates packet parsing from Uvicorn's event loop."),
            ("Scikit-learn:", "Random Forest (200 estimators) trained on VNAT dataset."),
        ], COLOR_ACCENT_PURPLE),
        ("Database & Infrastructure", "SQLite • MongoDB Atlas • ReportLab", [
            ("Dual Database:", "Zero-config SQLite local fallback + MongoDB cloud sync."),
            ("ReportLab:", "Programmatic executive PDF security report generator."),
            ("Docker / Render:", "Production-ready containerized cloud deployment."),
        ], COLOR_ACCENT_GREEN),
    ]

    for i, (title, sub, items, col) in enumerate(stacks):
        r = i // 2
        c = i % 2
        c_left = Inches(0.8 + c * 5.95)
        c_top  = Inches(1.65 + r * 2.65)
        create_card(s9, c_left, c_top, Inches(5.75), Inches(2.45))
        
        # Color bar
        cb = s9.shapes.add_shape(MSO_SHAPE.RECTANGLE, c_left, c_top, Inches(0.12), Inches(2.45))
        cb.fill.solid()
        cb.fill.fore_color.rgb = col
        cb.line.fill.background()

        tb = s9.shapes.add_textbox(c_left + Inches(0.25), c_top + Inches(0.15), Inches(5.35), Inches(2.2))
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
        p_s.font.color.rgb = col
        p_s.space_after = Pt(4)

        for b_t, n_t in items:
            add_bullet_point(tf, "• " + b_t, n_t, pt_size=10, space_after=3)

    set_notes(s9, "Tech stack explain karo: React frontend, FastAPI backend, PyShark+TShark parsing, RandomForest ML, SQLite auto-fallback, ReportLab PDF reporting.")

    # =========================================================================
    # SLIDE 10: Results / Key Features
    # =========================================================================
    s10 = prs.slides.add_slide(blank)
    set_bg(s10, COLOR_BG_LIGHT)
    add_header(s10, "Platform Deliverables", "System Outputs & Core Security Capabilities")

    # Left: Security Rules Table
    create_card(s10, Inches(0.8), Inches(1.65), Inches(6.8), Inches(5.2))
    tb_r = s10.shapes.add_textbox(Inches(1.05), Inches(1.85), Inches(6.3), Inches(4.8))
    tf_r = tb_r.text_frame
    tf_r.word_wrap = True

    p = tf_r.paragraphs[0]
    p.text = "Security Rules & Risk Assessment Matrix"
    p.font.bold = True
    p.font.size = Pt(13)
    p.font.color.rgb = COLOR_PRIMARY_NAVY
    p.space_after = Pt(8)

    rules = [
        ("IKE Version Check:", "IKEv1 detected (Risk +2) vs IKEv2 (Pass)."),
        ("Encryption Algorithm:", "Flags DES/3DES/NULL (Risk +3); validates AES-GCM/CBC (Pass)."),
        ("DH Group Strength:", "Rejects Group 1, 2, 5 (Risk +3); validates Group 14, 19, 20 (Pass)."),
        ("Authentication Method:", "Checks PSK hygiene (Risk +1) vs Digital Certificates RSA/ECDSA (Pass)."),
        ("ESP Protection:", "Verifies presence of encrypted data packets in capture."),
        ("Dynamic Risk Level:", "Categorized as High, Medium, Low, or Informational."),
    ]
    for b_t, n_t in rules:
        add_bullet_point(tf_r, "✔ " + b_t, n_t, pt_size=10, space_after=6)

    # Right: ML Output & Forensics
    create_card(s10, Inches(7.8), Inches(1.65), Inches(4.733), Inches(5.2))
    tb_m = s10.shapes.add_textbox(Inches(8.05), Inches(1.85), Inches(4.2), Inches(4.8))
    tf_m = tb_m.text_frame
    tf_m.word_wrap = True

    p = tf_m.paragraphs[0]
    p.text = "ML Classification & Forensics"
    p.font.bold = True
    p.font.size = Pt(13)
    p.font.color.rgb = COLOR_ACCENT_PURPLE
    p.space_after = Pt(8)

    ml_feats = [
        ("Predicted Category:", "Displays top traffic class with visual probability bar chart."),
        ("Confidence Score:", "High-precision certainty rating (e.g. 98.2%)."),
        ("Probability Breakdown:", "Complete distribution across all 5 VNAT traffic classes."),
        ("Short-Capture Warning:", "Auto-alerts analyst if PCAP < 50 pkts due to limited flow timing."),
        ("Packet Forensics Table:", "Presents up to 150 individual packets: IP, SPI, length, timestamp."),
    ]
    for b_t, n_t in ml_feats:
        add_bullet_point(tf_m, "★ " + b_t, n_t, pt_size=10, space_after=6)

    set_notes(s10, "Results slide: Risk score 0-10+, findings with evidence, ML 98.48% accuracy with class breakdown, packet forensics table upto 150 packets.")

    # =========================================================================
    # SLIDE 11: Challenges & How We Solved Them
    # =========================================================================
    s11 = prs.slides.add_slide(blank)
    set_bg(s11, COLOR_BG_LIGHT)
    add_header(s11, "Engineering Challenges", "Key Technical Hurdles & Implemented Solutions")

    challenges_solutions = [
        ("PyShark vs. Uvicorn Event Loop", "PyShark's internal asyncio conflicts with FastAPI's event loop.", "Isolated PyShark into a dedicated ThreadPoolExecutor with its own scoped event loop.", COLOR_ACCENT_RED),
        ("Missing Attributes in PyShark", "PyShark occasionally drops nested IKE transform fields.", "Engineered a dual-layer extraction: PyShark first, followed by direct TShark subprocess fallback.", COLOR_ACCENT_AMBER),
        ("Zero-Config Cloud Database", "PostgreSQL requires external credentials often missing in free tiers.", "Implemented auto-detecting SQLite fallback ensuring zero-config out-of-the-box history logging.", COLOR_ACCENT_BLUE),
        ("Short Capture Reliability", "Small captures (<50 packets) cause skewed inter-arrival statistics.", "Built an automatic warning banner alerting analysts when timing features are statistically thin.", COLOR_ACCENT_PURPLE),
        ("Reliable IKEv1/v2 Detection", "Heuristic packet parsing can confuse retransmissions and notifications.", "Combined protocol version nibble checking with exchange type numerical mapping.", COLOR_ACCENT_GREEN),
        ("Production Cloud Builds", "Heavy build dependencies causing deployment timeouts.", "Streamlined frontend bundle with Vite and Docker multi-stage container optimization.", COLOR_ACCENT_CYAN),
    ]

    for i, (title, problem, solution, col) in enumerate(challenges_solutions):
        r = i // 2
        c = i % 2
        c_left = Inches(0.8 + c * 5.95)
        c_top  = Inches(1.65 + r * 1.75)
        create_card(s11, c_left, c_top, Inches(5.75), Inches(1.55))
        
        # Color bar
        cb = s11.shapes.add_shape(MSO_SHAPE.RECTANGLE, c_left, c_top, Inches(0.1), Inches(1.55))
        cb.fill.solid()
        cb.fill.fore_color.rgb = col
        cb.line.fill.background()

        tb = s11.shapes.add_textbox(c_left + Inches(0.2), c_top + Inches(0.08), Inches(5.4), Inches(1.4))
        tf = tb.text_frame
        tf.word_wrap = True

        p_t = tf.paragraphs[0]
        p_t.text = title
        p_t.font.bold = True
        p_t.font.size = Pt(11)
        p_t.font.color.rgb = COLOR_PRIMARY_NAVY
        p_t.space_after = Pt(2)

        add_bullet_point(tf, "Problem:", problem, pt_size=9, color=COLOR_TEXT_MUTED, space_after=1)
        add_bullet_point(tf, "Solution:", solution, pt_size=9, color=COLOR_PRIMARY_NAVY, space_after=1)

    set_notes(s11, "Challenges slide: Explain how we resolved Uvicorn event loop conflict, TShark fallback parsing, SQLite cloud fallback, and short capture warnings.")

    # =========================================================================
    # SLIDE 12: Conclusion & Future Scope
    # =========================================================================
    s12 = prs.slides.add_slide(blank)
    set_bg(s12, COLOR_BG_LIGHT)
    add_header(s12, "Summary & Roadmap", "Conclusion & Future Scope")

    # Left Card: Conclusion & Achievements
    create_card(s12, Inches(0.8), Inches(1.65), Inches(5.75), Inches(5.2))
    tb_c = s12.shapes.add_textbox(Inches(1.05), Inches(1.85), Inches(5.25), Inches(4.8))
    tf_c = tb_c.text_frame
    tf_c.word_wrap = True

    p = tf_c.paragraphs[0]
    p.text = "What We Achieved"
    p.font.bold = True
    p.font.size = Pt(14)
    p.font.color.rgb = COLOR_ACCENT_GREEN
    p.space_after = Pt(6)

    achievements = [
        ("Real Packet Forensics:", "Parses actual PCAP/PCAPNG captures (not mock/simulated data)."),
        ("Automated Protocol Auditing:", "Detects IKE version and extracts encryption, auth & DH groups."),
        ("Deterministic Risk Scoring:", "Transparent 0–100 risk score based on NIST guidelines."),
        ("ML Encrypted Classification:", "98.48% accuracy on VNAT dataset without decrypting payloads."),
        ("Evidence Integrity:", "Never fabricates unobserved parameters; marks as 'Not Extracted'."),
        ("Cloud & Local Ready:", "Dockerized and deployed on Render with local Windows/Linux support."),
    ]
    for b_t, n_t in achievements:
        add_bullet_point(tf_c, "✔ " + b_t, n_t, pt_size=10, space_after=5)

    # Right Card: Future Scope
    create_card(s12, Inches(6.8), Inches(1.65), Inches(5.75), Inches(5.2))
    tb_f = s12.shapes.add_textbox(Inches(7.05), Inches(1.85), Inches(5.25), Inches(4.8))
    tf_f = tb_f.text_frame
    tf_f.word_wrap = True

    p = tf_f.paragraphs[0]
    p.text = "Future Scope & Enhancements"
    p.font.bold = True
    p.font.size = Pt(14)
    p.font.color.rgb = COLOR_ACCENT_BLUE
    p.space_after = Pt(6)

    futures = [
        ("Live Interface Sniffing:", "Real-time continuous packet capture from network interfaces (AF_PACKET)."),
        ("IKEv2 MOBIKE Support:", "Mobile IKEv2 protocol support for dynamic multi-homed tunnels."),
        ("SIEM Integration:", "Export findings and risk telemetry directly to Splunk and Elastic SIEM."),
        ("Post-Quantum Cryptography (PQC):", "Audit readiness against quantum-resistant algorithms (ML-KEM / Kyber)."),
        ("AH Protocol Support:", "Extend analysis to Authentication Header (AH) payloads."),
        ("Fine-Grained Threat Models:", "Train deep-learning transformers on enterprise-specific traffic archives."),
    ]
    for b_t, n_t in futures:
        add_bullet_point(tf_f, "➔ " + b_t, n_t, pt_size=10, space_after=5)

    set_notes(s12, "Conclusion slide: Real packet analysis, honest findings, cloud deployed. Future scope: live capture, PQC readiness, and SIEM integration.")

    # =========================================================================
    # SLIDE 13: References
    # =========================================================================
    s13 = prs.slides.add_slide(blank)
    set_bg(s13, COLOR_BG_DARK)
    add_header(s13, "References & Standards", "Key References & Citations", dark_mode=True)

    create_card(s13, Inches(0.8), Inches(1.65), Inches(11.733), Inches(5.2), bg_color=RGBColor(15, 23, 42), border_color=RGBColor(30, 41, 59))
    tb_ref = s13.shapes.add_textbox(Inches(1.1), Inches(1.85), Inches(11.1), Inches(4.8))
    tf_ref = tb_ref.text_frame
    tf_ref.word_wrap = True

    refs = [
        ("RFC 7296:", "Internet Key Exchange Protocol Version 2 (IKEv2), Kaufman et al., IETF Standard, 2014."),
        ("RFC 4301:", "Security Architecture for the Internet Protocol (IPsec), Kent & Seo, IETF Standard, 2005."),
        ("RFC 2409:", "The Internet Key Exchange (IKEv1), Harkins & Carrel, IETF RFC, 1998."),
        ("NIST SP 800-77 Rev. 1:", "Guide to IPsec VPNs, National Institute of Standards and Technology, 2020."),
        ("VNAT Dataset:", "MIT Lincoln Laboratory, 'VPN/Non-VPN Network Application Traffic Dataset', MIT LL Archive."),
        ("PyShark Forensics:", "Python wrapper for TShark packet analysis, KimiNewt open source project."),
        ("Scikit-learn:", "Pedregosa et al., 'Scikit-learn: Machine Learning in Python', Journal of Machine Learning Research."),
        ("Logjam Attack:", "Adrian et al., 'Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice', ACM CCS 2015."),
        ("SIH 2026 Problem 2616:", "National Technical Research Organisation (NTRO), Smart India Hackathon 2026."),
    ]

    for b_t, n_t in refs:
        add_bullet_point(tf_ref, b_t, n_t, pt_size=10.5, color=RGBColor(203, 213, 225), space_after=6)

    set_notes(s13, "References slide: Cite RFCs (7296, 4301, 2409), NIST SP 800-77, MIT Lincoln Lab VNAT dataset, Logjam attack paper, and SIH Problem Statement 2616.")

    # Save presentation
    output_filename = "IPsec_VPN_Analyzer_Presentation.pptx"
    prs.save(output_filename)
    print(f"Full 13-slide presentation successfully saved to: {output_filename}")

if __name__ == "__main__":
    generate_deck()
