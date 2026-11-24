# 📊 PPT Content — AI-Powered IPsec VPN Protocol Analyzer
### Minor Project Presentation | SIH Problem Statement 2616 | NTRO

---

## SLIDE 1 — Title Slide

**Title:** AI-Powered IPsec VPN Protocol Analyzer & Security Assessment Framework

**Subtitle:** Minor Project Presentation

**Details:**
- SIH Problem Statement No.: 2616
- Organization: National Technical Research Organisation (NTRO)
- Category: Cybersecurity

**Team Members:** *(Add your names)*
**Guide:** *(Add guide name)*
**Institution:** *(Add institution name)*
**Date:** October 2026

---

## SLIDE 2 — Agenda

- Introduction / Background
- Problem Statement
- Objectives
- Existing System / Literature Review
- Proposed Solution
- Methodology / Workflow
- Technologies / Tools Used
- Conclusion & Future Scope
- References

---

## SLIDE 3 — Introduction / Background

**Heading:** What is IPsec VPN?

**Points:**
- **IPsec (Internet Protocol Security)** is a suite of protocols used to secure IP communications by authenticating and encrypting each IP packet in a session.
- **VPN (Virtual Private Network)** creates an encrypted "tunnel" over a public network (e.g., internet) for secure communication.
- IPsec uses two main protocols:
  - **IKE (Internet Key Exchange)** — negotiates and establishes security associations (keys)
  - **ESP (Encapsulating Security Payload)** — encrypts actual data
- IKE has two versions:
  - **IKEv1** — older, legacy, vulnerable to attacks
  - **IKEv2** — modern, more secure, recommended standard
- **The Problem:** Even with encryption active, *how* the VPN is configured determines its real-world security strength.

**Why It Matters:**
- Weak encryption algorithms (e.g., 3DES, DES) = easy to break
- Weak Diffie-Hellman groups (e.g., Group 1, 2, 5) = vulnerable to Logjam attack
- Legacy IKEv1 = susceptible to aggressive-mode dictionary attacks
- Organizations need automated tools to detect these weaknesses from captured traffic

---

## SLIDE 4 — Problem Statement

**Heading:** The Problem We're Solving

**Official Problem Statement (SIH 2616):**
> *"Develop an AI-powered tool to analyze IPsec VPN traffic from PCAP files, identify protocol characteristics, evaluate cryptographic configurations, and generate security assessment reports."*
> — National Technical Research Organisation (NTRO)

**Key Challenges:**
1. **Manual Analysis is Complex** — Traditional packet tools (like Wireshark) require deep expert knowledge to interpret IPsec parameters
2. **Hidden Weaknesses** — Weak encryption or deprecated algorithms are not obvious without parsing IKE negotiation packets
3. **No Automated Reporting** — Security analysts must manually identify and document risks
4. **Traffic Type is Unknown** — Even with VPN active, the *type* of traffic (VOIP, Streaming, C2, etc.) inside the tunnel is unclear
5. **Scale Problem** — Manually analyzing hundreds of PCAP files is time-consuming and error-prone

**Bottom Line:**
> There is no existing open-source tool that combines **packet analysis + automated security assessment + ML-based traffic classification** in a single platform.

---

## SLIDE 5 — Objectives

**Heading:** Project Objectives

**Primary Objectives:**
1. ✅ Accept and validate PCAP/PCAPNG files containing IPsec VPN traffic
2. ✅ Automatically detect IKE version (IKEv1 / IKEv2) from captured packets
3. ✅ Extract cryptographic parameters:
   - Encryption algorithm (e.g., AES-GCM-16, 3DES-CBC)
   - Authentication method (e.g., RSA Signatures, PSK)
   - Diffie-Hellman Group (e.g., Group 19 ECP-256)
4. ✅ Evaluate parameters against a rule-based security engine to generate a **Risk Score**
5. ✅ Classify the type of traffic inside the VPN tunnel using **Machine Learning**
6. ✅ Present results in an interactive, user-friendly **web dashboard**
7. ✅ Generate downloadable **security reports** (PDF)

**Secondary Objectives:**
- Provide evidence-based findings (not assumptions)
- Clearly distinguish "not extracted" vs "insecure" parameters
- Support both Windows and Linux/cloud deployments

---

## SLIDE 6 — Existing System / Literature Review

**Heading:** Existing Tools & Their Limitations

| Tool / Method | What It Does | Limitation |
|---|---|---|
| **Wireshark** | Deep packet inspection, manual analysis | Requires expert knowledge; no automated assessment |
| **tcpdump** | Capture and display packets | CLI only; no security evaluation |
| **OpenVPN / strongSwan logs** | VPN configuration logs | No PCAP analysis; no ML |
| **Zeek (Bro IDS)** | Network monitoring and logging | Does not assess IPsec crypto strength |
| **Manual Pentesting** | Expert-led security review | Expensive, slow, not scalable |
| **Commercial SIEMs** | Enterprise-level monitoring | Very costly; overkill for targeted VPN analysis |

**Gap Identified:**
> No existing tool provides **automated IPsec crypto assessment + ML traffic classification + evidence-based reporting** in a single accessible platform.

**Our Novel Contribution:**
- Dual-engine approach: Static security analysis **+** ML-based traffic classification
- Evidence-based findings: Only flags issues from *actually observed* packets
- Honest uncertainty: Marks parameters as "Not Extracted" instead of fabricating results
- Open-source, deployable on cloud (Render) and local systems

---

## SLIDE 7 — Proposed Solution

**Heading:** Our Solution — Dual-Engine IPsec Analyzer

**System Overview:**
> An AI-powered web platform that accepts PCAP files, extracts IPsec parameters using deep packet inspection, evaluates security using configurable rules, classifies traffic using ML, and presents results in an interactive dashboard.

**Two Analysis Engines:**

### 🔍 Engine A: Static IPsec Security Analysis
- Parses IKE and ESP packets from PCAP
- Extracts: IKE Version, Encryption Algorithm, DH Group, Auth Method, VPN Mode
- Runs rule-based security checks
- Generates: Risk Score (0–10+), Risk Level (High/Medium/Low/Informational), Findings with recommendations

### 🤖 Engine B: ML Traffic Classification
- Uses flow-level features from ESP packets (Inter-Arrival Times, byte counts, packet counts)
- Trained on **MIT Lincoln Laboratory VNAT Dataset** (15,093 samples)
- Classifies traffic into: **C2 (Command & Control), CHAT, FILE_TRANSFER, STREAMING, VOIP**
- Reports confidence score (e.g., 94.7%)
- Model: **RandomForestClassifier (200 trees)** — Test Accuracy: **98.48%**

**Key Design Principle:**
> *"Only report what is observed. Never fabricate missing data."*

---

## SLIDE 8 — Methodology / Workflow

**Heading:** System Architecture & Workflow

### System Architecture:
```
User (Browser)
     │
     ▼
Frontend (React + Vite + Tailwind CSS)
     │  PCAP Upload
     ▼
Backend REST API (FastAPI — Python)
     │
     ├──► Packet Analyzer (PyShark + TShark subprocess)
     │         │
     │         ├── Extract: IKE version, Encryption, DH Group, Auth
     │         ├── Extract: Flow features (IAT stats, byte counts)
     │         └── Extract: Packet forensics (src/dst, SPI, timestamps)
     │
     ├──► Security Rules Engine (security_rules.py)
     │         └── Evaluate: Risk Score, Risk Level, Findings
     │
     └──► ML Classifier (ml_model.py — RandomForest)
               └── Predict: Traffic Category + Confidence Score
     │
     ▼
Results → Dashboard (Charts, Findings, Forensics Table)
     │
     ▼
PDF Report Generation
```

### Step-by-Step Workflow:
1. **Upload** — User uploads PCAP/PCAPNG file via web UI
2. **Validate** — Backend validates file format and size
3. **Parse** — PyShark + TShark extract packet-level data
4. **Extract Features** — IKE params extracted; flow stats computed per packet
5. **Security Analysis** — Rules engine evaluates crypto parameters → Risk Score
6. **ML Inference** — RandomForest classifier predicts traffic category
7. **Dashboard** — Results displayed with charts, tables, risk level badge
8. **Report** — User downloads PDF with full findings

### TShark Auto-Discovery:
- Priority: `TSHARK_PATH` env var → System PATH → Common Windows paths → Common Linux paths
- Dual extraction: PyShark layer access + TShark `-T fields` subprocess fallback

### Database:
- **SQLite** (default) — automatic fallback for local/cloud deployments without PostgreSQL
- **PostgreSQL** — production option for persistent history and multi-user support
- Analysis history stored: filename, timestamp, risk score, IKE version, traffic category

---

## SLIDE 9 — Technologies / Tools Used

**Heading:** Technology Stack

### Frontend:
| Technology | Purpose |
|---|---|
| **React.js + Vite** | Modern, fast frontend framework |
| **Tailwind CSS** | Utility-first CSS for responsive UI |
| **Recharts** | Charts for risk scores, packet distributions |
| **Axios** | HTTP client for API communication |

### Backend:
| Technology | Purpose |
|---|---|
| **Python 3.8+** | Core programming language |
| **FastAPI** | High-performance REST API framework |
| **PyShark** | Python wrapper for TShark packet analysis |
| **TShark (Wireshark)** | Deep packet inspection engine |

### Machine Learning:
| Technology | Purpose |
|---|---|
| **scikit-learn** | RandomForestClassifier (200 trees) |
| **NumPy + Pandas** | Feature engineering and data handling |
| **joblib** | Model serialization/loading |
| **VNAT Dataset (MIT LL)** | Training dataset (15,093 samples, 5 classes) |

### Database & Infrastructure:
| Technology | Purpose |
|---|---|
| **SQLite** | Default local database (auto-fallback) |
| **PostgreSQL** | Production database option |
| **SQLAlchemy** | ORM for database operations |
| **Docker** | Containerized deployment |
| **Render** | Cloud deployment platform |

### Key Design Decisions:
- **PyShark + TShark fallback**: PyShark for primary parsing; subprocess TShark `-T fields` as backup when PyShark can't extract crypto parameters
- **Thread pool isolation**: PyShark runs in a separate thread pool to avoid blocking Uvicorn's async event loop
- **SQLite auto-fallback**: If PostgreSQL is unavailable, system automatically falls back to SQLite — zero configuration required

---

## SLIDE 10 — Results / Key Features

**Heading:** What the System Produces

### Security Analysis Output:
- **Risk Score**: Numeric (0 = no risk observed, higher = more issues found)
- **Risk Level**: High / Medium / Low / Informational
- **Findings with Evidence**: Each finding includes:
  - Title & Description
  - Severity (High / Medium / Low / Informational)
  - Supporting Evidence from packet data
  - Recommended Mitigation

### Security Rules Implemented:
| Rule | What It Checks |
|---|---|
| IKE Version Check | IKEv1 (risk +2) vs IKEv2 (pass) |
| Encryption Algorithm | Weak: DES/3DES/NULL (risk +3); Strong: AES-GCM/ChaCha20 (pass) |
| DH Group Strength | Weak: Group 1,2,5 (risk +3); Strong: Group 14,19,20,21 (pass) |
| Authentication Method | PSK (risk +1); RSA/ECDSA (pass) |
| ESP Protection | Checks if encrypted data flow is present |

### ML Classification Output:
- **Predicted Category**: C2 / CHAT / FILE_TRANSFER / STREAMING / VOIP
- **Confidence Score**: e.g., 98.2%
- **All Class Probabilities**: Full probability breakdown across all 5 classes
- **Short-Capture Warning**: Automatically warns if < 50 packets (low IAT reliability)

### Packet Forensics Table:
- Up to 150 packets displayed: src/dst IP, protocol, length, ESP SPI, IKE exchange type

---

## SLIDE 11 — Challenges & How We Solved Them

**Heading:** Key Challenges & Solutions

| Challenge | Our Solution |
|---|---|
| PyShark conflicting with Uvicorn's event loop | Ran PyShark in an isolated thread pool (`ThreadPoolExecutor`) with its own `asyncio` loop |
| TShark not finding crypto fields via PyShark attributes | Added TShark subprocess `-T fields` fallback — two-layer extraction |
| No PostgreSQL on free cloud tier | Implemented automatic SQLite fallback in `database.py` |
| ML model accuracy on short captures | Added short-capture detection (< 50 pkts) and confidence warnings |
| IKEv1 vs IKEv2 detection reliability | Used both version byte (high nibble) AND exchange type number for detection |
| Frontend build failures on Render | Moved `react-pdf` and other build tools from `devDependencies` to `dependencies` |
| Render Blueprint YAML errors | Fixed `staticPublishPath` (not `publishDir`), removed invalid `plan: free` field |

---

## SLIDE 12 — Conclusion & Future Scope

**Heading:** Conclusion & Future Scope

### Conclusion:
- Successfully built a **dual-engine IPsec VPN analysis platform** combining:
  - Rule-based static security assessment
  - ML-powered traffic classification (98.48% accuracy)
- The tool provides **evidence-based, honest security findings** — never fabricates data
- Deployed on cloud (Render) and works locally (Windows + Linux)
- Addresses **SIH Problem 2616** by NTRO — providing automated, accessible VPN security analysis

### What We Achieved:
- ✅ PCAP/PCAPNG upload and real packet analysis (not simulated)
- ✅ Automated IKEv1/IKEv2 detection
- ✅ Crypto parameter extraction (Encryption, DH Group, Auth Method)
- ✅ Risk scoring with explainable findings
- ✅ ML traffic classification using real VNAT dataset
- ✅ Interactive web dashboard with charts and forensics table
- ✅ SQLite/PostgreSQL database with analysis history
- ✅ Cloud-deployed via Docker + Render

### Future Scope:
1. **Live Traffic Capture** — Real-time analysis of network interfaces (not just uploaded files)
2. **IKEv2 MOBIKE Support** — Mobile IKEv2 protocol support for mobile VPN analysis
3. **PDF Report Generation** — Downloadable executive + technical reports (ReportLab)
4. **Multi-user Authentication** — Role-based access control for SOC teams
5. **VPN vs Non-VPN Binary Classification** — Requires 32 GB VNAT PCAP archive (not currently downloaded)
6. **SIEM Integration** — Export findings to Splunk, Elastic SIEM
7. **Larger Dataset** — Fine-tune ML model with organization-specific traffic patterns
8. **AH Protocol Support** — Authentication Header analysis (currently only IKE + ESP)

---

## SLIDE 13 — References

**Heading:** References

1. **RFC 7296** — Internet Key Exchange Protocol Version 2 (IKEv2), Kaufman et al., 2014
2. **RFC 4301** — Security Architecture for the Internet Protocol (IPsec), Kent & Seo, 2005
3. **RFC 2409** — The Internet Key Exchange (IKEv1), Harkins & Carrel, 1998
4. **VNAT Dataset** — MIT Lincoln Laboratory, "VPN/Non-VPN Network Application Traffic Dataset", https://archive.ll.mit.edu/datasets/vnat/
5. **PyShark** — Python wrapper for TShark, https://github.com/KimiNewt/pyshark
6. **scikit-learn** — Pedregosa et al., "Scikit-learn: Machine Learning in Python", JMLR, 2011
7. **FastAPI** — Sebastián Ramírez, https://fastapi.tiangolo.com/
8. **Logjam Attack** — Adrian et al., "Imperfect Forward Secrecy: How Diffie-Hellman Fails in Practice", CCS 2015
9. **SIH 2026 Problem Statement 2616** — National Technical Research Organisation (NTRO), Smart India Hackathon 2026

---

## 📝 SPEAKER NOTES (Short Summary per Slide)

**Slide 3 (Intro):** IPsec ka basic concept explain karo — IKE negotiates keys, ESP encrypts data. IKEv1 old hai, IKEv2 modern.

**Slide 4 (Problem):** Manual Wireshark analysis expert chahiye. Automated tool nahi tha jo crypto weakness + ML dono kare.

**Slide 5 (Objectives):** 7 main goals — detection, extraction, evaluation, classification, dashboard, reporting.

**Slide 6 (Existing):** Wireshark manual hai, Zeek IPsec crypto check nahi karta, commercial tools costly hain. Humne gap fill kiya.

**Slide 7 (Solution):** Do engine — Engine A security rules check karta hai, Engine B ML se traffic type predict karta hai.

**Slide 8 (Methodology):** Upload → Parse → Extract → Rules → ML → Dashboard → Report. TShark auto-discover karta hai paths.

**Slide 9 (Tech Stack):** React frontend, FastAPI backend, PyShark+TShark parsing, RandomForest ML, SQLite fallback, Docker deployment.

**Slide 10 (Results):** Risk score 0-10+, findings with evidence, ML 98.48% accuracy, packet forensics table upto 150 packets.

**Slide 11 (Challenges):** Event loop conflict solve kiya ThreadPool se, TShark fallback add kiya, SQLite fallback add kiya.

**Slide 12 (Conclusion):** Real packet analysis, honest findings, cloud deployed. Future: live capture, PDF reports, SIEM integration.

---
*End of PPT Content*
