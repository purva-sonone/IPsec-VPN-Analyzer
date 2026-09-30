# Product Requirements Document (PRD)

## AI-Powered IPsec VPN Protocol Analyzer and Security Assessment Framework

**SIH Problem Statement:** 2616\
**Organization:** National Technical Research Organisation (NTRO)\
**Category / Theme:** Software / Blockchain & Cybersecurity\
**Version:** 1.0 --- September 2026\
**Target Users:** Cybersecurity analysts, network administrators,
security researchers

------------------------------------------------------------------------

## 1. Product Overview

### 1.1 Product Summary

The AI-Powered IPsec VPN Protocol Analyzer is a cybersecurity platform
that analyzes IPsec VPN traffic from captured files or authorized live
monitoring. It identifies observable protocol characteristics, infers
VPN modes where evidence permits, evaluates available cryptographic and
Security Association (SA) parameters, and generates security findings
and reports.

### 1.2 Problem Statement

IPsec security depends on correct encryption, authentication, key
exchange, and operational settings. Traditional packet tools provide
detailed data but often require expert interpretation. This product aims
to simplify analysis through automated protocol identification, security
checks, and explainable reporting.

### 1.3 Product Vision

Transform complex IPsec VPN traffic into understandable, evidence-based
security insights through packet analysis, AI-assisted classification,
and automated security checks.

## 2. Product Objectives

-   Identify IPsec traffic and IKE versions from available packet
    evidence.
-   Analyze VPN configurations and infer Tunnel Mode or Transport Mode
    where supported by evidence.
-   Evaluate cryptographic algorithms, Security Associations, and other
    observable parameters.
-   Identify potential misconfigurations and security weaknesses using
    configurable rules.
-   Predict broad traffic categories inside ESP using observable
    metadata and labeled datasets.
-   Present risk scores, AI confidence scores, a threat matrix, and
    downloadable reports.
-   Reduce manual packet inspection while preserving transparency about
    uncertainty.

## 3. Target Users

  -----------------------------------------------------------------------
  User                                Primary Need
  ----------------------------------- -----------------------------------
  Cybersecurity Analyst               Identify security risks, weak
                                      configurations, and supporting
                                      evidence.

  Network Administrator               Review VPN settings and
                                      troubleshoot configuration
                                      concerns.

  Security Researcher                 Analyze IPsec traffic and compare
                                      controlled VPN configurations.

  SOC Analyst                         Understand VPN-related activity and
                                      support investigations.

  Student / Research Team             Experiment with VPN testbeds,
                                      datasets, and ML models.
  -----------------------------------------------------------------------

## 4. Product Scope

### 4.1 In Scope

-   PCAP/PCAPNG upload and analysis; authorized live traffic capture.
-   IKE and ESP identification; optional AH analysis.
-   IKEv1/IKEv2 identification where observable.
-   VPN mode inference using packet and configuration evidence.
-   Cryptographic and SA parameter analysis, plus rule-based security
    assessment.
-   ML-based traffic classification, interactive dashboard, and PDF
    report generation.
-   Controlled VPN testbed and labeled dataset generation.

### 4.2 Out of Scope for the Initial MVP

-   Decrypting IPsec traffic without authorized access to the required
    keys.
-   Breaking encryption or recovering cryptographic keys.
-   Guaranteeing detection of every VPN vulnerability.
-   Automatically modifying production VPN configurations.
-   Identifying exact application content inside encrypted ESP traffic
    in all cases.
-   Replacing professional penetration testing or an enterprise SIEM.

> **Key limitation:** Some algorithms, authentication methods, and
> key-exchange parameters may not be visible in a packet capture. The
> system must distinguish observed facts from inferred or unavailable
> values and must not claim to recover hidden information from encrypted
> traffic.

## 5. Functional Requirements

### FR-01 --- User Authentication and Dashboard

-   Provide a login interface and role-appropriate access.
-   Display analyzed captures, key findings, and summary risk
    information.
-   Allow users to start an analysis and review previous results.
-   Support filtering by severity and protocol.

### FR-02 --- VPN Testbed Generation

Provide a controlled lab environment to generate labeled IPsec traffic
under multiple configurations.

  -----------------------------------------------------------------------
  Configuration Area                  Required Variations
  ----------------------------------- -----------------------------------
  VPN Mode                            Tunnel Mode; Transport Mode

  Encryption                          AES-128; AES-256

  Cipher Suites                       AES-GCM; AES-CBC + HMAC

  Key Exchange                        Different supported DH groups

  Forward Secrecy                     PFS enabled / disabled

  IP Version                          IPv4; IPv6

  Traffic Categories                  Web, ICMP, email, VoIP, video,
                                      messaging-like traffic
  -----------------------------------------------------------------------

### FR-03 --- Traffic Capture and Upload

-   Accept PCAP and PCAPNG files and validate them before processing.
-   Capture IKE negotiation and ESP packets; support optional AH
    analysis.
-   Display capture duration, packet count, and file details.
-   Allow authorized users to select and stop live capture.
-   Show clear errors for unsupported, corrupted, or oversized files.

### FR-04 --- AI-Based Protocol Identification

  Attribute                     Expected Output
  ----------------------------- -----------------------------------------------------
  IPsec Protocol                ESP, AH, IKE-related traffic, or unknown
  IKE Version                   IKEv1, IKEv2, or unknown where evidence supports it
  VPN Mode                      Tunnel, Transport, uncertain, or unavailable
  Encryption / Authentication   Identified, inferred, or unavailable
  Key Exchange                  Observable DH group or other available parameters
  Security Association          Available SA attributes
  Traffic Type                  Predicted category with confidence score

### FR-05 --- AI-Based Traffic Classification

Predict broad traffic categories carried within ESP using observable
metadata and labeled testbed data. Candidate classes include web
browsing, VoIP, email, video streaming, ICMP, messaging-like traffic,
and Unknown/Other.

Potential features include packet size, timing, flow duration,
direction, and packet frequency. The model must expose confidence and
allow an Unknown result when confidence is low.

### FR-06 --- Automated Security Assessment

  -----------------------------------------------------------------------
  Assessment Area                     Evaluation
  ----------------------------------- -----------------------------------
  Cryptographic Strength              Flag weak or deprecated algorithms
                                      against configured policy.

  Configuration Compliance            Compare available evidence with
                                      defined security rules.

  Security Associations               Review observable SA attributes.

  Key Lifetime                        Assess configured lifetime when
                                      available.

  Replay Protection                   Check available configuration or SA
                                      evidence.

  Perfect Forward Secrecy             Evaluate from observable or
                                      supplied configuration.

  Cipher Suite                        Identify weak or unsuitable
                                      combinations.

  Metadata Exposure                   Assess visible metadata and
                                      traffic-pattern leakage.
  -----------------------------------------------------------------------

Each finding should include a title, description, severity, supporting
evidence, recommended mitigation, and confidence/evidence availability.
Unavailable parameters must not be treated as confirmed vulnerabilities.

### FR-07 --- Risk Scoring and Threat Matrix

  Risk Level      Meaning
  --------------- ----------------------------------------------------
  Critical        Severe security concern requiring urgent review.
  High            Significant security weakness.
  Medium          Moderate security concern.
  Low             Limited security concern.
  Informational   Observation without a confirmed security weakness.

The risk score must be explainable, based on configurable assessment
rules, and accompanied by a factor breakdown. It must not be presented
as a guarantee that a VPN is secure.

### FR-08 --- Automated Report Generation

  -----------------------------------------------------------------------
  Executive Report                    Technical Report
  ----------------------------------- -----------------------------------
  Overall score and risk level        Protocol identification results

  Key findings and posture summary    IKE, ESP, and SA observations

  Recommended actions                 Cryptographic assessment

  Readable for non-technical          Traffic classification, evidence,
  stakeholders                        confidence, findings, and
                                      mitigations
  -----------------------------------------------------------------------

Reports shall be downloadable in PDF format.

## 6. Non-Functional Requirements

  -----------------------------------------------------------------------
  Requirement                         Description
  ----------------------------------- -----------------------------------
  Performance                         Process captures efficiently and
                                      provide progress feedback.

  Accuracy                            Evaluate model performance using
                                      labeled test data.

  Security                            Protect uploaded captures and
                                      restrict unauthorized access.

  Scalability                         Support increasing capture sizes
                                      and analysis workloads.

  Usability                           Keep the interface understandable
                                      for non-expert users.

  Reliability                         Handle invalid files and failed
                                      analysis gracefully.

  Explainability                      Show evidence and reasoning behind
                                      findings.

  Privacy                             Avoid unnecessary exposure of
                                      sensitive packet data in reports.

  Maintainability                     Keep capture, analysis, AI, and
                                      reporting modules separate.
  -----------------------------------------------------------------------

## 7. Proposed Technical Architecture

  -----------------------------------------------------------------------
  Layer                               Proposed Components /
                                      Responsibility
  ----------------------------------- -----------------------------------
  Frontend                            React.js, Tailwind CSS, Recharts
                                      --- dashboard, upload,
                                      visualizations, reports.

  Backend API                         Python + FastAPI ---
                                      authentication, validation,
                                      orchestration.

  Packet Analysis                     TShark, PyShark, Scapy --- parsing
                                      and feature extraction.

  VPN Testbed                         strongSwan on Linux --- controlled
                                      IPsec configurations and traffic
                                      generation.

  AI/ML                               Scikit-learn, Pandas, NumPy ---
                                      classification and evaluation.

  Data Management                     SQLite for MVP; PostgreSQL for
                                      expansion; controlled PCAP storage.

  Reporting                           ReportLab --- executive and
                                      technical PDF generation.

  Deployment                          Docker and Linux, depending on team
                                      environment.
  -----------------------------------------------------------------------

These are proposed technologies, not mandatory dependencies. The team
may substitute tools based on feasibility and available resources.

## 8. User Workflow

1.  **Start:** User logs in and starts a new analysis.
2.  **Input:** Upload a PCAP/PCAPNG file or begin authorized capture.
3.  **Extract:** System extracts IKE, ESP, SA, and traffic metadata.
4.  **Analyze:** AI predicts traffic categories; rules assess available
    security parameters.
5.  **Review:** Dashboard displays protocol details, confidence, risk,
    and findings.
6.  **Report:** User downloads an executive or technical PDF report.

## 9. MVP --- Minimum Viable Product

The MVP should include: - PCAP/PCAPNG upload and analysis. - IKE and ESP
identification with observable parameter extraction. - VPN mode
inference when evidence supports it. - Rule-based security assessment
and explainable findings. - Baseline ML traffic classifier with
evaluation metrics. - React dashboard with risk and confidence
visualization. - PDF report generation and testing against labeled
testbed captures.

> **MVP priority:** Build reliable offline capture analysis, security
> checks, and reporting first. Add live capture and more advanced ML
> capabilities after the offline workflow is stable.

## 10. Acceptance Criteria

  -----------------------------------------------------------------------
  ID                                  Acceptance Criterion
  ----------------------------------- -----------------------------------
  AC-01                               Valid PCAP/PCAPNG files are
                                      accepted; invalid files produce
                                      clear errors.

  AC-02                               Supported IKE and ESP traffic is
                                      identified in test captures.

  AC-03                               Supported attributes are extracted;
                                      unavailable values are marked
                                      appropriately.

  AC-04                               VPN mode inference is validated
                                      against known testbed
                                      configurations.

  AC-05                               Findings include severity,
                                      evidence, and recommendations.

  AC-06                               ML is evaluated on held-out labeled
                                      data, with metrics displayed.

  AC-07                               Dashboard displays analysis results
                                      and risk information.

  AC-08                               Executive and technical PDF reports
                                      can be downloaded.

  AC-09                               End-to-end workflow is demonstrated
                                      across multiple VPN configurations.
  -----------------------------------------------------------------------

## 11. Success Metrics

These are proposed evaluation metrics, not achieved results.

  -----------------------------------------------------------------------
  Metric                              Measurement
  ----------------------------------- -----------------------------------
  Protocol Identification             Precision, recall, and F1-score.

  VPN Mode Inference                  Accuracy on labeled testbed
                                      captures.

  Traffic Classification              Macro F1-score across traffic
                                      classes.

  Security Assessment                 Correctness against predefined test
                                      cases.

  AI Confidence                       Calibration and confidence versus
                                      observed performance.

  Processing Performance              Analysis time per capture.

  Report Generation                   Successful report generation rate.
  -----------------------------------------------------------------------

All numerical targets should be set after collecting a representative
dataset and running baseline experiments.

## 12. Risks and Mitigation

  -----------------------------------------------------------------------
  Risk                                Mitigation
  ----------------------------------- -----------------------------------
  Encrypted payload limits visibility Use metadata and negotiation
                                      evidence; clearly mark uncertainty.

  Insufficient training data          Generate labeled traffic using the
                                      VPN testbed.

  Incorrect AI predictions            Use confidence thresholds and an
                                      Unknown class.

  False-positive findings             Use evidence-based, configurable
                                      rules.

  Large PCAP files                    Set file limits and use
                                      streaming/progress feedback.

  Live capture permissions            Require authorized access and
                                      explicit interface selection.

  Sensitive network information       Apply access controls, secure
                                      storage, and retention policies.
  -----------------------------------------------------------------------

## 13. Development Roadmap

  -----------------------------------------------------------------------
  Phase                               Work Items
  ----------------------------------- -----------------------------------
  1\. Research & Requirements         Finalize scope, define rules,
                                      select tools, prepare environment.

  2\. Testbed & Dataset               Set up strongSwan, configure VPN
                                      modes, generate labeled traffic and
                                      PCAPs.

  3\. Analysis Engine                 Implement packet parsing, protocol
                                      identification, security checks,
                                      and ML.

  4\. Dashboard & Reports             Build React UI, API integration,
                                      visualizations, and PDF generation.

  5\. Testing & Demo                  Validate findings, measure model
                                      performance, document, and record
                                      demo.
  -----------------------------------------------------------------------

## 14. Expected Deliverables

-   Working AI-powered IPsec VPN Analyzer software prototype.
-   AI-based protocol identification and traffic classification engine.
-   IPsec VPN testbed with multiple security configurations.
-   Labeled dataset for training and testing.
-   Interactive cybersecurity dashboard.
-   Automated security assessment and risk scoring module.
-   Executive and technical PDF reports.
-   Demonstration video, technical documentation, and test results.

## 15. Final Product Outcome

The final product will provide a centralized platform for analyzing
IPsec VPN traffic and assessing its observable security posture. By
combining packet analysis, AI-based classification, and configurable
security rules, it will help analysts understand VPN configurations,
identify potential weaknesses, and generate actionable reports.

The system is intended to support security decision-making while clearly
communicating the limits of encrypted traffic inspection and AI-based
inference.

------------------------------------------------------------------------

*End of Product Requirements Document*
