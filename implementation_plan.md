# Implementation Plan: AI-Powered IPsec VPN Protocol Analyzer MVP

This plan outlines the architecture and development phases for building a beginner-friendly Minimum Viable Product (MVP) of the AI-Powered IPsec VPN Protocol Analyzer, as specified in the PRD. The MVP focuses on offline PCAP/PCAPNG upload, traffic analysis, security assessment, and basic ML classification.

## Goal Description

Build a full-stack web application (React + Vite frontend, FastAPI + Python backend) that allows users to upload IPsec VPN packet captures (PCAP/PCAPNG), parses them using TShark/PyShark, evaluates cryptographic configurations, applies a machine learning model (Scikit-learn) to predict encapsulated traffic types, and presents explainable security findings and downloadable PDF reports.

## Open Questions

> [!WARNING]
> Please review and confirm the following before we begin execution:
> 1. **Testing Data:** Do you already have sample PCAP/PCAPNG files with IKE/ESP traffic that we can use for initial testing, or should we prioritize setting up the strongSwan testbed first to generate them?
> 2. **ML Model:** For the MVP, should we train a basic mock ML classifier initially to unblock the frontend and API integration, and replace it with a properly trained Scikit-learn model later?
> 3. **Database:** The PRD mentions SQLite for the MVP. Is it acceptable to store uploaded PCAPs temporarily on the local filesystem during analysis, or do you require a specific storage mechanism?

## IPsec Attributes Visibility

Based on the limitations of analyzing encrypted traffic without keys, here is a breakdown of what can be observed vs. inferred:

> [!TIP]
> **Observable Attributes (from IKE and ESP/AH Headers):**
> - **IPsec Protocol:** IKE (UDP 500/4500), ESP (Protocol 50), AH (Protocol 51).
> - **IKE Version:** IKEv1, IKEv2 (from IKE Header).
> - **Security Association (SA) Parameters:** SPIs (Security Parameter Indices), Lifetimes (from IKE negotiation).
> - **Cryptographic Algorithms:** Proposed/Accepted Encryption (AES, etc.), Hash/Auth (SHA256, etc.), and DH Groups (visible if IKE initialization is captured).
> - **Traffic Metadata:** Packet size, arrival time, flow direction, inter-arrival time.

> [!NOTE]
> **Inferred Attributes:**
> - **VPN Mode (Tunnel vs. Transport):** Can be inferred from IP header encapsulation and NAT-T presence (UDP 4500).
> - **Traffic Type inside ESP:** Inferred using Machine Learning (Scikit-learn) based on flow characteristics (packet size, frequency, timing).

> [!CAUTION]
> **Unavailable/Hidden Attributes:**
> - Actual application content and payload data.
> - Decrypted cryptographic keys.
> - Certain Child SA parameters negotiated after the initial IKE encryption phase.

## Proposed Architecture & Folder Structure

We will use a monorepo structure containing both frontend and backend.

```text
IPsec-VPN-Analyzer/
├── backend/
│   ├── main.py                 # FastAPI application entry point
│   ├── api/
│   │   └── routes.py           # API endpoints (upload, analysis, report)
│   ├── core/
│   │   ├── analyzer.py         # PyShark PCAP parsing logic
│   │   ├── ml_model.py         # Scikit-learn prediction logic
│   │   └── security_rules.py   # Rule-based assessment logic
│   ├── models/
│   │   └── schemas.py          # Pydantic models for API responses
│   ├── utils/
│   │   └── report_gen.py       # PDF generation (ReportLab)
│   ├── data/                   # Uploaded PCAPs and SQLite DB
│   └── requirements.txt        # Python dependencies
├── frontend/
│   ├── index.html
│   ├── package.json            # Vite + React + Tailwind dependencies
│   ├── src/
│   │   ├── main.jsx
│   │   ├── App.jsx             # Main routing and layout
│   │   ├── components/         # Reusable UI components (Cards, Tables, Badges)
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx   # Main view, recent analyses
│   │   │   ├── Upload.jsx      # Drag-and-drop PCAP upload
│   │   │   └── Results.jsx     # Detailed analysis results and visualizations
│   │   └── services/
│   │       └── api.js          # Axios calls to FastAPI backend
│   ├── tailwind.config.js
│   └── index.css
└── README.md
```

## Dependencies

### Backend (Python)
- `fastapi`, `uvicorn` (Web API)
- `python-multipart` (File uploads)
- `pyshark` (Packet analysis via TShark)
- `scikit-learn`, `pandas`, `numpy` (ML classification)
- `reportlab` (PDF generation)
- `sqlalchemy` (SQLite ORM)

### Frontend (React/Node)
- `react`, `react-dom`
- `vite`
- `tailwindcss`, `postcss`, `autoprefixer` (Styling)
- `recharts` (Data visualization, charts)
- `lucide-react` (Icons)
- `axios` (API requests)
- `react-router-dom` (Navigation)

## API Endpoints

- `POST /api/upload`: Uploads a PCAP/PCAPNG file, triggers analysis, and returns a job ID or direct analysis summary.
- `GET /api/analysis/{analysis_id}`: Retrieves detailed results of a specific analysis (protocols, security findings, ML predictions).
- `GET /api/analyses`: Lists all historical analyses.
- `GET /api/report/{analysis_id}`: Generates and downloads the PDF report.

## Data Flow

1. **Upload:** User uploads a `.pcap` file via the React frontend.
2. **Receive & Store:** FastAPI receives the file and saves it temporarily in the `backend/data` folder.
3. **Parse (PyShark):** `analyzer.py` reads the file, extracting IKE and ESP packets, SA parameters, and flow metadata.
4. **Assess & Predict:**
   - `security_rules.py` evaluates extracted algorithms against best practices (e.g., flags DES/3DES as weak, AES-GCM as strong).
   - `ml_model.py` feeds packet metadata (size/timing) into a pre-trained Scikit-learn model to predict traffic type.
5. **Aggregate:** Backend compiles results, risk scores, and findings into a JSON response.
6. **Visualize:** React frontend displays the findings using Recharts and Tailwind-styled components.
7. **Report:** User clicks "Download Report", backend generates a PDF via `reportlab` and streams it to the client.

## Development Phases

### Phase 1: Foundation & Infrastructure
- Set up the Git repository.
- Initialize the Vite React frontend with Tailwind CSS.
- Initialize the FastAPI backend.
- Establish basic CORS and API connectivity.

### Phase 2: Packet Parsing Core (Backend)
- Implement file upload endpoint.
- Integrate PyShark for reading PCAPs.
- Extract basic IPsec metrics (packet counts, IKE versions, encryption algorithms).

### Phase 3: Security & ML Logic (Backend)
- Implement rule-based security assessment (flagging weak algorithms).
- Train/Mock the Scikit-learn model for traffic classification.
- Integrate ML predictions into the analysis pipeline.

### Phase 4: Dashboard & Visualization (Frontend)
- Build the Upload view with drag-and-drop.
- Build the Results Dashboard (charts, finding lists, threat matrix).
- Implement a premium, modern design with dark/light mode considerations and micro-animations.

### Phase 5: Reporting & Polish
- Implement PDF generation using ReportLab.
- End-to-end testing with sample PCAPs.
- Final UI polish and documentation.
