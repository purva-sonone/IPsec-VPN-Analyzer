# IPsec-VPN-Analyzer

IPsec-VPN-Analyzer is a dual-engine analysis tool designed to inspect PCAP/PCAPNG files containing IPsec VPN traffic. It performs both **Static IPsec Security Analysis** and **Machine Learning Traffic Category Classification**.

## Project Purpose
The purpose of this tool is to help network administrators and security researchers quickly evaluate the cryptographic strength of IPsec negotiations (IKEv1/IKEv2) and use machine learning to infer the category of the encrypted traffic inside the tunnel.

## Architecture
- **Frontend**: React application built with Vite and Tailwind CSS. Provides an interactive UI for PCAP upload and result visualization.
- **Backend**: FastAPI application serving a REST API.
- **Static Analysis Engine**: Uses PyShark (with TShark fallback) to extract IKE and ESP parameters, evaluate them against a security rules engine, and calculate a risk score.
- **ML Engine**: Uses a trained RandomForestClassifier (scikit-learn) to classify the traffic category based on flow-level characteristics.

## Prerequisites
- **Python 3.8+**
- **Node.js** (for frontend)
- **Wireshark / TShark**: You MUST have Wireshark or TShark installed and available in your system's PATH. This is required by PyShark for deep packet inspection.

## How to Start the Project

### 1. Start the Backend
```bash
cd backend
pip install -r requirements.txt
python main.py
```
The backend will run on `http://localhost:8000`.

### 2. Start the Frontend
In a new terminal:
```bash
cd frontend
npm install
npm run dev
```
The frontend will run on `http://localhost:5173`.

## PCAP Upload Workflow
1. Open the frontend in your browser.
2. Drag and drop or browse to select a `.pcap` or `.pcapng` file.
3. Click "Upload & Analyze".
4. The backend will parse the PCAP, extract cryptographic parameters, run the security rules, extract flow features, and run ML inference.
5. The results will be displayed in the UI.

## Engine A: Static IPsec Analysis
The static analyzer inspects the PCAP for IKE (Internet Key Exchange) and ESP (Encapsulating Security Payload) packets. It extracts:
- IKE Version (IKEv1 / IKEv2)
- Encryption Algorithm (e.g., AES-GCM-16, 3DES-CBC)
- Authentication Method (e.g., RSA Signatures)
- Diffie-Hellman Group (e.g., Group 19)

**Security Rules:**
The extracted parameters are evaluated against a security rules engine to generate a risk score. Legacy protocols (IKEv1) and weak algorithms (e.g., 3DES, DH Group 1, 2, 5) contribute to a higher risk score. A score of 0 indicates that no high-risk values were found in the observable data. 

*Note: Missing parameters (e.g., if the capture lacks the IKE_AUTH payload) are marked as "Not Extracted" and skipped by the rule engine rather than fabricated.*

## Engine B: ML Traffic Classification
The tool includes a trained Machine Learning model to classify the type of traffic flowing through the VPN. 

**IMPORTANT LIMITATION:** This is a **Traffic Category Classifier**, not a VPN vs Non-VPN binary classifier.

- **Dataset Used**: MIT Lincoln Laboratory VNAT (VPN/Non-VPN Network Application Traffic Dataset) Feature Dataframe release 1.
- **Model Type**: RandomForestClassifier (200 trees, balanced).
- **ML Classes**: C2 (Command & Control), CHAT, FILE_TRANSFER, STREAMING, VOIP.
- **Evaluation Metrics**: 98.48% accuracy on a stratified 80/20 split (15,093 total samples).

The model uses flow-level features (inter-arrival time statistics, byte/packet counts) extracted during packet parsing to make predictions.

## Limitations
- **Short Captures**: For captures with very few packets (< 50), the flow characteristics (like inter-arrival times) have high variance compared to the sustained flows used for training. Confidence scores will be lower and should be treated as indicative only.
- **No ESP**: If the capture only contains IKE negotiation and no ESP (encrypted data) packets, the ML classification is skipped because there is no data flow to classify.
- **VPN vs Non-VPN**: The model predicts traffic category (e.g., CHAT vs STREAMING). It does not detect whether traffic is VPN or non-VPN, as this requires a different dataset configuration.
