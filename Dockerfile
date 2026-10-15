# ── Stage 1: Build stage ──────────────────────────────────────────────────────
FROM python:3.11-slim

# Prevent interactive prompts during apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Install TShark (required by PyShark for PCAP parsing)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tshark \
        libpcap-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Allow tshark to be used without root (add to wireshark group)
RUN groupadd -f wireshark && \
    usermod -aG wireshark root

# Set working directory
WORKDIR /app

# Copy and install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire backend
COPY backend/ .

# Render assigns $PORT at runtime; default to 8000 for local Docker runs.
ENV PORT=8000
EXPOSE 8000

# Use shell form so $PORT is expanded at container start time.
CMD uvicorn main:app --host 0.0.0.0 --port $PORT
