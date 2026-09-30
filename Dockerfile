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

# Expose the port FastAPI runs on
EXPOSE 8000

# Start the FastAPI server
CMD ["python", "main.py"]
