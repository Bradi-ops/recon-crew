# =============================================================================
# ReconCrew v3 - Dockerized Multi-Agent Web Recon
# =============================================================================
FROM python:3.12-slim

LABEL maintainer="ReconCrew"
LABEL description="Multi-Agent Web Reconnaissance System"

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Working directory
WORKDIR /app

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY src/ ./src/
COPY templates/ ./templates/

# Reports volume
RUN mkdir -p /app/reports
VOLUME /app/reports

# Entrypoint
ENTRYPOINT ["python", "src/main.py"]
