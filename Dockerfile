# ============================================
# Multi-Stage Dockerfile for PCAP Analyzer
# Target size: <250 MB
# Security: Non-root user, minimal attack surface
# ============================================

# ============================================
# STAGE 1: Builder (Dependencies compilation)
# ============================================
FROM python:3.11-slim-bookworm AS builder

LABEL stage=builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Create virtualenv for isolation
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install
WORKDIR /build
COPY requirements.txt requirements-web.txt ./

# Install dependencies with no cache to minimize layer size
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r requirements-web.txt

# ============================================
# STAGE 2: Runtime dependencies
# ============================================
FROM python:3.11-slim-bookworm AS runtime-deps

LABEL stage=runtime-deps

# Install ONLY runtime libraries (no gcc, g++)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv

# ============================================
# STAGE 3: Final (Application)
# ============================================
FROM python:3.11-slim-bookworm

LABEL maintainer="PCAP Analyzer Team"
LABEL description="PCAP Network Analysis Tool - Web Interface"
LABEL version="1.0.0"
LABEL org.opencontainers.image.source="https://github.com/pcap-analyzer/pcap-analyzer"

# Install runtime libs only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtualenv
COPY --from=runtime-deps /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Create non-root user
RUN groupadd -r pcapuser && \
    useradd -r -g pcapuser -u 1000 -m -d /home/pcapuser pcapuser

# Create directories with proper permissions
RUN mkdir -p /app /data/uploads /data/reports /data/logs /tmp && \
    chown -R pcapuser:pcapuser /app /data /tmp

WORKDIR /app

# Copy application code (exclude .git, tests, docs via .dockerignore)
COPY --chown=pcapuser:pcapuser src/ ./src/
COPY --chown=pcapuser:pcapuser app/ ./app/
COPY --chown=pcapuser:pcapuser config.yaml ./

# Switch to non-root user
USER pcapuser

# Health check (every 30s, timeout 10s, 3 retries)
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/health').read()" || exit 1

# Expose port
EXPOSE 8000

# Volume for persistent data
VOLUME ["/data"]

# Environment variables (can be overridden at runtime)
ENV MAX_UPLOAD_SIZE_MB=500
ENV REPORT_TTL_HOURS=24
ENV DATA_DIR=/data
ENV LOG_LEVEL=INFO
ENV MAX_QUEUE_SIZE=5

# Startup command (uvicorn with 1 worker for CPU-bound workload)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
