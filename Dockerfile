# ============================================
# Multi-Stage Dockerfile for PCAP Analyzer
# Target size: <500 MB
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

# Copy project files for installation
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY app/ ./app/

# Install package with all dependencies (CLI + Web)
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e .

# ============================================
# STAGE 2: Final (Application)
# ============================================
FROM python:3.11-slim-bookworm

LABEL maintainer="PCAP Analyzer Team"
LABEL description="PCAP Network Analysis Tool - Web Interface"
LABEL version="4.25.0"
LABEL org.opencontainers.image.source="https://github.com/MacFlurry/pcap_analyzer"

# Install runtime libs + tshark for 100% retransmission detection accuracy
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap0.8 \
    tshark \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

# Create non-root user
RUN groupadd -r pcapuser && \
    useradd -r -g pcapuser -u 1000 -m -d /home/pcapuser pcapuser

# Create directories with proper permissions (including secrets directory)
RUN mkdir -p /app /data/uploads /data/reports /data/logs /tmp /var/run/secrets && \
    chown -R pcapuser:pcapuser /app /data /tmp /var/run/secrets

WORKDIR /app

# Copy application code (exclude .git, tests, docs via .dockerignore)
COPY --chown=pcapuser:pcapuser src/ ./src/
COPY --chown=pcapuser:pcapuser app/ ./app/
COPY --chown=pcapuser:pcapuser config.yaml ./
COPY --chown=pcapuser:pcapuser alembic/ ./alembic/
COPY --chown=pcapuser:pcapuser alembic.ini ./

# Copy entrypoint script and make it executable
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 755 /usr/local/bin/docker-entrypoint.sh && \
    ls -la /usr/local/bin/docker-entrypoint.sh

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

# Entrypoint script (generates admin password)
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Startup command (uvicorn with 1 worker for CPU-bound workload)
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
