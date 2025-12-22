# Environment Variables Reference

**Version**: 5.0
**Date**: 2025-12-21
**Status**: Production Ready ✅

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Reference](#quick-reference)
3. [Database Configuration](#database-configuration)
4. [Security Configuration](#security-configuration)
5. [Application Settings](#application-settings)
6. [Deployment Settings](#deployment-settings)
7. [Logging & Monitoring](#logging--monitoring)
8. [Development & Testing](#development--testing)
9. [Complete Examples](#complete-examples)
10. [Validation & Troubleshooting](#validation--troubleshooting)

---

## Overview

PCAP Analyzer v5.0 uses environment variables for configuration across all deployment modes (CLI, Docker Compose, Kubernetes).

### Configuration Priority

1. **Environment variables** (highest priority)
2. **`.env` file** (Docker Compose, local development)
3. **Kubernetes Secrets/ConfigMaps**
4. **Default values** (lowest priority)

### Security Best Practices

- ✅ **Never commit** `.env` files to version control
- ✅ **Use secrets management** in production (Kubernetes Secrets, AWS Secrets Manager)
- ✅ **Generate strong secrets** using `openssl rand` or similar
- ✅ **Rotate secrets** regularly (SECRET_KEY, admin password)
- ✅ **Restrict access** to `.env` files (chmod 600)

---

## Quick Reference

### Required in Production

| Variable | Description | Generate With |
|----------|-------------|---------------|
| `DATABASE_URL` | PostgreSQL connection string | Manual |
| `SECRET_KEY` | JWT signing key (64 hex chars) | `openssl rand -hex 32` |
| `CSRF_SECRET_KEY` | CSRF token key (64 hex chars) | `openssl rand -hex 32` |
| `POSTGRES_PASSWORD` | PostgreSQL password | `openssl rand -base64 32` |

### Commonly Configured

| Variable | Description | Default |
|----------|-------------|---------|
| `ENVIRONMENT` | Deployment mode | `development` |
| `APP_PORT` | Application HTTP port | `8000` |
| `DATABASE_SSL_MODE` | PostgreSQL TLS mode | `disable` |
| `LOG_LEVEL` | Logging verbosity | `INFO` |

### Optional (Advanced)

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_MIN_SIZE` | Connection pool min size | `2` |
| `DATABASE_MAX_SIZE` | Connection pool max size | `10` |
| `MAX_UPLOAD_SIZE_MB` | Max PCAP file size | `500` |
| `REPORT_TTL_HOURS` | Report retention time | `24` |

---

## Database Configuration

### DATABASE_URL

**Description**: Database connection string (PostgreSQL or SQLite)

**Type**: String (URL format)

**Required**: ❌ No (defaults to SQLite)

**Default**: `sqlite:///data/pcap_analyzer.db`

**Production**: ✅ Use PostgreSQL

**Format**:
```bash
# PostgreSQL (recommended for production)
DATABASE_URL="postgresql://username:password@host:port/database"

# PostgreSQL with SSL
DATABASE_URL="postgresql://username:password@host:port/database?sslmode=verify-full"

# SQLite (development only)
DATABASE_URL="sqlite:///path/to/database.db"
```

**Examples**:
```bash
# Local PostgreSQL
DATABASE_URL="postgresql://pcap:secure_password@localhost:5432/pcap_analyzer"

# Docker Compose (service name as host)
DATABASE_URL="postgresql://pcap:secure_password@postgres:5432/pcap_analyzer"

# Cloud PostgreSQL (AWS RDS)
DATABASE_URL="postgresql://pcap:password@pcap-db.abc123.us-east-1.rds.amazonaws.com:5432/pcap_analyzer"

# Cloud PostgreSQL (GCP Cloud SQL)
DATABASE_URL="postgresql://pcap:password@10.123.45.67:5432/pcap_analyzer"

# Kubernetes (service DNS)
DATABASE_URL="postgresql://pcap:password@postgres.pcap-analyzer.svc.cluster.local:5432/pcap_analyzer"

# SQLite (dev mode)
DATABASE_URL="sqlite:///data/pcap_analyzer.db"
```

**Security Notes**:
- ⚠️ **Never log** this value (contains password)
- ✅ **Use Kubernetes Secret** in production
- ✅ **Use strong password** (32+ chars)

---

### POSTGRES_PASSWORD

**Description**: PostgreSQL superuser/admin password (used by Docker Compose)

**Type**: String

**Required**: ✅ Yes (Docker Compose with PostgreSQL)

**Default**: ❌ None

**Format**:
```bash
POSTGRES_PASSWORD="your_secure_password_here"
```

**Generate**:
```bash
# Secure random password (32 bytes)
openssl rand -base64 32

# Alphanumeric only (24 chars)
openssl rand -base64 18 | tr -d '/+=' | head -c 24
```

**Example**:
```bash
POSTGRES_PASSWORD="aB3dEf9Gh2JkLm5NpQrStUvWxYz1234567890"
```

**Security Notes**:
- ⚠️ **Change default** immediately
- ✅ **Use 32+ characters**
- ✅ **Mix alphanumeric + symbols**
- ✅ **Rotate every 90 days**

---

### DATABASE_SSL_MODE

**Description**: PostgreSQL SSL/TLS connection mode

**Type**: String (enum)

**Required**: ❌ No

**Default**: `disable`

**Values**:
- `disable` - No SSL (development only)
- `require` - SSL required, no certificate verification
- `verify-ca` - SSL + verify CA certificate
- `verify-full` - SSL + verify CA + hostname (most secure)

**Format**:
```bash
DATABASE_SSL_MODE="verify-full"
```

**Examples by Environment**:
```bash
# Development (local PostgreSQL)
DATABASE_SSL_MODE="disable"

# Staging (cloud PostgreSQL)
DATABASE_SSL_MODE="require"

# Production (cloud PostgreSQL)
DATABASE_SSL_MODE="verify-full"
```

**Security Notes**:
- ⚠️ **Never use `disable` in production**
- ✅ **Use `verify-full` for cloud databases**
- ✅ **Ensure certificates are valid**

---

### DATABASE_MIN_SIZE

**Description**: Minimum connection pool size (asyncpg)

**Type**: Integer

**Required**: ❌ No

**Default**: `2`

**Range**: `1-20`

**Format**:
```bash
DATABASE_MIN_SIZE=2
```

**Recommended Values**:
- **Development**: `1`
- **Staging**: `2`
- **Production (low traffic)**: `2-5`
- **Production (high traffic)**: `5-10`

**Tuning**:
```bash
# Low traffic (<10 requests/sec)
DATABASE_MIN_SIZE=2

# Medium traffic (10-100 requests/sec)
DATABASE_MIN_SIZE=5

# High traffic (100+ requests/sec)
DATABASE_MIN_SIZE=10
```

---

### DATABASE_MAX_SIZE

**Description**: Maximum connection pool size (asyncpg)

**Type**: Integer

**Required**: ❌ No

**Default**: `10`

**Range**: `2-100`

**Format**:
```bash
DATABASE_MAX_SIZE=10
```

**Recommended Values**:
- **Development**: `5`
- **Staging**: `10`
- **Production (low traffic)**: `10-20`
- **Production (high traffic)**: `20-50`

**Tuning**:
```bash
# Low traffic
DATABASE_MAX_SIZE=10

# Medium traffic
DATABASE_MAX_SIZE=20

# High traffic (requires PostgreSQL max_connections ≥ 100)
DATABASE_MAX_SIZE=50
```

**Important**:
- ⚠️ **Must be ≤ PostgreSQL `max_connections`**
- ⚠️ **Multiple app instances** multiply connections: 3 instances × 50 = 150 connections
- ✅ **Monitor** with `SELECT count(*) FROM pg_stat_activity;`

---

## Security Configuration

### SECRET_KEY

**Description**: JWT token signing key (HS256 algorithm)

**Type**: String (64 hexadecimal characters)

**Required**: ✅ Yes (production mode)

**Default**: ❌ None (app fails hard in production)

**Format**:
```bash
SECRET_KEY="64_character_hex_string_here_1234567890abcdef..."
```

**Generate**:
```bash
# Recommended: 256-bit key (64 hex chars)
openssl rand -hex 32

# Alternative: Python
python -c "import secrets; print(secrets.token_hex(32))"
```

**Example**:
```bash
SECRET_KEY="a1b2c3d4e5f6789012345678901234567890abcdefabcdef1234567890abcdef"
```

**Security Notes**:
- ⚠️ **CRITICAL**: Never commit to version control
- ⚠️ **CRITICAL**: Changing this invalidates all JWT tokens
- ✅ **Must be different** from `CSRF_SECRET_KEY`
- ✅ **Rotate every 90-180 days**
- ✅ **Use Kubernetes Secret** in production

**Production Validation**:
```python
# Application enforces this check
if ENVIRONMENT == "production" and not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required in production")
```

---

### CSRF_SECRET_KEY

**Description**: CSRF token signing key

**Type**: String (64 hexadecimal characters)

**Required**: ✅ Yes (production mode)

**Default**: ❌ None (app fails hard in production)

**Format**:
```bash
CSRF_SECRET_KEY="different_64_character_hex_string_5678..."
```

**Generate**:
```bash
# Must be DIFFERENT from SECRET_KEY
openssl rand -hex 32
```

**Example**:
```bash
CSRF_SECRET_KEY="9f8e7d6c5b4a321098765432109876543210fedcbafedcba98765432109876"
```

**Security Notes**:
- ⚠️ **MUST differ** from `SECRET_KEY`
- ✅ **Same security requirements** as SECRET_KEY
- ✅ **Rotate independently** from SECRET_KEY

---

### ADMIN_PASSWORD_FILE

**Description**: Path to file containing admin brise-glace password

**Type**: String (file path)

**Required**: ❌ No

**Default**: `/var/run/secrets/admin_password`

**Format**:
```bash
ADMIN_PASSWORD_FILE="/var/run/secrets/admin_password"
```

**Usage**:
```bash
# Kubernetes: Mount secret as file
volumeMounts:
- name: admin-password
  mountPath: /var/run/secrets
  readOnly: true

# File content (plain text)
echo "MySecureAdminPassword123!" > /var/run/secrets/admin_password
chmod 600 /var/run/secrets/admin_password
```

**Fallback**: If file doesn't exist, random password generated and displayed in logs

**Security Notes**:
- ✅ **Preferred method** for Kubernetes deployments
- ✅ **File permissions**: `0600` (owner read/write only)
- ⚠️ **Change password** immediately after first login

---

## Application Settings

### ENVIRONMENT

**Description**: Deployment environment mode

**Type**: String (enum)

**Required**: ❌ No

**Default**: `development`

**Values**:
- `development` - Development mode (relaxed security, detailed logs)
- `staging` - Staging mode (production-like, test data allowed)
- `production` - Production mode (strict security, enforced secrets)

**Format**:
```bash
ENVIRONMENT="production"
```

**Effects**:
```bash
# Production mode (ENVIRONMENT=production)
- SECRET_KEY required (fails hard if missing)
- CSRF_SECRET_KEY required (fails hard if missing)
- Rate limiting enabled (5s lockout after 7 failed logins)
- Detailed error messages disabled
- TLS/SSL recommended warnings

# Development mode (ENVIRONMENT=development)
- SECRET_KEY optional (uses default)
- Detailed error stack traces
- No rate limiting
- Permissive CORS
```

---

### APP_PORT

**Description**: HTTP server listening port

**Type**: Integer

**Required**: ❌ No

**Default**: `8000`

**Range**: `1024-65535`

**Format**:
```bash
APP_PORT=8000
```

**Examples**:
```bash
# Default
APP_PORT=8000

# Custom port (if 8000 already in use)
APP_PORT=9000

# Kubernetes (usually keep default)
APP_PORT=8000
```

**Notes**:
- ⚠️ **Ports <1024** require root privileges (not recommended)
- ✅ **Use reverse proxy** (nginx, Ingress) for port 80/443

---

### MAX_UPLOAD_SIZE_MB

**Description**: Maximum PCAP file upload size (megabytes)

**Type**: Integer

**Required**: ❌ No

**Default**: `500`

**Range**: `1-10000`

**Format**:
```bash
MAX_UPLOAD_SIZE_MB=500
```

**Tuning**:
```bash
# Small captures (demo, testing)
MAX_UPLOAD_SIZE_MB=100

# Medium captures (typical production)
MAX_UPLOAD_SIZE_MB=500

# Large captures (forensics, long captures)
MAX_UPLOAD_SIZE_MB=2000

# Very large captures (multi-day captures)
MAX_UPLOAD_SIZE_MB=5000
```

**Security Notes**:
- ⚠️ **Larger files = longer processing** = more memory/CPU
- ✅ **Monitor disk space** when increasing limit
- ✅ **Consider timeout** for very large files

---

### REPORT_TTL_HOURS

**Description**: Report retention time (hours)

**Type**: Integer

**Required**: ❌ No

**Default**: `24`

**Range**: `1-8760` (1 hour - 1 year)

**Format**:
```bash
REPORT_TTL_HOURS=24
```

**Examples**:
```bash
# Short retention (demo, testing)
REPORT_TTL_HOURS=1

# Default (1 day)
REPORT_TTL_HOURS=24

# Medium retention (1 week)
REPORT_TTL_HOURS=168

# Long retention (1 month)
REPORT_TTL_HOURS=720

# Extended retention (1 year)
REPORT_TTL_HOURS=8760
```

**Cleanup Behavior**:
```bash
# Reports older than REPORT_TTL_HOURS are deleted by cleanup worker
# Runs every hour (configurable)
```

---

### DATA_DIR

**Description**: Data storage directory (database, uploads, reports)

**Type**: String (directory path)

**Required**: ❌ No

**Default**: `./data`

**Format**:
```bash
DATA_DIR="/data"
```

**Examples**:
```bash
# Default (relative to project root)
DATA_DIR="./data"

# Absolute path
DATA_DIR="/var/lib/pcap_analyzer"

# Docker Compose (volume mount)
DATA_DIR="/data"

# Kubernetes (PVC mount)
DATA_DIR="/data"
```

**Directory Structure**:
```
$DATA_DIR/
├── pcap_analyzer.db         # SQLite database (if DATABASE_URL not set)
├── uploads/                 # Uploaded PCAP files
│   └── {task_id}.pcap
└── reports/                 # Generated reports
    ├── {task_id}.html
    └── {task_id}.json
```

---

## Deployment Settings

### POSTGRES_PORT

**Description**: PostgreSQL container port (Docker Compose only)

**Type**: Integer

**Required**: ❌ No

**Default**: `5432`

**Range**: `1024-65535`

**Format**:
```bash
POSTGRES_PORT=5432
```

**Usage**:
```yaml
# docker-compose.yml
services:
  postgres:
    ports:
      - "${POSTGRES_PORT:-5432}:5432"
```

**Examples**:
```bash
# Default
POSTGRES_PORT=5432

# Custom port (if 5432 already in use)
POSTGRES_PORT=15432
```

---

### ADMINER_PORT

**Description**: Adminer web UI port (Docker Compose dev profile)

**Type**: Integer

**Required**: ❌ No

**Default**: `8080`

**Range**: `1024-65535`

**Format**:
```bash
ADMINER_PORT=8080
```

**Usage**:
```bash
# Access Adminer at http://localhost:8080
ADMINER_PORT=8080

# Custom port
ADMINER_PORT=9080
```

---

## Logging & Monitoring

### LOG_LEVEL

**Description**: Logging verbosity level

**Type**: String (enum)

**Required**: ❌ No

**Default**: `INFO`

**Values**:
- `DEBUG` - Detailed debug information (SQL queries, function calls)
- `INFO` - General informational messages (requests, responses)
- `WARNING` - Warning messages (deprecated features, slow queries)
- `ERROR` - Error messages (exceptions, failures)
- `CRITICAL` - Critical failures (app crash, data corruption)

**Format**:
```bash
LOG_LEVEL="INFO"
```

**Examples by Environment**:
```bash
# Development
LOG_LEVEL="DEBUG"

# Staging
LOG_LEVEL="INFO"

# Production
LOG_LEVEL="WARNING"
```

**Log Output Examples**:
```bash
# DEBUG
2025-12-21 20:00:00 DEBUG    [database] Executing query: SELECT * FROM users WHERE username=?
2025-12-21 20:00:00 DEBUG    [auth] JWT token generated for user alice

# INFO
2025-12-21 20:00:00 INFO     [api] POST /api/upload - 200 OK (1.23s)
2025-12-21 20:00:00 INFO     [worker] Task abc123 completed successfully

# WARNING
2025-12-21 20:00:00 WARNING  [auth] Failed login attempt for user bob (attempt 3/5)
2025-12-21 20:00:00 WARNING  [database] Slow query (2.5s): SELECT * FROM tasks

# ERROR
2025-12-21 20:00:00 ERROR    [worker] Task abc123 failed: File not found
2025-12-21 20:00:00 ERROR    [database] Connection pool exhausted (10/10)
```

---

### LOG_FORMAT

**Description**: Log output format

**Type**: String (enum)

**Required**: ❌ No

**Default**: `text`

**Values**:
- `text` - Human-readable text format
- `json` - Structured JSON format (for log aggregation)

**Format**:
```bash
LOG_FORMAT="json"
```

**Examples**:
```bash
# Text format (development)
LOG_FORMAT="text"
# Output: 2025-12-21 20:00:00 INFO [api] Request received

# JSON format (production, for ELK/Splunk)
LOG_FORMAT="json"
# Output: {"timestamp":"2025-12-21T20:00:00Z","level":"INFO","module":"api","message":"Request received"}
```

---

## Development & Testing

### TEST_DATABASE_URL

**Description**: Database URL for pytest tests

**Type**: String (URL format)

**Required**: ❌ No (defaults to temporary SQLite)

**Default**: `sqlite:///:memory:`

**Format**:
```bash
TEST_DATABASE_URL="postgresql://pcap:password@localhost:5432/pcap_analyzer_test"
```

**Usage**:
```bash
# Run tests with PostgreSQL
DATABASE_URL="postgresql://pcap:password@localhost:5432/pcap_analyzer_test" pytest

# Run tests with SQLite (default)
pytest
```

---

### SKIP_INTEGRATION_TESTS

**Description**: Skip integration tests during pytest run

**Type**: Boolean (any value = true)

**Required**: ❌ No

**Default**: `false` (run all tests)

**Format**:
```bash
SKIP_INTEGRATION_TESTS=1
```

**Usage**:
```bash
# Skip integration tests (faster CI)
SKIP_INTEGRATION_TESTS=1 pytest

# Run all tests (default)
pytest
```

---

## Complete Examples

### Development (CLI Only)

```bash
# No environment variables needed
# Uses default SQLite database

# Optional: Custom data directory
export DATA_DIR="/Users/alice/pcap_data"

# Optional: Verbose logging
export LOG_LEVEL="DEBUG"
```

---

### Development (Docker Compose)

**File**: `.env`

```bash
# Database
POSTGRES_PASSWORD=dev_password_change_me
POSTGRES_PORT=5432

# Application
APP_PORT=8000
ENVIRONMENT=development
LOG_LEVEL=DEBUG

# Security (optional in dev)
SECRET_KEY=dev_secret_key_32_chars_minimum_1234567890abcdef
CSRF_SECRET_KEY=dev_csrf_key_different_from_above_9876543210fed

# Storage
DATA_DIR=/data
MAX_UPLOAD_SIZE_MB=500
REPORT_TTL_HOURS=24

# Development tools
ADMINER_PORT=8080
```

---

### Staging (Docker Compose with PostgreSQL)

**File**: `.env`

```bash
# Database
DATABASE_URL=postgresql://pcap:SECURE_PASSWORD@postgres:5432/pcap_analyzer
POSTGRES_PASSWORD=SECURE_PASSWORD_32_CHARS_MIN
DATABASE_SSL_MODE=require
DATABASE_MIN_SIZE=2
DATABASE_MAX_SIZE=10

# Security (REQUIRED)
SECRET_KEY=a1b2c3d4e5f6789012345678901234567890abcdefabcdef1234567890abcdef
CSRF_SECRET_KEY=9f8e7d6c5b4a321098765432109876543210fedcbafedcba98765432109876

# Application
APP_PORT=8000
ENVIRONMENT=staging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Storage
DATA_DIR=/data
MAX_UPLOAD_SIZE_MB=1000
REPORT_TTL_HOURS=72

# Monitoring
POSTGRES_PORT=5432  # Exposed for monitoring tools
```

---

### Production (Kubernetes)

**Kubernetes Secret**: `pcap-secrets.yaml`

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: pcap-secrets
  namespace: pcap-analyzer
type: Opaque
stringData:
  # Database (generated with: openssl rand -base64 32)
  postgres-password: "aB3dEf9Gh2JkLm5NpQrStUvWxYz1234567890"

  # Security (generated with: openssl rand -hex 32)
  secret-key: "a1b2c3d4e5f6789012345678901234567890abcdefabcdef1234567890abcdef"
  csrf-secret-key: "9f8e7d6c5b4a321098765432109876543210fedcbafedcba98765432109876"

  # Admin password (generated with: openssl rand -base64 24)
  admin-password: "MySecureAdminPassword123!XyZ"
```

**Deployment Environment Variables**:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pcap-analyzer
spec:
  template:
    spec:
      containers:
      - name: app
        env:
        # Database
        - name: DATABASE_URL
          value: "postgresql://pcap:$(POSTGRES_PASSWORD)@postgres.pcap-analyzer.svc.cluster.local:5432/pcap_analyzer"
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: pcap-secrets
              key: postgres-password
        - name: DATABASE_SSL_MODE
          value: "verify-full"
        - name: DATABASE_MIN_SIZE
          value: "5"
        - name: DATABASE_MAX_SIZE
          value: "20"

        # Security
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: pcap-secrets
              key: secret-key
        - name: CSRF_SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: pcap-secrets
              key: csrf-secret-key
        - name: ADMIN_PASSWORD_FILE
          value: "/var/run/secrets/admin_password"

        # Application
        - name: ENVIRONMENT
          value: "production"
        - name: APP_PORT
          value: "8000"
        - name: LOG_LEVEL
          value: "WARNING"
        - name: LOG_FORMAT
          value: "json"

        # Storage
        - name: DATA_DIR
          value: "/data"
        - name: MAX_UPLOAD_SIZE_MB
          value: "2000"
        - name: REPORT_TTL_HOURS
          value: "168"  # 1 week

        volumeMounts:
        - name: admin-password
          mountPath: /var/run/secrets
          readOnly: true

      volumes:
      - name: admin-password
        secret:
          secretName: pcap-secrets
          items:
          - key: admin-password
            path: admin_password
```

---

## Validation & Troubleshooting

### Validate Configuration

**Script**: `scripts/validate_env.sh` (create this file)

```bash
#!/bin/bash
# Validate required environment variables

set -euo pipefail

echo "🔍 Validating environment variables..."

# Check ENVIRONMENT
if [ -z "${ENVIRONMENT:-}" ]; then
    echo "⚠️  ENVIRONMENT not set (defaulting to 'development')"
else
    echo "✅ ENVIRONMENT=$ENVIRONMENT"
fi

# Check SECRET_KEY (required in production)
if [ "${ENVIRONMENT:-development}" = "production" ]; then
    if [ -z "${SECRET_KEY:-}" ]; then
        echo "❌ SECRET_KEY is REQUIRED in production mode"
        exit 1
    elif [ ${#SECRET_KEY} -lt 32 ]; then
        echo "❌ SECRET_KEY must be at least 32 characters (current: ${#SECRET_KEY})"
        exit 1
    else
        echo "✅ SECRET_KEY is set (${#SECRET_KEY} chars)"
    fi
fi

# Check CSRF_SECRET_KEY (required in production)
if [ "${ENVIRONMENT:-development}" = "production" ]; then
    if [ -z "${CSRF_SECRET_KEY:-}" ]; then
        echo "❌ CSRF_SECRET_KEY is REQUIRED in production mode"
        exit 1
    elif [ "${SECRET_KEY:-}" = "${CSRF_SECRET_KEY:-}" ]; then
        echo "❌ CSRF_SECRET_KEY must differ from SECRET_KEY"
        exit 1
    else
        echo "✅ CSRF_SECRET_KEY is set and differs from SECRET_KEY"
    fi
fi

# Check DATABASE_URL
if [ -z "${DATABASE_URL:-}" ]; then
    echo "⚠️  DATABASE_URL not set (defaulting to SQLite)"
else
    echo "✅ DATABASE_URL=$DATABASE_URL"

    # Validate PostgreSQL SSL mode
    if [[ "$DATABASE_URL" == postgresql://* ]]; then
        if [ "${DATABASE_SSL_MODE:-disable}" = "disable" ] && [ "${ENVIRONMENT:-development}" = "production" ]; then
            echo "⚠️  WARNING: DATABASE_SSL_MODE=disable in production (insecure)"
        else
            echo "✅ DATABASE_SSL_MODE=${DATABASE_SSL_MODE:-disable}"
        fi
    fi
fi

# Check connection pool settings
if [ -n "${DATABASE_MAX_SIZE:-}" ]; then
    if [ "${DATABASE_MAX_SIZE}" -lt "${DATABASE_MIN_SIZE:-2}" ]; then
        echo "❌ DATABASE_MAX_SIZE ($DATABASE_MAX_SIZE) must be >= DATABASE_MIN_SIZE (${DATABASE_MIN_SIZE:-2})"
        exit 1
    else
        echo "✅ Connection pool: min=${DATABASE_MIN_SIZE:-2}, max=${DATABASE_MAX_SIZE}"
    fi
fi

# Check ports
if [ -n "${APP_PORT:-}" ]; then
    if [ "${APP_PORT}" -lt 1024 ]; then
        echo "⚠️  WARNING: APP_PORT=$APP_PORT requires root privileges"
    else
        echo "✅ APP_PORT=$APP_PORT"
    fi
fi

echo ""
echo "✅ Environment validation passed!"
```

**Usage**:
```bash
# Validate .env file
source .env && bash scripts/validate_env.sh

# Validate Kubernetes deployment
kubectl exec -n pcap-analyzer deployment/pcap-analyzer -- bash -c 'bash scripts/validate_env.sh'
```

---

### Common Issues

#### Issue: "SECRET_KEY environment variable is required in production"

**Cause**: `ENVIRONMENT=production` but `SECRET_KEY` not set

**Solution**:
```bash
# Generate and set SECRET_KEY
export SECRET_KEY=$(openssl rand -hex 32)

# Or add to .env
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env
```

---

#### Issue: "Connection pool exhausted"

**Cause**: `DATABASE_MAX_SIZE` too low for traffic volume

**Solution**:
```bash
# Increase pool size
export DATABASE_MAX_SIZE=20

# Verify PostgreSQL max_connections
docker exec -it pcap_postgres psql -U postgres -c "SHOW max_connections;"

# Ensure: DATABASE_MAX_SIZE × num_instances < max_connections
```

---

#### Issue: "SSL connection has been closed unexpectedly"

**Cause**: `DATABASE_SSL_MODE` mismatch with PostgreSQL configuration

**Solution**:
```bash
# Development: disable SSL
export DATABASE_SSL_MODE=disable

# Production: verify PostgreSQL SSL enabled
docker exec -it pcap_postgres psql -U postgres -c "SHOW ssl;"

# If SSL is off, enable it or use DATABASE_SSL_MODE=disable
```

---

## Related Documentation

- [PostgreSQL Deployment Guide](POSTGRESQL_DEPLOYMENT.md)
- [Migration Guide v5.0](MIGRATION_GUIDE_v5.0.md)
- [Security Best Practices](SECURITY_BEST_PRACTICES.md) (upcoming)
- [Docker Compose Usage Guide](DOCKER_COMPOSE_GUIDE.md) (upcoming)

---

**Last Updated**: 2025-12-21
**Version**: 5.0.0
**Status**: Production Ready ✅
