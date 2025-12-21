# Docker Compose Usage Guide

**Version**: 5.0
**Date**: 2025-12-21
**Status**: Production Ready ✅

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start](#quick-start)
4. [Development Workflow](#development-workflow)
5. [Production Deployment](#production-deployment)
6. [Service Management](#service-management)
7. [Data Management](#data-management)
8. [Monitoring & Logs](#monitoring--logs)
9. [Backup & Restore](#backup--restore)
10. [Upgrading](#upgrading)
11. [Common Operations](#common-operations)

---

## Overview

PCAP Analyzer provides a multi-service Docker Compose setup for local development and production deployments.

### Services

| Service | Description | Port | Profile |
|---------|-------------|------|---------|
| **app** | PCAP Analyzer application | 8000 | dev, prod |
| **postgres** | PostgreSQL 15 database | 5432 | dev, prod |
| **adminer** | Database web UI | 8080 | dev only |

### Profiles

- **dev** - Development mode (includes Adminer for database inspection)
- **prod** - Production mode (app + postgres only, no dev tools)

---

## Prerequisites

### Required

- **Docker**: 20.10+ ([Install Docker](https://docs.docker.com/get-docker/))
- **Docker Compose**: V2 recommended ([Install Compose](https://docs.docker.com/compose/install/))

### Verify Installation

```bash
# Check Docker version
docker --version
# Expected: Docker version 24.0.0+

# Check Docker Compose version
docker compose version
# Expected: Docker Compose version v2.20.0+

# Or old syntax
docker-compose version
# Expected: docker-compose version 1.29.0+
```

---

## Quick Start

### Step 1: Clone Repository

```bash
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer
```

---

### Step 2: Configure Environment

```bash
# Copy example configuration
cp .env.example .env

# Generate secrets
./scripts/generate_secrets.sh

# Or manually:
echo "POSTGRES_PASSWORD=$(openssl rand -base64 32)" >> .env
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env
echo "CSRF_SECRET_KEY=$(openssl rand -hex 32)" >> .env

# Review and edit .env
nano .env
```

**Minimum required variables**:
```bash
# .env
POSTGRES_PASSWORD=your_secure_password_here
SECRET_KEY=64_char_hex_string_1234567890abcdef...
CSRF_SECRET_KEY=different_64_char_hex_string_9876...
```

---

### Step 3: Start Services

```bash
# Development mode (with Adminer)
docker compose --profile dev up -d

# Or production mode (no Adminer)
docker compose --profile prod up -d

# Check status
docker compose ps
```

**Expected output**:
```
NAME              IMAGE                    STATUS         PORTS
pcap_analyzer     pcap-analyzer:latest     Up 10 seconds  0.0.0.0:8000->8000/tcp
pcap_postgres     postgres:15-alpine       Up 15 seconds  0.0.0.0:5432->5432/tcp
pcap_adminer      adminer:latest           Up 10 seconds  0.0.0.0:8080->8080/tcp
```

---

### Step 4: Verify Deployment

```bash
# Health check
curl http://localhost:8000/api/health

# Expected response
{
  "status": "ok",
  "database": "connected",
  "version": "5.0.0"
}

# Open in browser
open http://localhost:8000
```

---

### Step 5: Get Admin Password

```bash
# Check logs for admin brise-glace password
docker compose logs app | grep "ADMIN BRISE-GLACE"

# Example output:
# 🔒 ADMIN BRISE-GLACE ACCOUNT CREATED
# Username: admin
# Password: aB3dEf9Gh2JkLm5NpQrStUvWxYz

# Login and change password immediately
curl -X POST http://localhost:8000/api/token \
  -d "username=admin&password=<displayed_password>"
```

---

## Development Workflow

### Starting for Development

```bash
# Start all services in background
docker compose --profile dev up -d

# Or start with logs visible (foreground)
docker compose --profile dev up

# Start specific service only
docker compose up postgres -d
```

---

### Code Changes (Live Reload)

The application **auto-reloads** when code changes are detected (if `--reload` flag is set in `uvicorn`).

```yaml
# docker-compose.yml (dev mode)
services:
  app:
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
    volumes:
      - ./app:/app/app  # Mount source code
      - ./src:/app/src
```

**Workflow**:
1. Edit code in your IDE
2. Save file
3. Application automatically restarts
4. Refresh browser (http://localhost:8000)

---

### Database Inspection (Adminer)

**Access Adminer**: http://localhost:8080

**Login**:
- **System**: PostgreSQL
- **Server**: `postgres` (service name)
- **Username**: `pcap`
- **Password**: (from `.env` POSTGRES_PASSWORD)
- **Database**: `pcap_analyzer`

**Features**:
- Browse tables (users, tasks, progress_snapshots)
- Run SQL queries
- Export/import data
- View table structure

---

### Running Migrations

```bash
# Check current migration version
docker compose exec app alembic current

# Apply all pending migrations
docker compose exec app alembic upgrade head

# Rollback one migration
docker compose exec app alembic downgrade -1

# View migration history
docker compose exec app alembic history --verbose
```

---

### Running Tests

```bash
# Run all tests inside container
docker compose exec app pytest

# Run specific test file
docker compose exec app pytest tests/test_auth.py

# Run with coverage
docker compose exec app pytest --cov=app --cov=src --cov-report=html

# View coverage report
open htmlcov/index.html
```

---

### Accessing Shell

```bash
# Application container bash
docker compose exec app bash

# PostgreSQL psql shell
docker compose exec postgres psql -U pcap -d pcap_analyzer

# Run Python REPL
docker compose exec app python
```

---

## Production Deployment

### Configuration Best Practices

**Required Environment Variables**:
```bash
# .env (production)

# Database
POSTGRES_PASSWORD=STRONG_PASSWORD_32_CHARS_MINIMUM
DATABASE_SSL_MODE=require  # Or verify-full for cloud PostgreSQL

# Security (CRITICAL)
SECRET_KEY=64_char_hex_string_CHANGE_THIS_1234567890abcdef
CSRF_SECRET_KEY=different_64_hex_CHANGE_THIS_9876543210fed
ENVIRONMENT=production

# Application
APP_PORT=8000
LOG_LEVEL=WARNING
LOG_FORMAT=json

# Storage
MAX_UPLOAD_SIZE_MB=500
REPORT_TTL_HOURS=24
```

---

### Starting in Production

```bash
# Use production profile
docker compose --profile prod up -d

# Verify services started
docker compose ps

# Check logs for errors
docker compose logs app | grep -E "ERROR|CRITICAL"

# Health check
curl http://localhost:8000/api/health
```

---

### Reverse Proxy (nginx)

**Recommended**: Put nginx in front of application for HTTPS termination.

**File**: `nginx.conf`

```nginx
server {
    listen 443 ssl http2;
    server_name pcap.example.com;

    # TLS certificate
    ssl_certificate /etc/letsencrypt/live/pcap.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pcap.example.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    # Proxy to Docker Compose app
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # File upload size limit
        client_max_body_size 500M;
    }

    # SSE (Server-Sent Events) for progress updates
    location /api/progress/ {
        proxy_pass http://localhost:8000;
        proxy_buffering off;
        proxy_cache off;
        proxy_set_header Connection '';
        chunked_transfer_encoding off;
    }
}

# HTTP → HTTPS redirect
server {
    listen 80;
    server_name pcap.example.com;
    return 301 https://$host$request_uri;
}
```

**Start nginx**:
```bash
sudo nginx -t  # Test configuration
sudo systemctl restart nginx
```

---

### Resource Limits

**File**: `docker-compose.yml`

```yaml
services:
  app:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M

  postgres:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 1G
        reservations:
          cpus: '0.25'
          memory: 256M
```

**Apply limits**:
```bash
docker compose up -d  # Limits applied automatically
```

---

## Service Management

### Starting Services

```bash
# All services
docker compose up -d

# Specific service
docker compose up postgres -d

# Multiple services
docker compose up app postgres -d

# With specific profile
docker compose --profile dev up -d
```

---

### Stopping Services

```bash
# All services (graceful shutdown)
docker compose down

# Stop without removing containers
docker compose stop

# Stop specific service
docker compose stop app

# Force stop (kill immediately)
docker compose kill
```

---

### Restarting Services

```bash
# All services
docker compose restart

# Specific service
docker compose restart app

# Recreate containers (apply config changes)
docker compose up -d --force-recreate
```

---

### Scaling Services

```bash
# Scale app to 3 instances (requires load balancer)
docker compose up -d --scale app=3

# Note: SQLite doesn't support multiple instances
# Use PostgreSQL for scaling
```

---

### Viewing Service Status

```bash
# All services
docker compose ps

# With resource usage
docker compose ps --format json | jq

# Detailed status
docker compose ps -a

# Top (live resource usage)
docker compose top
```

---

## Data Management

### Volumes

**Persistent Volumes**:
```yaml
# docker-compose.yml
volumes:
  postgres_data:      # PostgreSQL database files
    driver: local
  app_data:           # PCAP uploads and reports (optional)
    driver: local
```

**List volumes**:
```bash
docker volume ls | grep pcap

# Example output:
# pcap_analyzer_postgres_data
# pcap_analyzer_app_data
```

---

### Volume Inspection

```bash
# Inspect volume
docker volume inspect pcap_analyzer_postgres_data

# Output:
# [
#     {
#         "Name": "pcap_analyzer_postgres_data",
#         "Driver": "local",
#         "Mountpoint": "/var/lib/docker/volumes/pcap_analyzer_postgres_data/_data",
#         ...
#     }
# ]

# View volume size
docker system df -v | grep pcap_analyzer
```

---

### Cleaning Up

```bash
# Remove stopped containers
docker compose down

# Remove containers + volumes (⚠️ DATA LOSS!)
docker compose down -v

# Remove containers + images
docker compose down --rmi all

# Remove everything (⚠️ COMPLETE WIPEOUT!)
docker compose down -v --rmi all --remove-orphans
```

---

## Monitoring & Logs

### Viewing Logs

```bash
# All services (follow mode)
docker compose logs -f

# Specific service
docker compose logs -f app
docker compose logs -f postgres

# Last 100 lines
docker compose logs --tail=100 app

# Timestamps
docker compose logs -f -t app

# Since specific time
docker compose logs --since 2025-12-21T20:00:00 app
```

---

### Log Filtering

```bash
# Errors only
docker compose logs app | grep -E "ERROR|CRITICAL"

# Failed logins
docker compose logs app | grep "Failed login attempt"

# Admin actions (audit trail)
docker compose logs app | grep "AUDIT:"

# Database connection errors
docker compose logs app | grep "connection refused\|Connection pool exhausted"
```

---

### Resource Monitoring

```bash
# Live resource usage (CPU, memory, I/O)
docker stats pcap_analyzer pcap_postgres

# Output:
# CONTAINER       CPU %     MEM USAGE / LIMIT     MEM %     NET I/O
# pcap_analyzer   5.21%     256.4MiB / 2GiB       12.52%    1.2kB / 850B
# pcap_postgres   2.10%     128.2MiB / 1GiB       12.52%    850B / 1.2kB
```

---

### Health Checks

```bash
# Application health
curl http://localhost:8000/api/health

# PostgreSQL health
docker compose exec postgres pg_isready -U pcap

# Container health status
docker inspect pcap_analyzer --format='{{.State.Health.Status}}'
```

---

## Backup & Restore

### Database Backup

**Manual Backup**:
```bash
# Backup to file
docker compose exec postgres pg_dump -U pcap pcap_analyzer | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz

# Verify backup created
ls -lh backup_*.sql.gz
```

**Automated Backup** (cron job):
```bash
# Add to crontab
crontab -e

# Daily backup at 2 AM
0 2 * * * cd /path/to/pcap_analyzer && docker compose exec -T postgres pg_dump -U pcap pcap_analyzer | gzip > backups/backup_$(date +\%Y\%m\%d).sql.gz

# Keep last 7 days
0 3 * * * find /path/to/pcap_analyzer/backups -name "backup_*.sql.gz" -mtime +7 -delete
```

---

### Database Restore

```bash
# Stop application (prevent writes during restore)
docker compose stop app

# Drop existing database
docker compose exec postgres psql -U postgres -c "DROP DATABASE pcap_analyzer;"

# Recreate database
docker compose exec postgres psql -U postgres -c "CREATE DATABASE pcap_analyzer OWNER pcap;"

# Restore from backup
gunzip -c backup_20251221_020000.sql.gz | docker compose exec -T postgres psql -U pcap -d pcap_analyzer

# Restart application
docker compose start app

# Verify restoration
curl http://localhost:8000/api/health
```

---

### PCAP Files Backup

```bash
# Backup uploaded PCAP files (if using local storage)
tar -czf pcaps_backup_$(date +%Y%m%d).tar.gz data/uploads/

# Restore
tar -xzf pcaps_backup_20251221.tar.gz -C data/
```

---

## Upgrading

### Upgrade to New Version

**Step 1: Backup**
```bash
# Backup database
docker compose exec postgres pg_dump -U pcap pcap_analyzer | gzip > backup_pre_upgrade.sql.gz

# Backup .env
cp .env .env.backup
```

**Step 2: Pull New Code**
```bash
# Fetch updates
git fetch origin
git checkout tags/v5.1.0  # Or git pull for latest

# Review CHANGELOG
cat CHANGELOG.md
```

**Step 3: Update Environment**
```bash
# Check for new environment variables
diff .env.example .env

# Add new variables if needed
nano .env
```

**Step 4: Rebuild Images**
```bash
# Rebuild application image
docker compose build app

# Or pull from registry
docker compose pull
```

**Step 5: Run Migrations**
```bash
# Stop app (keep postgres running)
docker compose stop app

# Run migrations
docker compose run --rm app alembic upgrade head

# Start app
docker compose start app
```

**Step 6: Verify Upgrade**
```bash
# Check version
curl http://localhost:8000/api/health | jq '.version'

# Check logs for errors
docker compose logs app | grep -E "ERROR|CRITICAL"
```

---

### Rollback

```bash
# Stop services
docker compose down

# Checkout previous version
git checkout tags/v5.0.0

# Restore database
gunzip -c backup_pre_upgrade.sql.gz | docker compose exec -T postgres psql -U pcap -d pcap_analyzer

# Rebuild and start
docker compose build app
docker compose up -d

# Verify rollback
curl http://localhost:8000/api/health
```

---

## Common Operations

### Reset Everything (Fresh Start)

```bash
# ⚠️ WARNING: This deletes ALL data!

# Stop and remove everything
docker compose down -v --rmi all

# Remove .env (optional)
rm .env

# Start fresh
cp .env.example .env
nano .env  # Configure secrets
docker compose --profile dev up -d
```

---

### Change Admin Password

```bash
# Login as admin
TOKEN=$(curl -s -X POST http://localhost:8000/api/token \
  -d "username=admin&password=<old_password>" \
  | jq -r '.access_token')

# Change password
curl -X PUT http://localhost:8000/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "<old_password>",
    "new_password": "NewSecurePassword123!"
  }'
```

---

### Rotate SECRET_KEY

```bash
# ⚠️ WARNING: This invalidates all JWT tokens (users must re-login)

# Generate new SECRET_KEY
export NEW_SECRET_KEY=$(openssl rand -hex 32)

# Update .env
sed -i "s/SECRET_KEY=.*/SECRET_KEY=$NEW_SECRET_KEY/" .env

# Restart application
docker compose restart app

# Users must re-login
```

---

### Access PostgreSQL Shell

```bash
# psql shell
docker compose exec postgres psql -U pcap -d pcap_analyzer

# Example queries
SELECT * FROM users;
SELECT COUNT(*) FROM tasks;
\dt  # List tables
\d users  # Describe users table
\q  # Quit
```

---

### Export/Import Data

**Export users to CSV**:
```bash
docker compose exec postgres psql -U pcap -d pcap_analyzer -c "COPY users TO STDOUT WITH CSV HEADER" > users.csv
```

**Import users from CSV**:
```bash
cat users.csv | docker compose exec -T postgres psql -U pcap -d pcap_analyzer -c "COPY users FROM STDIN WITH CSV HEADER"
```

---

### View Container Resource Usage

```bash
# Live stats
docker stats pcap_analyzer pcap_postgres

# Disk usage
docker compose exec app du -sh /data

# PostgreSQL database size
docker compose exec postgres psql -U pcap -d pcap_analyzer -c "SELECT pg_size_pretty(pg_database_size('pcap_analyzer'));"
```

---

### Cleanup Old Reports

```bash
# Reports older than REPORT_TTL_HOURS are auto-deleted by cleanup worker

# Manual cleanup (delete reports older than 24 hours)
docker compose exec app bash -c '
  find /data/reports -name "*.html" -mtime +1 -delete
  find /data/reports -name "*.json" -mtime +1 -delete
'
```

---

## Troubleshooting

For common issues and solutions, see:
- [Troubleshooting Guide](TROUBLESHOOTING.md)
- [PostgreSQL Deployment Guide](POSTGRESQL_DEPLOYMENT.md)

**Quick fixes**:

```bash
# Restart everything
docker compose restart

# View logs
docker compose logs -f

# Rebuild from scratch
docker compose down -v
docker compose build --no-cache
docker compose up -d
```

---

## Related Documentation

- [README.md](../README.md) - Project overview
- [PostgreSQL Deployment Guide](POSTGRESQL_DEPLOYMENT.md)
- [Environment Variables Reference](ENVIRONMENT_VARIABLES.md)
- [Migration Guide v5.0](MIGRATION_GUIDE_v5.0.md)
- [Security Best Practices](SECURITY_BEST_PRACTICES.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)

---

**Last Updated**: 2025-12-21
**Version**: 5.0.0
**Status**: Production Ready ✅
