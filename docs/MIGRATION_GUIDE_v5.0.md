# Migration Guide: v4.x → v5.0

**Version**: 5.0
**Date**: 2025-12-21
**Status**: Production Ready ✅

---

## Table of Contents

1. [Overview](#overview)
2. [Breaking Changes](#breaking-changes)
3. [Prerequisites](#prerequisites)
4. [Migration Paths](#migration-paths)
5. [Step-by-Step Migration](#step-by-step-migration)
6. [Environment Variables](#environment-variables)
7. [Authentication Setup](#authentication-setup)
8. [Backward Compatibility](#backward-compatibility)
9. [Rollback Procedure](#rollback-procedure)
10. [Troubleshooting](#troubleshooting)

---

## Overview

PCAP Analyzer v5.0 is a **major release** with significant architectural changes:

### What's New

- **PostgreSQL support** - Production database (replaces SQLite for multi-instance)
- **Authentication system** - JWT-based auth with admin approval workflow
- **Multi-tenant isolation** - CWE-639 compliant with `owner_id` foreign keys
- **Enhanced security** - 100% OWASP ASVS compliance, rate limiting, CSRF protection
- **Test coverage** - 730+ tests (49.75% coverage)

### Migration Complexity

**Difficulty**: ⚠️ **MEDIUM** (requires database migration and configuration changes)

**Estimated Time**:
- **CLI-only users**: 5-10 minutes (minimal impact)
- **Docker Compose users**: 15-30 minutes (database migration required)
- **Kubernetes users**: 30-60 minutes (database + secrets + migration)

**Downtime Required**: ✅ Yes (10-30 minutes depending on data volume)

---

## Breaking Changes

### ⚠️ CRITICAL

1. **Authentication Required** (Web API)
   - **Impact**: All `/api/*` endpoints now require JWT token
   - **Migration**: Create admin account, login to get token
   - **CLI**: No impact (CLI remains standalone)

2. **PostgreSQL Recommended** (Production)
   - **Impact**: SQLite not suitable for multi-instance deployments
   - **Migration**: Migrate data to PostgreSQL
   - **Development**: SQLite still supported

3. **Admin Approval Workflow**
   - **Impact**: New users must be approved by admin before login
   - **Migration**: Approve existing users (automatic for first admin)
   - **Behavior**: `is_approved=false` by default

4. **SECRET_KEY Required** (Production)
   - **Impact**: Application fails hard if SECRET_KEY missing in production
   - **Migration**: Generate and set SECRET_KEY environment variable
   - **Security**: Prevents insecure JWT tokens

### MAJOR

5. **DatabaseService API Change**
   - **Before**: `DatabaseService(db_path=str)`
   - **After**: `DatabaseService(database_url=str)`
   - **Impact**: Custom code using DatabaseService must be updated

6. **owner_id Foreign Key**
   - **Impact**: All tasks now have `owner_id` referencing `users.id`
   - **Migration**: Legacy tasks (NULL owner_id) accessible only by admins
   - **Isolation**: Users can only see their own tasks

7. **Docker Compose Changes**
   - **Impact**: New PostgreSQL service, environment variables required
   - **Migration**: Update `.env` file, recreate containers
   - **Profiles**: Use `--profile dev` or `--profile prod`

---

## Prerequisites

### Before You Start

**Backup Your Data** ✅
```bash
# SQLite backup (if using web interface)
cp data/pcap_analyzer.db data/pcap_analyzer.db.backup.$(date +%Y%m%d)

# PCAP files backup (if stored locally)
tar -czf data/pcaps_backup_$(date +%Y%m%d).tar.gz data/*.pcap
```

**Check Current Version**:
```bash
# CLI
pcap_analyzer --version

# Web (if running)
curl http://localhost:8000/api/health
```

**System Requirements**:
- Python 3.11+ (unchanged)
- Docker 20.10+ (if using Docker Compose)
- PostgreSQL 15+ (new, production only)

**Dependencies Update**:
```bash
# Pull latest code
git pull origin main

# Update dependencies
pip install -e . --upgrade
```

---

## Migration Paths

Choose your migration path based on current deployment:

### Path A: CLI-Only Users (Recommended ⚡)

**Who**: Users running `pcap_analyzer analyze` locally

**Impact**: ✅ **MINIMAL** - No breaking changes

**Steps**:
1. Update code: `git pull`
2. Update dependencies: `pip install -e . --upgrade`
3. Continue using CLI as before

**No migration needed** - CLI remains fully functional and unchanged.

---

### Path B: Docker Compose Users (PostgreSQL Migration)

**Who**: Users running web interface via `docker-compose up`

**Impact**: ⚠️ **MEDIUM** - Database migration required

**Steps**:
1. Stop current containers
2. Backup SQLite database
3. Create `.env` file with secrets
4. Start PostgreSQL service
5. Migrate data (optional, for existing tasks)
6. Create admin account
7. Approve users

See [Step-by-Step: Docker Compose Migration](#docker-compose-migration) below.

---

### Path C: Kubernetes Users (Full Migration)

**Who**: Users running on Kubernetes with Helm

**Impact**: ⚠️ **HIGH** - Database + secrets + Helm chart migration

**Steps**:
1. Backup existing PVC data
2. Update Helm chart to v5.0
3. Create PostgreSQL database (external or StatefulSet)
4. Create Kubernetes secrets
5. Apply Helm upgrade
6. Migrate data
7. Create admin account

See [Step-by-Step: Kubernetes Migration](#kubernetes-migration) below.

---

## Step-by-Step Migration

### Docker Compose Migration

#### Step 1: Stop Current Services

```bash
cd pcap_analyzer

# Stop and remove old containers
docker-compose down

# Optional: Remove old volumes (if starting fresh)
# ⚠️ WARNING: This deletes all data!
# docker-compose down -v
```

---

#### Step 2: Backup SQLite Database

```bash
# Backup existing SQLite database
cp data/pcap_analyzer.db data/pcap_analyzer.db.v4_backup_$(date +%Y%m%d)

# Verify backup
ls -lh data/*.backup*
```

---

#### Step 3: Create Environment Variables

```bash
# Copy example
cp .env.example .env

# Generate secrets
echo "POSTGRES_PASSWORD=$(openssl rand -base64 32)" >> .env
echo "SECRET_KEY=$(openssl rand -hex 32)" >> .env
echo "CSRF_SECRET_KEY=$(openssl rand -hex 32)" >> .env

# Optional: Customize ports
echo "APP_PORT=8000" >> .env
echo "POSTGRES_PORT=5432" >> .env
echo "ADMINER_PORT=8080" >> .env

# Review generated secrets
cat .env
```

**Example `.env` file**:
```bash
# Database
POSTGRES_PASSWORD=aB3dEf9Gh2JkLm5NpQrStUvWxYz1234567890
POSTGRES_PORT=5432

# Security (REQUIRED in production)
SECRET_KEY=64_char_hex_string_here_1234567890abcdef
CSRF_SECRET_KEY=different_64_char_hex_string_5678

# Application
APP_PORT=8000
ADMINER_PORT=8080
ENVIRONMENT=production
```

---

#### Step 4: Start PostgreSQL Service

```bash
# Start with development profile (includes Adminer)
docker-compose --profile dev up -d

# Check logs
docker-compose logs -f postgres

# Wait for PostgreSQL to be ready
docker exec -it pcap_postgres pg_isready -U pcap
# Output: /var/run/postgresql:5432 - accepting connections
```

---

#### Step 5: Run Database Migrations

```bash
# Run Alembic migrations
docker-compose exec app alembic upgrade head

# Verify schema created
docker exec -it pcap_postgres psql -U pcap -d pcap_analyzer -c "\dt"
# Should show: users, tasks, progress_snapshots, alembic_version
```

---

#### Step 6: Create Admin Account

**Admin account is automatically created on first boot** with random password displayed in logs:

```bash
# Check logs for admin password
docker-compose logs app | grep "ADMIN BRISE-GLACE"

# Example output:
# 🔒 ADMIN BRISE-GLACE ACCOUNT CREATED
# ================================================================================
# Username: admin
# Password: aB3dEf9Gh2JkLm5NpQrStUvWxYz
# ⚠️  CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN!
# ================================================================================
```

**Login and change password**:
```bash
# Login to get JWT token
curl -X POST http://localhost:8000/api/token \
  -d "username=admin&password=<displayed_password>"

# Response: {"access_token": "eyJ...", "token_type": "bearer"}

# Change password
curl -X PUT http://localhost:8000/api/users/me \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "<displayed_password>",
    "new_password": "MySecureAdminPassword123!"
  }'
```

---

#### Step 7: Migrate Existing Data (Optional)

**If you have existing tasks in SQLite v4.x** and want to migrate them:

**Option A: Manual SQL Export/Import**

```bash
# Export users from SQLite
docker exec -it pcap_analyzer sqlite3 /data/pcap_analyzer.db.v4_backup <<EOF
.mode insert users
SELECT * FROM users;
EOF > users.sql

# Export tasks from SQLite
docker exec -it pcap_analyzer sqlite3 /data/pcap_analyzer.db.v4_backup <<EOF
.mode insert tasks
SELECT * FROM tasks;
EOF > tasks.sql

# Import to PostgreSQL (requires manual editing for syntax differences)
docker exec -it pcap_postgres psql -U pcap -d pcap_analyzer -f /tmp/users.sql
docker exec -it pcap_postgres psql -U pcap -d pcap_analyzer -f /tmp/tasks.sql
```

**Option B: Python Migration Script** (Recommended)

See [Data Migration Script](#data-migration-script) section below.

---

#### Step 8: Approve Existing Users

All users from v4.x need to be approved:

```bash
# List all users
curl -X GET http://localhost:8000/api/users \
  -H "Authorization: Bearer <admin_token>"

# Approve each user
curl -X PUT http://localhost:8000/api/admin/users/<user_id>/approve \
  -H "Authorization: Bearer <admin_token>"
```

---

#### Step 9: Verify Migration

```bash
# Check health
curl http://localhost:8000/api/health
# Expected: {"status": "ok", "database": "connected"}

# Check admin can list users
curl -X GET http://localhost:8000/api/users \
  -H "Authorization: Bearer <admin_token>"

# Access web interface
open http://localhost:8000
```

---

### Kubernetes Migration

#### Step 1: Backup Existing PVC Data

```bash
# If using Helm chart with PVC
kubectl cp pcap-analyzer/pcap-analyzer-0:/data ./data_backup

# Or use kubectl exec
kubectl exec -n pcap-analyzer pcap-analyzer-0 -- tar -czf - /data > data_backup.tar.gz
```

---

#### Step 2: Create PostgreSQL Database

**Option A: External PostgreSQL** (Recommended)

Use managed PostgreSQL service (AWS RDS, GCP Cloud SQL, Azure Database):

```bash
# Example AWS RDS connection string
export DATABASE_URL="postgresql://pcap:PASSWORD@pcap-db.abc123.us-east-1.rds.amazonaws.com:5432/pcap_analyzer"
```

**Option B: PostgreSQL StatefulSet** (Self-hosted)

```yaml
# postgres-statefulset.yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
spec:
  serviceName: postgres
  replicas: 1
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        env:
        - name: POSTGRES_DB
          value: pcap_analyzer
        - name: POSTGRES_USER
          value: pcap
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        ports:
        - containerPort: 5432
          name: postgres
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
  - metadata:
      name: postgres-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 10Gi
```

---

#### Step 3: Create Kubernetes Secrets

```bash
# Generate secrets
export POSTGRES_PASSWORD=$(openssl rand -base64 32)
export SECRET_KEY=$(openssl rand -hex 32)
export CSRF_SECRET_KEY=$(openssl rand -hex 32)
export ADMIN_PASSWORD=$(openssl rand -base64 24)

# Create secrets
kubectl create secret generic pcap-secrets \
  --namespace pcap-analyzer \
  --from-literal=postgres-password="$POSTGRES_PASSWORD" \
  --from-literal=secret-key="$SECRET_KEY" \
  --from-literal=csrf-secret-key="$CSRF_SECRET_KEY" \
  --from-literal=admin-password="$ADMIN_PASSWORD"

# Verify secrets created
kubectl get secrets -n pcap-analyzer
```

---

#### Step 4: Update Helm Values

**File**: `values.yaml`

```yaml
# Database configuration
database:
  type: postgresql  # Changed from sqlite
  url: "postgresql://pcap:PASSWORD@postgres.pcap-analyzer.svc.cluster.local:5432/pcap_analyzer"
  sslMode: require  # Development: disable, Production: verify-full

# Security
secrets:
  secretKey:
    existingSecret: pcap-secrets
    key: secret-key
  csrfSecretKey:
    existingSecret: pcap-secrets
    key: csrf-secret-key
  adminPassword:
    existingSecret: pcap-secrets
    key: admin-password

# Environment
environment: production

# Ingress (if using)
ingress:
  enabled: true
  className: nginx
  hosts:
    - host: pcap.example.com
      paths:
        - path: /
          pathType: Prefix
```

---

#### Step 5: Apply Helm Upgrade

```bash
# Update Helm chart
helm upgrade pcap-analyzer ./helm-chart/pcap-analyzer \
  --namespace pcap-analyzer \
  --values values.yaml \
  --wait

# Check rollout status
kubectl rollout status deployment/pcap-analyzer -n pcap-analyzer

# Check pods
kubectl get pods -n pcap-analyzer

# Check logs
kubectl logs -n pcap-analyzer deployment/pcap-analyzer -f
```

---

#### Step 6: Run Database Migrations

```bash
# Run Alembic migrations inside pod
kubectl exec -n pcap-analyzer deployment/pcap-analyzer -- alembic upgrade head

# Verify schema
kubectl exec -n pcap-analyzer deployment/pcap-analyzer -- \
  psql $DATABASE_URL -c "\dt"
```

---

#### Step 7: Retrieve Admin Password

```bash
# Admin password is in Kubernetes secret
kubectl get secret pcap-secrets -n pcap-analyzer -o jsonpath='{.data.admin-password}' | base64 -d

# Or check pod logs
kubectl logs -n pcap-analyzer deployment/pcap-analyzer | grep "ADMIN BRISE-GLACE"
```

---

#### Step 8: Verify Migration

```bash
# Port-forward to access application
kubectl port-forward -n pcap-analyzer svc/pcap-analyzer 8000:8000

# Check health
curl http://localhost:8000/api/health

# Or use Ingress URL
curl https://pcap.example.com/api/health
```

---

## Environment Variables

### New Required Variables (v5.0)

| Variable | Description | Required | Default | Example |
|----------|-------------|----------|---------|---------|
| `DATABASE_URL` | PostgreSQL connection string | Production | `sqlite:///data/pcap_analyzer.db` | `postgresql://pcap:password@localhost:5432/pcap_analyzer` |
| `SECRET_KEY` | JWT signing key (64 hex chars) | Production | ❌ Fails hard | `64_char_hex_string...` |
| `CSRF_SECRET_KEY` | CSRF token key (different from SECRET_KEY) | Production | ❌ Fails hard | `different_64_hex...` |

### New Optional Variables

| Variable | Description | Default | Example |
|----------|-------------|---------|---------|
| `DATABASE_SSL_MODE` | PostgreSQL SSL mode | `disable` | `verify-full` |
| `DATABASE_MIN_SIZE` | Connection pool min size | `2` | `5` |
| `DATABASE_MAX_SIZE` | Connection pool max size | `10` | `20` |
| `ENVIRONMENT` | Deployment environment | `development` | `production` |
| `POSTGRES_PASSWORD` | PostgreSQL password | ❌ Required | `secure_password` |

### Unchanged Variables (v4.x)

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_PORT` | Application port | `8000` |
| `MAX_UPLOAD_SIZE_MB` | Max PCAP file size | `500` |
| `REPORT_TTL_HOURS` | Report retention time | `24` |
| `LOG_LEVEL` | Logging level | `INFO` |

---

## Authentication Setup

### First Admin Account

**Automatic creation** on first boot:
- Username: `admin`
- Password: Random 24-char string (displayed in logs)
- Role: `admin`
- Approved: `true`

**Retrieve admin password**:

```bash
# Docker Compose
docker-compose logs app | grep "ADMIN BRISE-GLACE"

# Kubernetes
kubectl logs -n pcap-analyzer deployment/pcap-analyzer | grep "ADMIN BRISE-GLACE"

# Direct logs
tail -f logs/app.log | grep "ADMIN BRISE-GLACE"
```

**Change admin password** (REQUIRED):

```bash
# Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/token \
  -d "username=admin&password=<displayed_password>" \
  | jq -r '.access_token')

# Change password
curl -X PUT http://localhost:8000/api/users/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "<displayed_password>",
    "new_password": "MyNewSecurePassword123!"
  }'
```

---

### User Registration Flow

**New users** (v5.0):
1. Register via `POST /api/register`
2. Account created with `is_approved=false`
3. Admin approves via `PUT /api/admin/users/{id}/approve`
4. User can now login

**Example**:

```bash
# User registers
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "email": "alice@example.com",
    "password": "SecurePassword123!"
  }'

# Admin approves (get user_id from previous response or GET /api/users)
curl -X PUT http://localhost:8000/api/admin/users/<user_id>/approve \
  -H "Authorization: Bearer <admin_token>"

# User can login
curl -X POST http://localhost:8000/api/token \
  -d "username=alice&password=SecurePassword123!"
```

---

## Data Migration Script

For migrating existing SQLite data to PostgreSQL:

**File**: `scripts/migrate_v4_to_v5.py` (create this file)

```python
#!/usr/bin/env python3
"""
Migration script: SQLite v4.x → PostgreSQL v5.0

Usage:
    python scripts/migrate_v4_to_v5.py \\
        --sqlite-url "sqlite:///data/pcap_analyzer.db.v4_backup" \\
        --postgres-url "postgresql://pcap:password@localhost:5432/pcap_analyzer"
"""

import asyncio
import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.services.database import DatabaseService


async def export_sqlite_data(sqlite_db: DatabaseService) -> dict:
    """Export all data from SQLite database"""
    print("📤 Exporting SQLite data...")

    # Export users
    users_query = "SELECT * FROM users"
    users = await sqlite_db.fetch_all(users_query)
    print(f"  ✅ Exported {len(users)} users")

    # Export tasks
    tasks_query = "SELECT * FROM tasks"
    tasks = await sqlite_db.fetch_all(tasks_query)
    print(f"  ✅ Exported {len(tasks)} tasks")

    # Export progress snapshots
    progress_query = "SELECT * FROM progress_snapshots"
    progress = await sqlite_db.fetch_all(progress_query)
    print(f"  ✅ Exported {len(progress)} progress snapshots")

    return {
        "users": [dict(row) for row in users],
        "tasks": [dict(row) for row in tasks],
        "progress_snapshots": [dict(row) for row in progress]
    }


async def import_postgres_data(postgres_db: DatabaseService, data: dict):
    """Import data to PostgreSQL database"""
    print("📥 Importing to PostgreSQL...")

    # Import users
    for user in data["users"]:
        insert_query = """
        INSERT INTO users (id, username, email, hashed_password, role, is_active, is_approved, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (id) DO NOTHING
        """
        await postgres_db.execute(
            insert_query,
            user["id"], user["username"], user["email"], user["hashed_password"],
            user["role"], user["is_active"], user.get("is_approved", True),
            user["created_at"]
        )
    print(f"  ✅ Imported {len(data['users'])} users")

    # Import tasks
    for task in data["tasks"]:
        insert_query = """
        INSERT INTO tasks (
            task_id, filename, file_size, status, progress, result,
            error_message, uploaded_at, completed_at, owner_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (task_id) DO NOTHING
        """
        await postgres_db.execute(
            insert_query,
            task["task_id"], task["filename"], task["file_size"],
            task["status"], task["progress"], task.get("result"),
            task.get("error_message"), task["uploaded_at"],
            task.get("completed_at"), task.get("owner_id")
        )
    print(f"  ✅ Imported {len(data['tasks'])} tasks")

    # Import progress snapshots
    for snapshot in data["progress_snapshots"]:
        insert_query = """
        INSERT INTO progress_snapshots (task_id, progress, status, timestamp)
        VALUES (?, ?, ?, ?)
        """
        await postgres_db.execute(
            insert_query,
            snapshot["task_id"], snapshot["progress"],
            snapshot["status"], snapshot["timestamp"]
        )
    print(f"  ✅ Imported {len(data['progress_snapshots'])} progress snapshots")


async def migrate(sqlite_url: str, postgres_url: str):
    """Main migration function"""
    print("🚀 Starting migration: SQLite v4.x → PostgreSQL v5.0\n")

    # Connect to SQLite
    print(f"📂 Connecting to SQLite: {sqlite_url}")
    sqlite_db = DatabaseService(database_url=sqlite_url)
    await sqlite_db.init_db()

    # Connect to PostgreSQL
    print(f"🐘 Connecting to PostgreSQL: {postgres_url}\n")
    postgres_db = DatabaseService(database_url=postgres_url)
    await postgres_db.init_db()

    try:
        # Export from SQLite
        data = await export_sqlite_data(sqlite_db)

        # Import to PostgreSQL
        await import_postgres_data(postgres_db, data)

        print("\n✅ Migration completed successfully!")
        print(f"   - {len(data['users'])} users")
        print(f"   - {len(data['tasks'])} tasks")
        print(f"   - {len(data['progress_snapshots'])} progress snapshots")

    except Exception as e:
        print(f"\n❌ Migration failed: {e}")
        raise

    finally:
        # Close connections
        await sqlite_db.close()
        await postgres_db.close()


def main():
    parser = argparse.ArgumentParser(description="Migrate SQLite v4.x to PostgreSQL v5.0")
    parser.add_argument("--sqlite-url", required=True, help="SQLite database URL")
    parser.add_argument("--postgres-url", required=True, help="PostgreSQL database URL")
    args = parser.parse_args()

    asyncio.run(migrate(args.sqlite_url, args.postgres_url))


if __name__ == "__main__":
    main()
```

**Usage**:

```bash
# Make script executable
chmod +x scripts/migrate_v4_to_v5.py

# Run migration
python scripts/migrate_v4_to_v5.py \
  --sqlite-url "sqlite:///data/pcap_analyzer.db.v4_backup" \
  --postgres-url "postgresql://pcap:password@localhost:5432/pcap_analyzer"
```

---

## Backward Compatibility

### SQLite Still Supported ✅

**Development mode** continues to work with SQLite:

```bash
# No DATABASE_URL set → defaults to SQLite
unset DATABASE_URL

# Start application
uvicorn app.main:app --reload

# Uses: sqlite:///data/pcap_analyzer.db
```

### CLI Unchanged ✅

**CLI users** have zero breaking changes:

```bash
# Works exactly as v4.x
pcap_analyzer analyze capture.pcap
pcap_analyzer analyze capture.pcap --latency 0.5
```

### Database Abstraction Layer

`DatabasePool` handles both SQLite and PostgreSQL transparently:

- **Query translation**: `?` → `$1, $2` for PostgreSQL
- **Type conversion**: UUID (PostgreSQL) ↔ TEXT(36) (SQLite)
- **Timestamp parsing**: datetime objects ↔ ISO strings

---

## Rollback Procedure

### If Migration Fails

**Docker Compose**:

```bash
# Stop v5.0 containers
docker-compose down

# Restore v4.x backup
cp data/pcap_analyzer.db.v4_backup data/pcap_analyzer.db

# Checkout v4.x code
git checkout tags/v4.24.3  # Latest v4.x version

# Restart with old code
docker-compose up -d
```

**Kubernetes**:

```bash
# Rollback Helm release
helm rollback pcap-analyzer -n pcap-analyzer

# Restore PVC data from backup
kubectl cp ./data_backup pcap-analyzer/pcap-analyzer-0:/data

# Verify rollback
kubectl get pods -n pcap-analyzer
kubectl logs -n pcap-analyzer deployment/pcap-analyzer
```

---

## Troubleshooting

### Issue: "password authentication failed for user pcap"

**Cause**: Incorrect PostgreSQL password

**Solution**:
```bash
# Check .env file
cat .env | grep POSTGRES_PASSWORD

# Reset PostgreSQL password
docker exec -it pcap_postgres psql -U postgres
ALTER USER pcap WITH PASSWORD 'new_password';
\q

# Update .env
nano .env  # Set POSTGRES_PASSWORD=new_password

# Restart
docker-compose restart app
```

---

### Issue: "FATAL: database pcap_analyzer does not exist"

**Cause**: Database not created

**Solution**:
```bash
# Create database
docker exec -it pcap_postgres psql -U postgres
CREATE DATABASE pcap_analyzer OWNER pcap;
\q

# Run migrations
docker-compose exec app alembic upgrade head
```

---

### Issue: "SECRET_KEY environment variable is required in production"

**Cause**: Missing SECRET_KEY in production mode

**Solution**:
```bash
# Generate SECRET_KEY
export SECRET_KEY=$(openssl rand -hex 32)

# Add to .env
echo "SECRET_KEY=$SECRET_KEY" >> .env

# Restart
docker-compose restart app
```

---

### Issue: "User cannot login after migration"

**Cause**: User not approved (is_approved=false)

**Solution**:
```bash
# Get admin token
TOKEN=$(curl -s -X POST http://localhost:8000/api/token \
  -d "username=admin&password=<admin_password>" \
  | jq -r '.access_token')

# List users
curl -X GET http://localhost:8000/api/users \
  -H "Authorization: Bearer $TOKEN"

# Approve user
curl -X PUT http://localhost:8000/api/admin/users/<user_id>/approve \
  -H "Authorization: Bearer $TOKEN"
```

---

### Issue: "Connection pool exhausted"

**Cause**: Too many concurrent connections

**Solution**:
```bash
# Increase pool size in .env
echo "DATABASE_MAX_SIZE=20" >> .env

# Or increase PostgreSQL max_connections
docker exec -it pcap_postgres psql -U postgres
ALTER SYSTEM SET max_connections = 200;
SELECT pg_reload_conf();
\q

# Restart
docker-compose restart
```

---

### Issue: "Old tasks not visible after migration"

**Cause**: Tasks have NULL owner_id (legacy data)

**Diagnosis**:
- Regular users cannot see tasks with NULL owner_id
- Only admins can see legacy tasks

**Solution**:
```bash
# Option 1: Assign ownership to admin
docker exec -it pcap_postgres psql -U pcap -d pcap_analyzer
UPDATE tasks SET owner_id = (SELECT id FROM users WHERE role='admin' LIMIT 1) WHERE owner_id IS NULL;
\q

# Option 2: Login as admin to view legacy tasks
# (No changes needed, admin can see all tasks)
```

---

## Related Documentation

- [PostgreSQL Deployment Guide](POSTGRESQL_DEPLOYMENT.md)
- [Admin Approval Workflow Guide](ADMIN_APPROVAL_WORKFLOW.md)
- [CHANGELOG v5.0](../CHANGELOG.md#500---2025-12-21)
- [Security Best Practices](SECURITY_BEST_PRACTICES.md) (upcoming)
- [API Documentation](API_DOCUMENTATION.md)

---

## Support

**Issues**: https://github.com/MacFlurry/pcap_analyzer/issues
**Discussions**: https://github.com/MacFlurry/pcap_analyzer/discussions

---

**Last Updated**: 2025-12-21
**Version**: 5.0.0
**Migration Complexity**: MEDIUM ⚠️
