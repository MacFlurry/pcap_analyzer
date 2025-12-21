# PostgreSQL Deployment Guide v5.0

**Version**: 5.0
**Date**: 2025-12-21
**Status**: Production Ready ✅

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Development Setup](#development-setup)
4. [Production Deployment](#production-deployment)
5. [Database Migrations](#database-migrations)
6. [Security Configuration](#security-configuration)
7. [Performance Tuning](#performance-tuning)
8. [Troubleshooting](#troubleshooting)

---

## Overview

PCAP Analyzer v5.0 uses **PostgreSQL** as the production database, replacing SQLite for multi-instance deployments. PostgreSQL provides:

- **Concurrent access** for multiple app instances
- **ACID compliance** for data integrity
- **Better performance** for large datasets
- **Advanced features**: UUIDs, foreign keys, transactions
- **Multi-tenant isolation** with row-level security

### Database Schema

**Tables**:
- `users` - User accounts (admin approval workflow)
- `tasks` - PCAP analysis tasks (with owner_id for multi-tenant)
- `progress_snapshots` - Real-time progress tracking

**Key Features**:
- UUID primary keys (PostgreSQL) / TEXT(36) (SQLite)
- `owner_id` foreign key for multi-tenant isolation
- Timestamps with timezone support
- Indexed columns for performance

---

## Quick Start

### Docker Compose (Recommended)

```bash
# Clone repository
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer

# Configure environment
cp .env.example .env
nano .env  # Set POSTGRES_PASSWORD and SECRET_KEY

# Start services
docker-compose --profile dev up -d

# Check logs
docker-compose logs -f

# Access
#  - Application: http://localhost:8000
#  - Adminer: http://localhost:8080
#  - PostgreSQL: localhost:5432
```

### Manual Setup

```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib  # Ubuntu/Debian
brew install postgresql@15  # macOS

# Start PostgreSQL
sudo systemctl start postgresql  # Linux
brew services start postgresql@15  # macOS

# Create database and user
sudo -u postgres psql <<EOF
CREATE USER pcap WITH PASSWORD 'your_secure_password';
CREATE DATABASE pcap_analyzer OWNER pcap;
GRANT ALL PRIVILEGES ON DATABASE pcap_analyzer TO pcap;
EOF

# Configure application
export DATABASE_URL="postgresql://pcap:your_secure_password@localhost:5432/pcap_analyzer"
export SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")

# Run migrations
alembic upgrade head

# Start application
uvicorn app.main:app --reload
```

---

## Development Setup

### Using Docker Compose

**File**: `docker-compose.yml`

```yaml
services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: pcap_analyzer
      POSTGRES_USER: pcap
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "${POSTGRES_PORT:-5432}:5432"

  adminer:
    image: adminer:latest
    ports:
      - "${ADMINER_PORT:-8080}:8080"
    depends_on:
      - postgres

  app:
    build: .
    environment:
      DATABASE_URL: postgresql://pcap:${POSTGRES_PASSWORD}@postgres:5432/pcap_analyzer
      SECRET_KEY: ${SECRET_KEY}
      DATABASE_SSL_MODE: disable  # Development only
    volumes:
      - ./data:/data
    ports:
      - "${APP_PORT:-8000}:8000"
    depends_on:
      - postgres
```

**Commands**:
```bash
# Start development environment
docker-compose --profile dev up -d

# View logs
docker-compose logs -f app

# Access PostgreSQL
docker exec -it pcap_postgres psql -U pcap -d pcap_analyzer

# Run migrations inside container
docker-compose exec app alembic upgrade head

# Stop services
docker-compose down

# Clean everything (WARNING: data loss)
docker-compose down -v
```

---

## Production Deployment

### Environment Variables

**Required**:
```bash
# Database connection
DATABASE_URL=postgresql://pcap:STRONG_PASSWORD@postgres.example.com:5432/pcap_analyzer

# Security
SECRET_KEY=<64-char-hex-string>  # Generate with: openssl rand -hex 32
CSRF_SECRET_KEY=<different-64-char-hex-string>

# Environment
ENVIRONMENT=production

# TLS/SSL (IMPORTANT for production)
DATABASE_SSL_MODE=verify-full  # require, verify-ca, or verify-full
```

**Optional**:
```bash
# Application
APP_PORT=8000
MAX_UPLOAD_SIZE_MB=500
REPORT_TTL_HOURS=24
LOG_LEVEL=INFO

# Database connection pool
DATABASE_MIN_SIZE=2
DATABASE_MAX_SIZE=10
```

### TLS/SSL Configuration

**Development** (local PostgreSQL):
```bash
DATABASE_SSL_MODE=disable
```

**Staging** (cloud PostgreSQL):
```bash
DATABASE_SSL_MODE=require  # Encrypted but no cert verification
```

**Production** (cloud PostgreSQL):
```bash
DATABASE_SSL_MODE=verify-full  # Encrypted + certificate verification
```

### Generating Secrets

```bash
# PostgreSQL password (32 bytes)
openssl rand -base64 32

# SECRET_KEY for JWT (64 hex chars)
openssl rand -hex 32

# CSRF_SECRET_KEY (must be different from SECRET_KEY)
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Admin Brise-Glace Password

**Option 1**: Kubernetes Secret (recommended)
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: admin-password
type: Opaque
stringData:
  admin_password: "YourSecureAdminPassword123!"
```

Mount at `/var/run/secrets/admin_password` in pod.

**Option 2**: Random generation (less secure)

If no secret file exists, a random password is generated on first boot and displayed on STDOUT:

```bash
# Check container logs to see admin password
docker logs pcap-analyzer 2>&1 | grep "ADMIN BRISE-GLACE"
kubectl logs deployment/pcap-analyzer | grep "ADMIN BRISE-GLACE"
```

**⚠️ IMPORTANT**: Change the admin password immediately after first login via:
```bash
PUT /api/users/me
{
  "current_password": "<generated_password>",
  "new_password": "<your_secure_password>"
}
```

---

## Database Migrations

### Using Alembic

**Check current version**:
```bash
alembic current
```

**Upgrade to latest**:
```bash
alembic upgrade head
```

**Downgrade one version**:
```bash
alembic downgrade -1
```

**View migration history**:
```bash
alembic history --verbose
```

**Create new migration** (for developers):
```bash
alembic revision --autogenerate -m "Add new table"
```

### Migration Timeline (v5.0)

| Migration | Description | Version |
|-----------|-------------|---------|
| `001_initial_schema` | Users, tasks, progress_snapshots | v4.23.0 |
| `002_add_owner_id` | Multi-tenant support (CWE-639) | v4.24.0 |
| `003_add_password_must_change` | Force password change on first login | v4.25.0 |
| `004_add_indexes` | Performance optimization | v5.0.0 |

### SQLite to PostgreSQL Migration

See [MIGRATION_GUIDE_v5.0.md](MIGRATION_GUIDE_v5.0.md) for complete migration instructions.

**Quick migration**:
```python
from app.utils.migration import migrate_database

# Export SQLite → JSON → Import to PostgreSQL
stats = await migrate_database(
    sqlite_url="sqlite:///data/pcap_analyzer.db",
    postgres_url="postgresql://pcap:password@localhost:5432/pcap_analyzer"
)
print(f"Migrated {stats['users']} users, {stats['tasks']} tasks")
```

---

## Security Configuration

### Connection Security

**Enforce TLS/SSL**:
```bash
# Production (cloud PostgreSQL)
DATABASE_SSL_MODE=verify-full
```

**PostgreSQL server** (`postgresql.conf`):
```conf
ssl = on
ssl_cert_file = '/path/to/server.crt'
ssl_key_file = '/path/to/server.key'
ssl_ca_file = '/path/to/root.crt'
```

### Authentication

**Password policy** (enforced by application):
- Minimum 12 characters
- bcrypt cost factor 12
- No password in logs (CWE-532 compliance)

**Admin approval workflow**:
1. User registers via `POST /api/register`
2. Account created with `is_approved=False`
3. Admin approves via `PUT /api/admin/users/{id}/approve`
4. User can now login

### Multi-Tenant Isolation

**Database level** (CWE-639):
- Each task has `owner_id` foreign key to `users.id`
- Application enforces `WHERE owner_id = current_user.id`
- Admins can see all tasks (`role='admin'`)

**Row-Level Security** (optional, future enhancement):
```sql
ALTER TABLE tasks ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_isolation ON tasks
  USING (owner_id = current_setting('app.current_user_id')::UUID);

CREATE POLICY admin_all_access ON tasks
  USING (current_setting('app.current_user_role') = 'admin');
```

### Audit Logging

All admin actions are logged:
```json
{
  "timestamp": "2025-12-21T20:30:00Z",
  "level": "WARNING",
  "message": "🔓 AUDIT: Admin john approved user alice (id: abc-123)"
}
```

---

## Performance Tuning

### Connection Pool

**Application settings** (asyncpg):
```python
pool = await asyncpg.create_pool(
    database_url,
    min_size=2,      # Minimum connections
    max_size=10,     # Maximum connections
    command_timeout=60,
    ssl=ssl_mode
)
```

**Recommended settings**:
- **Development**: min_size=1, max_size=5
- **Production**: min_size=2, max_size=10
- **High load**: min_size=5, max_size=20

### PostgreSQL Configuration

**File**: `postgresql.conf`

```conf
# Connection limits
max_connections = 100

# Memory
shared_buffers = 256MB
effective_cache_size = 1GB

# Query performance
work_mem = 4MB
maintenance_work_mem = 64MB

# Write-ahead log
wal_buffers = 16MB
checkpoint_completion_target = 0.9

# Logging
log_min_duration_statement = 1000  # Log slow queries (>1s)
```

### Indexes

**Critical indexes** (already created by migrations):
```sql
-- Users table
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);

-- Tasks table
CREATE INDEX idx_tasks_owner_id ON tasks(owner_id);
CREATE INDEX idx_tasks_status ON tasks(status);
CREATE INDEX idx_tasks_uploaded_at ON tasks(uploaded_at DESC);
```

### Query Optimization

**Slow query example** (missing owner_id filter):
```sql
-- BAD (table scan)
SELECT * FROM tasks ORDER BY uploaded_at DESC LIMIT 100;

-- GOOD (index scan)
SELECT * FROM tasks
WHERE owner_id = 'abc-123'
ORDER BY uploaded_at DESC
LIMIT 100;
```

**Analyze query performance**:
```sql
EXPLAIN ANALYZE SELECT * FROM tasks WHERE owner_id = 'abc-123';
```

---

## Troubleshooting

### Connection Issues

**Error**: `password authentication failed for user "pcap"`

**Solution**:
```bash
# Check password in .env
cat .env | grep POSTGRES_PASSWORD

# Reset PostgreSQL password
sudo -u postgres psql
ALTER USER pcap WITH PASSWORD 'new_password';

# Update DATABASE_URL
export DATABASE_URL="postgresql://pcap:new_password@localhost:5432/pcap_analyzer"
```

---

**Error**: `FATAL: database "pcap_analyzer" does not exist`

**Solution**:
```bash
sudo -u postgres psql
CREATE DATABASE pcap_analyzer OWNER pcap;
```

---

**Error**: `connection refused (port 5432)`

**Solution**:
```bash
# Check if PostgreSQL is running
sudo systemctl status postgresql

# Start PostgreSQL
sudo systemctl start postgresql

# Check port
sudo netstat -tlnp | grep 5432
```

---

### SSL/TLS Issues

**Error**: `SSL connection has been closed unexpectedly`

**Solution**:
```bash
# Development: disable SSL
DATABASE_SSL_MODE=disable

# Production: verify server certificate
DATABASE_SSL_MODE=verify-full
```

---

### Migration Issues

**Error**: `alembic.util.exc.CommandError: Can't locate revision identified by 'xyz'`

**Solution**:
```bash
# Check current version
alembic current

# Stamp to specific version
alembic stamp head

# Re-run migrations
alembic upgrade head
```

---

**Error**: `column "owner_id" does not exist`

**Solution**:
```bash
# Run migration to add owner_id
alembic upgrade head

# Or manually add column
psql -U pcap -d pcap_analyzer <<EOF
ALTER TABLE tasks ADD COLUMN owner_id TEXT REFERENCES users(id);
CREATE INDEX idx_tasks_owner_id ON tasks(owner_id);
EOF
```

---

### Performance Issues

**Slow queries** (>1s):

**Solution**:
```sql
-- Enable slow query logging
ALTER SYSTEM SET log_min_duration_statement = 1000;
SELECT pg_reload_conf();

-- Analyze tables
ANALYZE users;
ANALYZE tasks;

-- Reindex if needed
REINDEX TABLE tasks;
```

---

**Connection pool exhausted**:

**Solution**:
```bash
# Increase max_size in application
DATABASE_MAX_SIZE=20

# Or increase PostgreSQL max_connections
sudo -u postgres psql
ALTER SYSTEM SET max_connections = 200;
SELECT pg_reload_conf();
```

---

## References

- [PostgreSQL Documentation](https://www.postgresql.org/docs/15/)
- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [asyncpg Documentation](https://magicstack.github.io/asyncpg/)
- [OWASP Database Security](https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html)
- [Migration Guide v5.0](MIGRATION_GUIDE_v5.0.md)
- [Security Best Practices](SECURITY_BEST_PRACTICES.md)

---

**Last Updated**: 2025-12-21
**Version**: 5.0.0
**Status**: Production Ready ✅
