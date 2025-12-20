# PostgreSQL Migration Guide

This document explains how to migrate the pcap_analyzer project from SQLite to PostgreSQL for production deployments.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Migration Process](#migration-process)
4. [Configuration](#configuration)
5. [Running Migrations](#running-migrations)
6. [Verification](#verification)
7. [Rollback](#rollback)
8. [Troubleshooting](#troubleshooting)

## Overview

The pcap_analyzer project now supports both SQLite and PostgreSQL databases:

- **SQLite**: Recommended for development and testing
- **PostgreSQL**: Recommended for production deployments

### Key Features

- **Alembic migrations**: Database schema versioning and migration management
- **Dual database support**: Automatic detection of database type from `DATABASE_URL`
- **Connection pooling**: asyncpg connection pooling for PostgreSQL
- **Enhanced schema**: User approval workflow with new fields
- **Backward compatibility**: Existing SQLite deployments continue to work

### New Schema Changes

The migration adds the following enhancements:

#### Users Table
- `is_approved BOOLEAN DEFAULT FALSE` - User approval status
- `approved_by UUID REFERENCES users(id)` - Admin who approved the user
- `approved_at TIMESTAMP` - Timestamp of approval

#### Tasks Table
- `ON DELETE CASCADE` for `owner_id` foreign key (PostgreSQL only)

## Prerequisites

Before migrating, ensure you have:

1. **PostgreSQL 12+** installed and running
2. **Python dependencies** installed:
   ```bash
   pip install -r requirements-web.txt
   ```
3. **Database created**:
   ```sql
   CREATE DATABASE pcap_analyzer;
   CREATE USER pcap_user WITH PASSWORD 'your_secure_password';
   GRANT ALL PRIVILEGES ON DATABASE pcap_analyzer TO pcap_user;
   ```

## Migration Process

### Step 1: Install Dependencies

```bash
# Install PostgreSQL-specific dependencies
pip install alembic asyncpg psycopg2-binary
```

### Step 2: Configure Database URL

Create a `.env` file from the example:

```bash
cp .env.example .env
```

Edit `.env` and set the `DATABASE_URL`:

```bash
# For PostgreSQL:
DATABASE_URL=postgresql://pcap_user:your_password@localhost:5432/pcap_analyzer

# For SQLite (default):
# DATABASE_URL=sqlite:///data/pcap_analyzer.db
```

### Step 3: Run Migrations

```bash
# Apply all migrations
alembic upgrade head
```

This will create the following tables:
- `users` - User accounts with approval workflow
- `tasks` - PCAP analysis tasks
- `progress_snapshots` - Progress tracking

### Step 4: Verify Migration

```bash
# Check migration history
alembic history

# Check current version
alembic current
```

You should see output similar to:
```
<base> -> eba0e1bcc7ec (head), initial_schema_with_user_approval
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | Database connection string | `sqlite:///data/pcap_analyzer.db` |
| `SECRET_KEY` | JWT secret key | **REQUIRED** |
| `DATA_DIR` | Data directory for uploads | `/data` |
| `REPORT_TTL_HOURS` | Report retention time | `24` |

### Database URL Format

**SQLite:**
```
sqlite:///path/to/database.db
```

**PostgreSQL:**
```
postgresql://username:password@hostname:port/database_name
```

**PostgreSQL with asyncpg (recommended):**
```
postgresql+asyncpg://username:password@hostname:port/database_name
```

## Running Migrations

### Create a New Migration

```bash
# Auto-generate migration from schema changes
alembic revision --autogenerate -m "description_of_changes"

# Create empty migration template
alembic revision -m "description_of_changes"
```

### Apply Migrations

```bash
# Apply all pending migrations
alembic upgrade head

# Apply specific version
alembic upgrade <revision_id>

# Apply one migration at a time
alembic upgrade +1
```

### Rollback Migrations

```bash
# Rollback one migration
alembic downgrade -1

# Rollback to specific version
alembic downgrade <revision_id>

# Rollback all migrations
alembic downgrade base
```

## Verification

### 1. Check Database Connection

```python
import asyncio
from app.services.postgres_database import DatabasePool

async def test_connection():
    db = DatabasePool()
    await db.connect()
    print(f"Connected to {db.db_type} database")

    # Test query
    result = await db.fetch_one("SELECT 1 as test")
    print(f"Test query result: {result}")

    await db.close()

asyncio.run(test_connection())
```

### 2. Verify Tables

**PostgreSQL:**
```sql
-- List all tables
\dt

-- Describe users table
\d users

-- Check foreign keys
SELECT
    tc.table_name,
    kcu.column_name,
    ccu.table_name AS foreign_table_name,
    ccu.column_name AS foreign_column_name
FROM information_schema.table_constraints AS tc
JOIN information_schema.key_column_usage AS kcu
  ON tc.constraint_name = kcu.constraint_name
JOIN information_schema.constraint_column_usage AS ccu
  ON ccu.constraint_name = tc.constraint_name
WHERE constraint_type = 'FOREIGN KEY';
```

**SQLite:**
```sql
-- List all tables
.tables

-- Show users table schema
.schema users

-- Check foreign keys
PRAGMA foreign_key_list(tasks);
```

### 3. Test User Approval Workflow

```python
import asyncio
from app.services.user_database import get_user_db_service
from app.models.user import UserCreate, UserRole

async def test_approval():
    db = get_user_db_service()
    await db.init_db()

    # Create admin (auto-approved)
    admin_data = UserCreate(
        username="testadmin",
        email="admin@test.com",
        password="SecurePassword123"
    )
    admin = await db.create_user(admin_data, role=UserRole.ADMIN)
    print(f"Admin approved: {admin.is_approved}")

    # Create regular user (requires approval)
    user_data = UserCreate(
        username="testuser",
        email="user@test.com",
        password="SecurePassword123"
    )
    user = await db.create_user(user_data)
    print(f"User approved: {user.is_approved}")

    # Approve user
    await db.approve_user(user.id, admin.id)

    # Verify approval
    approved_user = await db.get_user_by_id(user.id)
    print(f"User now approved: {approved_user.is_approved}")
    print(f"Approved by: {approved_user.approved_by}")

asyncio.run(test_approval())
```

## Rollback

If you need to rollback the migration:

### Option 1: Rollback via Alembic

```bash
# Rollback to previous version
alembic downgrade -1

# Rollback completely
alembic downgrade base
```

### Option 2: Manual Rollback

**Drop all tables:**
```sql
-- PostgreSQL
DROP TABLE IF EXISTS progress_snapshots CASCADE;
DROP TABLE IF EXISTS tasks CASCADE;
DROP TABLE IF EXISTS users CASCADE;
DROP TABLE IF EXISTS alembic_version;

-- SQLite
DROP TABLE IF EXISTS progress_snapshots;
DROP TABLE IF EXISTS tasks;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS alembic_version;
```

### Option 3: Switch Back to SQLite

Simply change `DATABASE_URL` in `.env`:

```bash
DATABASE_URL=sqlite:///data/pcap_analyzer.db
```

The application will automatically use SQLite.

## Troubleshooting

### Issue: "alembic command not found"

**Solution:**
```bash
pip install alembic
```

### Issue: "cannot import name 'asyncpg'"

**Solution:**
```bash
pip install asyncpg psycopg2-binary
```

### Issue: "connection refused" (PostgreSQL)

**Solution:**
- Check PostgreSQL is running: `systemctl status postgresql`
- Verify connection details in `DATABASE_URL`
- Check firewall rules
- Test connection: `psql -h localhost -U pcap_user pcap_analyzer`

### Issue: "FATAL: database does not exist"

**Solution:**
```bash
# Create database
createdb pcap_analyzer

# Or via SQL
psql -U postgres
CREATE DATABASE pcap_analyzer;
```

### Issue: "permission denied for table"

**Solution:**
```sql
-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE pcap_analyzer TO pcap_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO pcap_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO pcap_user;
```

### Issue: Migration fails with "column already exists"

**Solution:**
```bash
# Mark migration as applied without running it
alembic stamp head
```

### Issue: "password cannot be longer than 72 bytes" (bcrypt error)

**Solution:**
This is a known issue with bcrypt 5.x and Python 3.14. It doesn't affect production use, only tests.

**Workaround:**
```bash
# Downgrade bcrypt
pip install 'bcrypt<5.0'
```

## Docker Deployment

### docker-compose.yml Example

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: pcap_analyzer
      POSTGRES_USER: pcap_user
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  app:
    build: .
    depends_on:
      - postgres
    environment:
      DATABASE_URL: postgresql://pcap_user:${POSTGRES_PASSWORD}@postgres:5432/pcap_analyzer
      SECRET_KEY: ${SECRET_KEY}
    command: >
      sh -c "
        alembic upgrade head &&
        uvicorn app.main:app --host 0.0.0.0 --port 8000
      "
    ports:
      - "8000:8000"

volumes:
  postgres_data:
```

### Startup Command

```bash
# Apply migrations and start app
docker-compose up -d
```

## Best Practices

1. **Always backup before migrating**: `pg_dump` (PostgreSQL) or copy SQLite file
2. **Test migrations in staging first**: Never run untested migrations in production
3. **Use alembic for all schema changes**: Don't manually modify database schema
4. **Keep migrations idempotent**: Migrations should be safe to run multiple times
5. **Document migration dependencies**: Note any data migrations or manual steps
6. **Monitor migration performance**: Some migrations may take time on large datasets
7. **Use connection pooling**: Configure asyncpg pool size based on workload

## References

- [Alembic Documentation](https://alembic.sqlalchemy.org/)
- [asyncpg Documentation](https://magicstack.github.io/asyncpg/)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [FastAPI Database Guide](https://fastapi.tiangolo.com/tutorial/sql-databases/)

## Support

For issues or questions:

1. Check the [Troubleshooting](#troubleshooting) section
2. Review the [GitHub Issues](https://github.com/your-repo/issues)
3. Contact the development team

---

**Last Updated:** December 20, 2025
**Migration Version:** v1.0.0 (eba0e1bcc7ec)
