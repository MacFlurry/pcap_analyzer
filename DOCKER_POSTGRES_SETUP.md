# PostgreSQL Docker Compose Setup - Quick Start Guide

## Overview

The PCAP Analyzer now includes a production-ready PostgreSQL setup with Docker Compose, including:

- PostgreSQL 16 Alpine (lightweight, secure)
- Adminer web UI for database management (development only)
- Network isolation with Docker networks
- Health checks for service dependencies
- Environment-based configuration
- Docker profiles for dev/prod environments

## Quick Start

### 1. Initial Setup

```bash
# Clone the repository
git clone https://github.com/MacFlurry/pcap_analyzer.git
cd pcap_analyzer

# Copy environment template
cp .env.example .env

# Edit .env and set secure passwords
nano .env  # or vim, code, etc.
```

### 2. Generate Secure Credentials

```bash
# Generate PostgreSQL password
openssl rand -base64 32

# Generate application secret key
openssl rand -hex 32

# Add these to your .env file:
# POSTGRES_PASSWORD=<generated-password>
# SECRET_KEY=<generated-secret-key>
```

### 3. Start Services

**Development mode (with Adminer):**
```bash
docker-compose --profile dev up -d
```

**Production mode (without Adminer):**
```bash
docker-compose --profile prod up -d
```

### 4. Verify Setup

```bash
# Check service status
docker-compose ps

# Expected output:
# pcap-analyzer   running   0.0.0.0:8000->8000/tcp
# pcap_postgres   running   0.0.0.0:5432->5432/tcp
# pcap_adminer    running   0.0.0.0:8080->8080/tcp (dev only)

# View logs
docker-compose logs -f

# Test application health
curl http://localhost:8000/api/health
```

## Access Points

| Service | URL | Credentials |
|---------|-----|-------------|
| PCAP Analyzer | http://localhost:8000 | N/A |
| Adminer (dev) | http://localhost:8080 | See below |
| PostgreSQL | localhost:5432 | See .env |

## Database Access

### Via Adminer Web UI

1. Open http://localhost:8080
2. Fill in connection details:
   - **System:** PostgreSQL
   - **Server:** `postgres` (container name)
   - **Username:** `pcap`
   - **Password:** (from .env POSTGRES_PASSWORD)
   - **Database:** `pcap_analyzer`
3. Click "Login"

### Via psql CLI

```bash
# Connect from host
docker exec -it pcap_postgres psql -U pcap -d pcap_analyzer

# Or using Docker Compose
docker-compose exec postgres psql -U pcap -d pcap_analyzer

# Example queries
\l              # List databases
\dt             # List tables
\du             # List users
\q              # Quit
```

### Via Application Connection String

The application automatically connects using:
```
postgresql://pcap:${POSTGRES_PASSWORD}@postgres:5432/pcap_analyzer
```

## Configuration

### Environment Variables (.env)

```bash
# Required
POSTGRES_PASSWORD=your_secure_password
SECRET_KEY=your_secret_key_32_chars_min

# Optional (with defaults)
APP_PORT=8000
POSTGRES_PORT=5432
ADMINER_PORT=8080
MAX_UPLOAD_SIZE_MB=500
REPORT_TTL_HOURS=24
LOG_LEVEL=INFO
```

### Docker Profiles

- **dev**: Includes all services (app, postgres, adminer)
- **prod**: Excludes Adminer (app, postgres only)

```bash
# Development
docker-compose --profile dev up -d

# Production
docker-compose --profile prod up -d

# Start specific service
docker-compose up -d postgres
```

## Database Management

### Backup Database

```bash
# Create backup
docker exec pcap_postgres pg_dump -U pcap pcap_analyzer > backup_$(date +%Y%m%d_%H%M%S).sql

# Backup with compression
docker exec pcap_postgres pg_dump -U pcap pcap_analyzer | gzip > backup_$(date +%Y%m%d_%H%M%S).sql.gz
```

### Restore Database

```bash
# From SQL file
docker exec -i pcap_postgres psql -U pcap -d pcap_analyzer < backup.sql

# From compressed file
gunzip -c backup.sql.gz | docker exec -i pcap_postgres psql -U pcap -d pcap_analyzer
```

### Reset Database

```bash
# Stop services
docker-compose down

# Remove volumes (WARNING: deletes all data)
docker-compose down -v

# Restart with fresh database
docker-compose --profile dev up -d
```

## Maintenance

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f postgres
docker-compose logs -f pcap-analyzer

# Last 100 lines
docker-compose logs --tail=100
```

### Cleanup Old Images

```bash
# Run cleanup script
./scripts/cleanup_docker.sh

# Manual cleanup
docker system prune -a
docker volume prune
```

### Update Services

```bash
# Rebuild application image
docker-compose build pcap-analyzer

# Pull latest PostgreSQL image
docker-compose pull postgres

# Restart with new images
docker-compose down
docker-compose --profile dev up -d
```

## Troubleshooting

### PostgreSQL Connection Issues

```bash
# Check if PostgreSQL is running
docker-compose ps postgres

# Check PostgreSQL health
docker exec pcap_postgres pg_isready -U pcap -d pcap_analyzer

# View PostgreSQL logs
docker-compose logs postgres
```

### Application Cannot Connect

```bash
# Verify environment variables
docker-compose config

# Check network connectivity
docker-compose exec pcap-analyzer ping postgres

# Test database connection manually
docker-compose exec pcap-analyzer python -c "
import psycopg2
conn = psycopg2.connect('postgresql://pcap:${POSTGRES_PASSWORD}@postgres:5432/pcap_analyzer')
print('Connection successful!')
conn.close()
"
```

### Permission Issues

```bash
# Fix volume permissions
docker-compose down
docker volume rm pcap_analyzer_postgres_data
docker-compose --profile dev up -d
```

### Port Conflicts

If ports are already in use, modify .env:
```bash
APP_PORT=8001
POSTGRES_PORT=5433
ADMINER_PORT=8081
```

## Security Best Practices

1. **Never commit .env to version control**
   ```bash
   # Verify .env is ignored
   git status --ignored
   ```

2. **Use strong passwords**
   ```bash
   # Minimum 16 characters, alphanumeric + symbols
   openssl rand -base64 32
   ```

3. **Restrict file permissions**
   ```bash
   chmod 600 .env
   ```

4. **Use different credentials per environment**
   - Development: dev.env
   - Staging: staging.env
   - Production: prod.env

5. **Regular backups**
   ```bash
   # Add to cron for daily backups
   0 2 * * * cd /path/to/pcap_analyzer && ./scripts/backup_postgres.sh
   ```

6. **Update regularly**
   ```bash
   docker-compose pull
   docker-compose up -d
   ```

## Architecture

```
┌─────────────────────────────────────────────┐
│  Docker Network: pcap_network               │
│                                             │
│  ┌──────────────┐    ┌──────────────┐      │
│  │              │    │              │      │
│  │  pcap-       │───→│  postgres    │      │
│  │  analyzer    │    │  :5432       │      │
│  │  :8000       │    │              │      │
│  │              │    └──────────────┘      │
│  └──────────────┘           │              │
│         │                   │              │
│         │            ┌──────────────┐      │
│         │            │              │      │
│         └───────────→│  adminer     │      │
│                      │  :8080       │      │
│                      │  (dev only)  │      │
│                      └──────────────┘      │
│                                             │
└─────────────────────────────────────────────┘
```

## Migration Path

### From SQLite to PostgreSQL

If you're migrating from SQLite:

1. **Export existing data**
   ```bash
   # Backup SQLite database
   cp data/pcap_analyzer.db data/pcap_analyzer.db.backup
   ```

2. **Start PostgreSQL**
   ```bash
   docker-compose --profile dev up -d postgres
   ```

3. **Run migrations**
   ```bash
   # Application will automatically create tables on first run
   docker-compose --profile dev up -d pcap-analyzer
   ```

4. **Verify migration**
   ```bash
   docker-compose logs pcap-analyzer | grep -i migration
   ```

## Next Steps

- [ ] Configure .env with secure credentials
- [ ] Start services with appropriate profile
- [ ] Access Adminer to verify database
- [ ] Upload test PCAP file
- [ ] Set up automated backups
- [ ] Configure monitoring/alerting
- [ ] Review security checklist

## Resources

- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Adminer Documentation](https://www.adminer.org/)
- [PCAP Analyzer GitHub](https://github.com/MacFlurry/pcap_analyzer)

## Support

For issues or questions:
- GitHub Issues: https://github.com/MacFlurry/pcap_analyzer/issues
- Security issues: See SECURITY.md
