#!/bin/bash
# ============================================
# PCAP Analyzer - Docker Entrypoint
# Generates random admin password and stores in /var/run/secrets
# ============================================

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Secrets directory
SECRETS_DIR="/var/run/secrets"
ADMIN_PASSWORD_FILE="${SECRETS_DIR}/admin_password"

# Create secrets directory if it doesn't exist
mkdir -p "${SECRETS_DIR}"

# Generate random admin password (24 chars, URL-safe)
if [ ! -f "${ADMIN_PASSWORD_FILE}" ]; then
    echo -e "${CYAN}🔐 Generating new admin password...${NC}"

    # Generate secure random password using Python
    ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24)[:24])")

    # Store in secrets file
    echo -n "${ADMIN_PASSWORD}" > "${ADMIN_PASSWORD_FILE}"
    chmod 600 "${ADMIN_PASSWORD_FILE}"

    echo -e "${GREEN}✅ Admin password generated and stored in ${ADMIN_PASSWORD_FILE}${NC}"
    echo ""
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${MAGENTA}🔒 ADMIN CREDENTIALS${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${GREEN}Username:${NC} admin"
    echo -e "${GREEN}Password:${NC} ${ADMIN_PASSWORD}"
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${RED}⚠️  SAVE THIS PASSWORD - IT WON'T BE SHOWN AGAIN!${NC}"
    echo -e "${CYAN}📝 Access it inside container: cat /var/run/secrets/admin_password${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo ""
else
    echo -e "${BLUE}ℹ️  Admin password already exists in ${ADMIN_PASSWORD_FILE}${NC}"
    echo -e "${CYAN}📝 To view: cat ${ADMIN_PASSWORD_FILE}${NC}"
fi

# Run database migrations if using PostgreSQL
if [ -n "${DATABASE_URL}" ] && [[ "${DATABASE_URL}" == postgresql* ]]; then
    echo -e "${CYAN}🗄️  Running database migrations (PostgreSQL detected)...${NC}"

    # Wait for PostgreSQL to be ready (max 30s)
    echo -e "${BLUE}⏳ Waiting for PostgreSQL to be ready...${NC}"
    for i in {1..30}; do
        if python3 -c "import asyncio; import asyncpg; asyncio.run(asyncpg.connect('${DATABASE_URL}'))" 2>/dev/null; then
            echo -e "${GREEN}✅ PostgreSQL is ready!${NC}"
            break
        fi
        if [ $i -eq 30 ]; then
            echo -e "${RED}❌ PostgreSQL not ready after 30s, exiting...${NC}"
            exit 1
        fi
        sleep 1
    done

    # Run Alembic migrations
    echo -e "${CYAN}📋 Running Alembic migrations...${NC}"
    alembic upgrade head

    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Database migrations completed successfully!${NC}"
    else
        echo -e "${RED}❌ Database migration failed, exiting...${NC}"
        exit 1
    fi
else
    echo -e "${BLUE}ℹ️  Using SQLite (no migrations needed)${NC}"
fi

# Execute the main command (uvicorn)
echo -e "${GREEN}🚀 Starting PCAP Analyzer...${NC}"
exec "$@"
