#!/bin/bash
# ============================================
# Docker Setup Verification Script
# PCAP Analyzer - PostgreSQL Configuration
# ============================================
# This script verifies the Docker Compose setup
# and PostgreSQL configuration

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

# Header
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Docker Setup Verification${NC}"
echo -e "${BLUE}  PCAP Analyzer with PostgreSQL${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Function to check test result
check_result() {
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ PASS${NC}: $1"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAIL${NC}: $1"
        ((TESTS_FAILED++))
    fi
}

# Test 1: Check Docker is running
echo -e "${BLUE}[1/10] Checking Docker daemon...${NC}"
docker info >/dev/null 2>&1
check_result "Docker daemon is running"
echo ""

# Test 2: Check Docker Compose is installed
echo -e "${BLUE}[2/10] Checking Docker Compose...${NC}"
docker-compose --version >/dev/null 2>&1
check_result "Docker Compose is installed"
echo ""

# Test 3: Validate docker-compose.yml syntax
echo -e "${BLUE}[3/10] Validating docker-compose.yml...${NC}"
docker-compose config --quiet 2>/dev/null
check_result "docker-compose.yml syntax is valid"
echo ""

# Test 4: Check .env.example exists
echo -e "${BLUE}[4/10] Checking .env.example...${NC}"
test -f .env.example
check_result ".env.example file exists"
echo ""

# Test 5: Check init_db.sql exists
echo -e "${BLUE}[5/10] Checking database initialization script...${NC}"
test -f scripts/init_db.sql
check_result "scripts/init_db.sql exists"
echo ""

# Test 6: Check cleanup script exists and is executable
echo -e "${BLUE}[6/10] Checking cleanup script...${NC}"
test -x scripts/cleanup_docker.sh
check_result "scripts/cleanup_docker.sh exists and is executable"
echo ""

# Test 7: Check if .env is in .gitignore
echo -e "${BLUE}[7/10] Checking .gitignore configuration...${NC}"
grep -q "^\.env$" .gitignore
check_result ".env is in .gitignore"
echo ""

# Test 8: Validate PostgreSQL service configuration
echo -e "${BLUE}[8/10] Checking PostgreSQL service configuration...${NC}"
docker-compose config | grep -q "postgres:"
check_result "PostgreSQL service is configured"
echo ""

# Test 9: Validate Adminer service configuration
echo -e "${BLUE}[9/10] Checking Adminer service configuration...${NC}"
docker-compose config | grep -q "adminer:"
check_result "Adminer service is configured"
echo ""

# Test 10: Check network configuration
echo -e "${BLUE}[10/10] Checking network configuration...${NC}"
docker-compose config | grep -q "pcap_network:"
check_result "pcap_network is configured"
echo ""

# Summary
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Verification Summary${NC}"
echo -e "${BLUE}============================================${NC}"
echo -e "Tests passed: ${GREEN}${TESTS_PASSED}${NC}"
echo -e "Tests failed: ${RED}${TESTS_FAILED}${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ All checks passed!${NC}"
    echo ""
    echo -e "${BLUE}Next steps:${NC}"
    echo "  1. Copy environment template: ${YELLOW}cp .env.example .env${NC}"
    echo "  2. Edit .env and set secure passwords"
    echo "  3. Generate passwords:"
    echo "     ${YELLOW}openssl rand -base64 32  # PostgreSQL password${NC}"
    echo "     ${YELLOW}openssl rand -hex 32     # Secret key${NC}"
    echo "  4. Start services:"
    echo "     ${YELLOW}docker-compose --profile dev up -d${NC}"
    echo "  5. Verify services:"
    echo "     ${YELLOW}docker-compose ps${NC}"
    echo "     ${YELLOW}curl http://localhost:8000/api/health${NC}"
    echo ""
    echo -e "${BLUE}Documentation:${NC}"
    echo "  - Quick start: ${YELLOW}DOCKER_POSTGRES_SETUP.md${NC}"
    echo "  - Environment: ${YELLOW}.env.example${NC}"
    echo "  - Main README: ${YELLOW}README.md${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}✗ Some checks failed. Please review the errors above.${NC}"
    echo ""
    echo -e "${BLUE}Troubleshooting:${NC}"
    echo "  - Ensure Docker is installed and running"
    echo "  - Run ${YELLOW}docker-compose config${NC} to check syntax"
    echo "  - Check that all required files exist"
    echo "  - See DOCKER_POSTGRES_SETUP.md for detailed setup"
    echo ""
    exit 1
fi
