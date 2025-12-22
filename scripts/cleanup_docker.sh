#!/bin/bash
# ============================================
# Docker Cleanup Script
# PCAP Analyzer - Maintenance Utility
# ============================================
# This script removes old Docker images, containers, and volumes
# to free up disk space and maintain system health

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Header
echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Docker Cleanup - PCAP Analyzer${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Function to show disk usage
show_disk_usage() {
    echo -e "${BLUE}Current Docker disk usage:${NC}"
    docker system df
    echo ""
}

# Show initial disk usage
echo -e "${YELLOW}Before cleanup:${NC}"
show_disk_usage

# Confirm before cleanup
echo -e "${YELLOW}This will remove:${NC}"
echo "  - Stopped containers"
echo "  - Unused images older than 7 days"
echo "  - Unused volumes (WARNING: data loss possible)"
echo "  - Build cache"
echo ""
read -p "Do you want to continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Cleanup canceled${NC}"
    exit 0
fi

echo ""
echo -e "${GREEN}Starting cleanup...${NC}"
echo ""

# Stop and remove PCAP Analyzer containers (optional)
echo -e "${BLUE}1. Stopping PCAP Analyzer containers...${NC}"
if docker ps -a | grep -q "pcap"; then
    docker-compose down 2>/dev/null || true
    echo -e "${GREEN}   Containers stopped${NC}"
else
    echo -e "${YELLOW}   No PCAP Analyzer containers running${NC}"
fi
echo ""

# Remove stopped containers
echo -e "${BLUE}2. Removing stopped containers...${NC}"
STOPPED_CONTAINERS=$(docker container prune -f 2>&1)
echo "$STOPPED_CONTAINERS" | grep -q "Total reclaimed space: 0B" && \
    echo -e "${YELLOW}   No stopped containers to remove${NC}" || \
    echo -e "${GREEN}   $STOPPED_CONTAINERS${NC}"
echo ""

# Remove old images (older than 7 days)
echo -e "${BLUE}3. Removing unused images older than 7 days...${NC}"
OLD_IMAGES=$(docker image prune -af --filter "until=168h" 2>&1)
echo "$OLD_IMAGES" | grep -q "Total reclaimed space: 0B" && \
    echo -e "${YELLOW}   No old images to remove${NC}" || \
    echo -e "${GREEN}   $OLD_IMAGES${NC}"
echo ""

# Remove unused volumes (WITH CONFIRMATION)
echo -e "${BLUE}4. Removing unused volumes...${NC}"
echo -e "${RED}   WARNING: This will delete data in unused volumes!${NC}"
read -p "   Remove unused volumes? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    UNUSED_VOLUMES=$(docker volume prune -f 2>&1)
    echo "$UNUSED_VOLUMES" | grep -q "Total reclaimed space: 0B" && \
        echo -e "${YELLOW}   No unused volumes to remove${NC}" || \
        echo -e "${GREEN}   $UNUSED_VOLUMES${NC}"
else
    echo -e "${YELLOW}   Skipped volume cleanup${NC}"
fi
echo ""

# Remove build cache
echo -e "${BLUE}5. Removing build cache...${NC}"
BUILD_CACHE=$(docker builder prune -af 2>&1)
echo "$BUILD_CACHE" | grep -q "Total reclaimed space: 0B" && \
    echo -e "${YELLOW}   No build cache to remove${NC}" || \
    echo -e "${GREEN}   $BUILD_CACHE${NC}"
echo ""

# Remove unused networks
echo -e "${BLUE}6. Removing unused networks...${NC}"
UNUSED_NETWORKS=$(docker network prune -f 2>&1)
echo "$UNUSED_NETWORKS" | grep -q "deleted" && \
    echo -e "${GREEN}   $UNUSED_NETWORKS${NC}" || \
    echo -e "${YELLOW}   No unused networks to remove${NC}"
echo ""

# Show final disk usage
echo -e "${YELLOW}After cleanup:${NC}"
show_disk_usage

# Summary
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Cleanup Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  - Restart services: ${YELLOW}docker-compose up -d${NC}"
echo "  - Check status: ${YELLOW}docker ps${NC}"
echo "  - View logs: ${YELLOW}docker-compose logs -f${NC}"
echo ""
