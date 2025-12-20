#!/bin/bash
#
# Log rotation and archival script for PCAP Analyzer
#
# Purpose:
#   - Compress old log files older than 30 days
#   - Delete archived logs older than 90 days
#   - Maintain disk space and comply with retention policies
#
# Security:
#   - NIST SP 800-92: Log retention for compliance
#   - GDPR Article 5: Data minimization and storage limitation
#   - SOC 2: Log retention policies
#
# Usage:
#   ./rotate_logs.sh [log_directory]
#
# Cron Example (daily at 2 AM):
#   0 2 * * * /path/to/rotate_logs.sh /var/log/pcap_analyzer
#

set -euo pipefail

# Configuration
LOG_DIR="${1:-/var/log/pcap_analyzer}"
COMPRESS_AFTER_DAYS=30
DELETE_AFTER_DAYS=90
SCRIPT_NAME="$(basename "$0")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*"
}

# Validate log directory exists
if [[ ! -d "$LOG_DIR" ]]; then
    log_error "Log directory does not exist: $LOG_DIR"
    exit 1
fi

# Check write permissions
if [[ ! -w "$LOG_DIR" ]]; then
    log_error "No write permission for log directory: $LOG_DIR"
    exit 1
fi

log "Starting log rotation for: $LOG_DIR"

# Count files before operation
total_files=$(find "$LOG_DIR" -type f -name "*.log*" | wc -l)
log "Found $total_files log files"

# Compress old log files (older than COMPRESS_AFTER_DAYS days)
log "Compressing log files older than $COMPRESS_AFTER_DAYS days..."
compressed_count=0

while IFS= read -r -d '' file; do
    if [[ ! "$file" =~ \.gz$ ]]; then
        log "Compressing: $file"
        gzip "$file"
        ((compressed_count++))
    fi
done < <(find "$LOG_DIR" -type f -name "*.log.*" -mtime +"$COMPRESS_AFTER_DAYS" -print0 2>/dev/null)

if [[ $compressed_count -eq 0 ]]; then
    log "No log files to compress"
else
    log_success "Compressed $compressed_count log files"
fi

# Delete old archived logs (older than DELETE_AFTER_DAYS days)
log "Deleting archived logs older than $DELETE_AFTER_DAYS days..."
deleted_count=0

while IFS= read -r -d '' file; do
    log "Deleting: $file"
    rm -f "$file"
    ((deleted_count++))
done < <(find "$LOG_DIR" -type f -name "*.log.*.gz" -mtime +"$DELETE_AFTER_DAYS" -print0 2>/dev/null)

if [[ $deleted_count -eq 0 ]]; then
    log "No archived logs to delete"
else
    log_success "Deleted $deleted_count archived log files"
fi

# Calculate disk space usage
log "Calculating disk space usage..."
total_size=$(du -sh "$LOG_DIR" 2>/dev/null | cut -f1)
log "Current log directory size: $total_size"

# Count remaining files
remaining_files=$(find "$LOG_DIR" -type f -name "*.log*" | wc -l)
log "Remaining log files: $remaining_files"

# Summary
log_success "Log rotation completed successfully"
log "Summary:"
log "  - Compressed: $compressed_count files"
log "  - Deleted: $deleted_count files"
log "  - Remaining: $remaining_files files"
log "  - Total size: $total_size"

exit 0
