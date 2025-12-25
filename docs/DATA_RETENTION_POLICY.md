# Data Retention and Cleanup Policy

This document describes how PCAP Analyzer manages storage, data retention, and automatic cleanup to ensure system performance and GDPR compliance.

## Overview

PCAP Analyzer stores three main types of data:
1. **Physical Files**: PCAP uploads and generated reports (HTML/JSON).
2. **Database Records**: User information, task metadata, and analysis progress.
3. **Audit Logs**: Records of administrative actions.

## 1. Physical Files Retention

Storage location is defined by the `DATA_DIR` environment variable (default: `/data`).

### PCAP Uploads
- **Purpose**: Temporary storage for analysis.
- **Retention**: Deleted **immediately** after successful analysis or failure.
- **Cleanup Job**: `cleanup_old_files` (Hourly) also removes orphaned PCAPs older than 24h.

### Analysis Reports (HTML & JSON)
- **Purpose**: Visualization and export of results.
- **Default TTL**: 24 hours.
- **Cleanup Job**: `cleanup_old_files` runs every hour and deletes files older than `REPORT_TTL_HOURS`.

## 2. Automated Cleanup Jobs

The `CleanupScheduler` (`app/services/cleanup.py`) manages the following tasks:

| Job ID | Frequency | Description |
|--------|-----------|-------------|
| `cleanup_old_files` | Hourly | Deletes expired reports and temporary uploads from disk. |
| `cleanup_orphaned_tasks` | Every 5 mins | Detects tasks stuck in "PROCESSING" (e.g., worker crash) and marks them as FAILED. |
| `cleanup_orphaned_files` | Daily (3:00 AM) | **Safety Net**: Deletes any file on disk that has no corresponding record in the database. |

## 3. GDPR "Right to be Forgotten"

PCAP Analyzer strictly enforces data deletion when a user account is removed.

### User Deletion Workflow
When an administrator deletes a user account:
1. **File Cleanup**: All PCAP uploads and reports owned by the user are immediately deleted from disk.
2. **Database Cleanup**: All associated records (tasks, snapshots, password history) are deleted via `CASCADE` constraints.
3. **Audit**: The deletion is logged with the count of files removed.

## 4. Configuration

You can customize retention periods using environment variables:

```bash
# Time in hours before a report is considered expired
REPORT_TTL_HOURS=24

# Root directory for storage
DATA_DIR=/data
```

## 5. Troubleshooting

If you notice storage growing unexpectedly:
1. Check the logs for `Cleanup scheduler started`.
2. Verify that the daily `cleanup_orphaned_files` job is running.
3. Ensure the application has write/delete permissions on the `DATA_DIR`.

```bash
# Manual check of orphaned files in logs
kubectl logs -n pcap-analyzer -l app.kubernetes.io/name=pcap-analyzer | grep "Deleted orphaned file"
```
