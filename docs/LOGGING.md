# PCAP Analyzer Logging Guide

## Overview

This document describes the centralized logging system for PCAP Analyzer, implemented according to:

- **OpenSSF Secure Coding Guide**: Comprehensive logging for security events
- **NIST SP 800-92**: Guide to Computer Security Log Management
- **OWASP Logging Cheat Sheet**: Secure logging practices
- **Python logging best practices**: `logging.config`, handlers, formatters

## Table of Contents

1. [Logging Levels](#logging-levels)
2. [Log File Locations](#log-file-locations)
3. [Log Rotation Policy](#log-rotation-policy)
4. [Configuration](#configuration)
5. [Security Audit Logging](#security-audit-logging)
6. [SIEM Integration](#siem-integration)
7. [GDPR Compliance](#gdpr-compliance)
8. [Troubleshooting](#troubleshooting)

---

## Logging Levels

### Available Levels

| Level | Description | Use Case | Production |
|-------|-------------|----------|-----------|
| `DEBUG` | Detailed diagnostic information | Development debugging | **NEVER** |
| `INFO` | Informational messages | Normal operations | **Default** |
| `WARNING` | Warning messages (non-critical issues) | Potential problems | Yes |
| `ERROR` | Error messages (failures) | Application errors | Yes |
| `CRITICAL` | Critical failures | System failures | Yes |

### When to Use Each Level

#### DEBUG (Development Only)
```python
logger.debug(f"Processing packet {packet_num} with flags {tcp_flags}")
logger.debug(f"Flow state: {flow_state}")
```

**WARNING**: Never use DEBUG in production. It may expose:
- Packet contents (potentially sensitive data)
- Internal state information
- File paths and system information
- Configuration details

#### INFO (Production Default)
```python
logger.info("PCAP analysis started")
logger.info(f"Processed {packet_count} packets in {duration:.2f}s")
logger.info("Report generated successfully")
```

#### WARNING (Potential Issues)
```python
logger.warning("Memory usage approaching limit (85%)")
logger.warning(f"Retransmission rate high: {retrans_rate:.1f}%")
logger.warning("PCAP-NG detected, converting to PCAP")
```

#### ERROR (Failures)
```python
logger.error(f"Failed to parse packet {packet_num}: {error}")
logger.error("Report generation failed")
logger.error(f"SSH connection failed: {error}")
```

#### CRITICAL (Security Events)
```python
logger.critical("Resource limit exceeded (potential DoS)")
logger.critical("Decompression bomb detected")
logger.critical("Path traversal attempt blocked")
```

---

## Log File Locations

### Default Locations

```
logs/
├── pcap_analyzer.log          # Main application log
├── pcap_analyzer.log.1        # Rotated log (1st backup)
├── pcap_analyzer.log.2        # Rotated log (2nd backup)
├── ...
├── security_audit.log         # Security events only
├── security_audit.log.1       # Rotated audit log
└── ...
```

### Production Locations (Recommended)

```
/var/log/pcap_analyzer/
├── pcap_analyzer.log
├── security_audit.log
└── archive/                   # Compressed old logs
    ├── pcap_analyzer.log.1.gz
    ├── pcap_analyzer.log.2.gz
    └── ...
```

### File Permissions

All log files are created with **0600 permissions** (owner read/write only):

```bash
-rw------- 1 user user 1.2M Dec 20 16:00 pcap_analyzer.log
-rw------- 1 user user 856K Dec 20 16:00 security_audit.log
```

This prevents unauthorized access to logs which may contain sensitive information.

---

## Log Rotation Policy

### Automatic Rotation

Log rotation is handled automatically by `RotatingFileHandler`:

#### Main Application Log
- **Max file size**: 10 MB
- **Backup count**: 5 files
- **Total storage**: ~50 MB
- **Retention**: Until manually deleted

#### Security Audit Log
- **Max file size**: 10 MB
- **Backup count**: 10 files
- **Total storage**: ~100 MB
- **Retention**: Longer for compliance

### Manual Rotation (Cron Job)

Use the provided `scripts/rotate_logs.sh` script for additional compression and archival:

```bash
# Run daily at 2 AM
0 2 * * * /path/to/pcap_analyzer/scripts/rotate_logs.sh /var/log/pcap_analyzer
```

#### Rotation Policy

1. **Compress** logs older than 30 days:
   ```bash
   pcap_analyzer.log.1 → pcap_analyzer.log.1.gz
   ```

2. **Delete** archived logs older than 90 days:
   ```bash
   pcap_analyzer.log.10.gz (90+ days old) → deleted
   ```

#### Customization

Edit `scripts/rotate_logs.sh` to adjust retention periods:

```bash
COMPRESS_AFTER_DAYS=30    # Compress after N days
DELETE_AFTER_DAYS=90      # Delete after N days
```

---

## Configuration

### CLI Options

Control logging behavior via command-line options:

```bash
# Set log level
pcap_analyzer analyze capture.pcap --log-level INFO

# Specify log file location
pcap_analyzer analyze capture.pcap --log-file /var/log/app.log

# Disable file logging
pcap_analyzer analyze capture.pcap --no-log-file

# Enable JSON format (for SIEM)
pcap_analyzer analyze capture.pcap --log-format json

# Enable audit logging
pcap_analyzer analyze capture.pcap --enable-audit-log
```

### YAML Configuration

Use `config/logging.yaml` for advanced configuration:

```yaml
version: 1
disable_existing_loggers: false

formatters:
  standard:
    format: '%(asctime)s [%(levelname)s] %(name)s:%(lineno)d - %(message)s'
    datefmt: '%Y-%m-%d %H:%M:%S'

handlers:
  console:
    class: logging.StreamHandler
    level: INFO
    formatter: standard

  file:
    class: logging.handlers.RotatingFileHandler
    level: INFO
    formatter: standard
    filename: logs/pcap_analyzer.log
    maxBytes: 10485760  # 10MB
    backupCount: 5

root:
  level: INFO
  handlers: [console, file]
```

Load custom configuration:

```bash
pcap_analyzer analyze capture.pcap --log-config /path/to/logging.yaml
```

### Programmatic Configuration

```python
from src.utils.logging_config import setup_logging

# Basic setup
setup_logging(
    log_dir="logs",
    log_level="INFO",
    enable_console=True,
    enable_file=True,
    enable_audit=True
)

# Advanced setup
setup_logging(
    log_dir="/var/log/pcap_analyzer",
    log_level="WARNING",
    enable_console=False,  # No console in production
    enable_file=True,
    enable_audit=True,
    log_format="json"  # For SIEM integration
)
```

---

## Security Audit Logging

### Purpose

Security audit logs track security-relevant events separately from application logs:

- File validation failures (malicious uploads)
- Resource limit violations (DoS attempts)
- Authentication failures (brute force)
- Path traversal attempts (directory traversal)
- Decompression bombs (zip bombs)
- Suspicious network activity (from PCAP analysis)

### Audit Log Format

```
2025-12-20 16:30:15 [SECURITY] src.utils.audit_logger - event_type='file_validation_failure' | severity='high' | message='File validation failed: Invalid PCAP magic bytes' | details={'file_path': '/tmp/upload.pcap', 'reason': 'Invalid magic bytes', 'magic_bytes': 'b"\\x00\\x00\\x00\\x00"'}
```

### Using Audit Logger

```python
from src.utils.audit_logger import AuditLogger

audit = AuditLogger()

# Log file validation failure
audit.log_file_validation_failure(
    file_path="/tmp/upload.pcap",
    reason="Invalid PCAP magic bytes",
    details={"magic_bytes": magic_bytes.hex()}
)

# Log resource limit violation
audit.log_resource_limit_hit(
    limit_type="memory",
    limit_value="4.0 GB",
    current_value="4.2 GB",
    details={"pcap_file": "large_capture.pcap"}
)

# Log decompression bomb
audit.log_decompression_bomb(
    file_path="compressed.pcap.gz",
    compressed_size=1024,
    uncompressed_size=10485760,
    expansion_ratio=10240.0
)
```

### Convenience Functions

```python
from src.utils.audit_logger import (
    log_file_validation_failure,
    log_resource_limit_hit,
    log_decompression_bomb,
    log_path_traversal_attempt,
    log_suspicious_network_activity
)

# Direct function calls
log_file_validation_failure(
    file_path="/tmp/upload.pcap",
    reason="File too large"
)

log_suspicious_network_activity(
    activity_type="port_scan",
    source_ip="192.168.1.100",
    destination_ip="10.0.0.50",
    ports_scanned=1024
)
```

---

## SIEM Integration

### Structured Logging

Enable JSON format for SIEM ingestion:

```bash
pcap_analyzer analyze capture.pcap --log-format json
```

#### JSON Log Format

```json
{
  "asctime": "2025-12-20 16:30:15",
  "name": "src.utils.audit_logger",
  "levelname": "CRITICAL",
  "message": "event_type='decompression_bomb_detected' | severity='critical' | ...",
  "pathname": "/path/to/audit_logger.py",
  "lineno": 123
}
```

### SIEM Parsing Examples

#### Splunk

```spl
index=pcap_analyzer sourcetype=json
| spath event_type
| search event_type=*
| stats count by event_type, severity
```

#### ELK Stack (Elasticsearch)

```json
{
  "filebeat.inputs": [{
    "type": "log",
    "enabled": true,
    "paths": ["/var/log/pcap_analyzer/*.log"],
    "json.keys_under_root": true,
    "json.add_error_key": true
  }]
}
```

#### Graylog

Use GELF input with JSON parser:

```bash
# Send logs to Graylog via UDP
logger --server graylog.example.com --port 12201 --file /var/log/pcap_analyzer/security_audit.log
```

### Syslog Integration

For centralized syslog servers:

```python
# Add to config/logging.yaml
handlers:
  syslog:
    class: logging.handlers.SysLogHandler
    level: INFO
    formatter: standard
    address: ['syslog.example.com', 514]
    facility: LOG_LOCAL0
```

---

## GDPR Compliance

### Data Minimization

- **Minimize PII in logs**: Never log full packet payloads, user passwords, or sensitive data
- **Audit logs only**: Log minimal information required for security analysis

### Storage Limitation

Log retention policies comply with GDPR Article 5(1)(e):

| Log Type | Retention | Justification |
|----------|-----------|---------------|
| Application logs | 30 days | Operational troubleshooting |
| Security audit logs | 90 days | Compliance and incident response |
| Compressed archives | 1 year | Long-term forensic analysis |

Configure retention in `scripts/rotate_logs.sh`:

```bash
COMPRESS_AFTER_DAYS=30    # Archive after 30 days
DELETE_AFTER_DAYS=90      # Delete after 90 days
```

### Right to Erasure

If logs contain personal data and a data subject requests erasure:

1. Identify relevant log entries:
   ```bash
   grep -r "192.168.1.100" /var/log/pcap_analyzer/
   ```

2. Redact or delete entries:
   ```bash
   sed -i 's/192.168.1.100/[REDACTED]/g' /var/log/pcap_analyzer/*.log
   ```

3. Document the erasure in audit trail

### Access Control

- **File permissions**: 0600 (owner only)
- **Directory permissions**: 0700 (owner only)
- **Encryption**: Encrypt logs at rest if required by policy

---

## Troubleshooting

### Common Issues

#### Logs Not Being Written

**Symptom**: No log files created

**Solution**:
```bash
# Check log directory exists
ls -la logs/

# Create if missing
mkdir -p logs
chmod 700 logs

# Check permissions
stat logs/
```

#### Permission Denied

**Symptom**: `PermissionError: [Errno 13] Permission denied: 'logs/pcap_analyzer.log'`

**Solution**:
```bash
# Fix permissions
chmod 700 logs
chmod 600 logs/*.log

# Run as correct user
sudo chown -R $USER:$USER logs/
```

#### Disk Full

**Symptom**: Logs stop being written, application hangs

**Solution**:
```bash
# Check disk space
df -h

# Clean up old logs
./scripts/rotate_logs.sh /var/log/pcap_analyzer

# Adjust rotation policy (more aggressive)
# Edit scripts/rotate_logs.sh
COMPRESS_AFTER_DAYS=7
DELETE_AFTER_DAYS=30
```

#### Log Level Not Working

**Symptom**: DEBUG messages not appearing

**Solution**:
```bash
# Explicitly set DEBUG level
pcap_analyzer analyze capture.pcap --log-level DEBUG

# Check configuration
pcap_analyzer analyze capture.pcap --log-config config/logging.yaml
```

#### JSON Logging Not Working

**Symptom**: `ImportError: No module named 'pythonjsonlogger'`

**Solution**:
```bash
# Install required package
pip install python-json-logger

# Retry with JSON format
pcap_analyzer analyze capture.pcap --log-format json
```

### Debugging Logging Issues

Enable Python logging debug mode:

```bash
# Set environment variable
export PYTHONVERBOSE=1

# Run with verbose output
pcap_analyzer analyze capture.pcap --log-level DEBUG 2>&1 | tee debug.log
```

### Log Analysis

#### Find Security Events

```bash
# Search audit log for critical events
grep -i "CRITICAL" logs/security_audit.log

# Search for specific event types
grep "event_type='decompression_bomb_detected'" logs/security_audit.log

# Count events by severity
grep -oP "severity='\K[^']*" logs/security_audit.log | sort | uniq -c
```

#### Analyze Performance

```bash
# Find slow operations
grep "seconds" logs/pcap_analyzer.log | grep -oP "\d+\.\d+" | sort -n | tail -10

# Count errors
grep -c "ERROR" logs/pcap_analyzer.log

# Timeline of events
grep "2025-12-20 16:" logs/pcap_analyzer.log | head -20
```

---

## Best Practices

### Production Deployment

1. **Set log level to INFO or WARNING** (never DEBUG)
2. **Disable console logging** (use file logging only)
3. **Enable audit logging** for security events
4. **Use JSON format** for SIEM integration
5. **Set up log rotation cron job**
6. **Monitor disk space** usage
7. **Set file permissions** to 0600/0700
8. **Encrypt logs at rest** if required

### Development Deployment

1. **Use DEBUG level** for detailed diagnostics
2. **Enable console logging** for immediate feedback
3. **Use standard format** (more human-readable)
4. **Disable log rotation** (keep all logs)

### Log Message Guidelines

**DO**:
- Use structured logging with key=value pairs
- Include context (file names, IP addresses, counts)
- Use consistent terminology
- Log entry/exit of critical functions
- Log security events at CRITICAL level

**DON'T**:
- Log sensitive data (passwords, keys, full packets)
- Log at DEBUG level in production
- Use vague messages ("Error occurred")
- Log excessive details (every packet)
- Log to console in production (use file logging)

---

## References

- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
- [OpenSSF Secure Coding Guide](https://github.com/ossf/wg-best-practices-os-developers)
- [Python Logging HOWTO](https://docs.python.org/3/howto/logging.html)
- [GDPR Article 5: Principles relating to processing of personal data](https://gdpr-info.eu/art-5-gdpr/)

---

**Last Updated**: 2025-12-20
**Version**: 4.20.0
