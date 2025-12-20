# NIST-Compliant Audit Logging Implementation

## Overview

This document provides a complete implementation guide for NIST SP 800-53 AU-2/AU-3 compliant audit logging in the PCAP Analyzer application.

**Implemented:**
- ✅ `src/utils/audit_events.py` - Event type definitions
- ✅ `src/utils/audit_logger.py` - NIST-compliant audit logger

**To be integrated:**
- File validation audit logging
- Resource limit audit logging
- Decompression bomb audit logging
- SSH authentication audit logging
- Path traversal detection audit logging

## Standards Compliance

### NIST SP 800-53 AU-2: Audit Events
The following auditable events are implemented:

| Requirement | Implementation | Event Types |
|-------------|----------------|-------------|
| Account Logon | SSH authentication | `AUTH_SUCCESS`, `AUTH_FAILURE`, `AUTH_RATE_LIMIT` |
| Object Access | File validation | `FILE_VALIDATION_SUCCESS`, `FILE_VALIDATION_FAILURE` |
| Policy Changes | Configuration | `CONFIG_LOADED`, `CONFIG_CHANGED`, `CONFIG_VALIDATION_ERROR` |
| Privilege Functions | Resource limits | `RESOURCE_LIMIT_EXCEEDED`, `RESOURCE_LIMIT_WARNING` |
| Process Tracking | File processing | `FILE_PROCESSING_START`, `FILE_PROCESSING_COMPLETE` |
| System Events | Resource exhaustion | `MEMORY_ERROR`, `CPU_LIMIT_EXCEEDED`, `DISK_FULL` |

### NIST SP 800-53 AU-3: Content of Audit Records
Each audit record contains:

1. **Event type**: Enumerated event identifier (e.g., `file.validation.success`)
2. **Timestamp**: ISO 8601 format with timezone (`2025-12-20T15:30:45.123Z`)
3. **Location**: Component name (`file_validator`, `ssh_auth`, etc.)
4. **Source**: User, process ID, source IP, session ID
5. **Outcome**: SUCCESS, FAILURE, BLOCKED, PARTIAL, UNKNOWN
6. **Identity**: User ID, hostname, session tracking

## Audit Record Format

### JSON Structure
```json
{
  "component": "file_validator",
  "details": {
    "file_size_bytes": 1024000,
    "pcap_type": "pcap"
  },
  "event_type": "file.validation.success",
  "file_path": "capture.pcap",
  "hostname": "analyst-workstation",
  "outcome": "SUCCESS",
  "process_id": 12345,
  "record_id": "550e8400-e29b-41d4-a716-446655440000",
  "session_id": "abc123def456",
  "severity": "INFO",
  "source_ip": null,
  "timestamp": "2025-12-20T15:30:45.123456+00:00",
  "user": null
}
```

## Integration Examples

### 1. File Validator Integration

**Location:** `src/utils/file_validator.py`

```python
# Add import at top
from .audit_logger import get_audit_logger

# Initialize audit logger
audit_logger = get_audit_logger()

# In validate_pcap_magic_number() - SUCCESS case
if magic_bytes in PCAP_MAGIC_NUMBERS:
    pcap_type = PCAP_MAGIC_NUMBERS[magic_bytes]
    logger.info(f"Valid PCAP file detected: type={pcap_type}")

    # AUDIT: Log successful validation
    audit_logger.log_file_validation(
        file_path=file_path,
        outcome="SUCCESS",
        pcap_type=pcap_type
    )

    return pcap_type

# In validate_pcap_magic_number() - FAILURE case
if magic_bytes not in PCAP_MAGIC_NUMBERS:
    magic_hex = '0x' + magic_bytes.hex()
    error_msg = f"Invalid PCAP file: magic number {magic_hex} not recognized"

    # AUDIT: Log validation failure
    audit_logger.log_file_validation(
        file_path=file_path,
        outcome="FAILURE",
        reason=f"Invalid magic number: {magic_hex}"
    )

    logger.warning(f"Invalid magic number detected: {magic_hex}")
    raise ValueError(error_msg)

# In validate_pcap_file_size() - SIZE VIOLATION
if file_size > max_size_bytes:
    file_size_gb = file_size / (1024 * 1024 * 1024)

    # AUDIT: Log oversized file rejection
    audit_logger.log_security_violation(
        violation_type="OVERSIZED_FILE",
        details={
            "file_size_bytes": file_size,
            "file_size_gb": file_size_gb,
            "max_size_gb": max_size_gb,
            "action": "REJECTED"
        },
        file_path=file_path
    )

    logger.warning(f"File too large: {file_size_gb:.1f} GB > {max_size_gb} GB")
    raise ValueError(f"PCAP file too large: {file_size_gb:.1f} GB exceeds maximum of {max_size_gb} GB")
```

### 2. Resource Limits Integration

**Location:** `src/utils/resource_limits.py`

```python
# Add import at top
from .audit_logger import get_audit_logger

# Initialize audit logger
audit_logger = get_audit_logger()

# In set_resource_limits() - AFTER setting each limit
try:
    # Set memory limit
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))

    # AUDIT: Log resource limit configuration
    audit_logger.log_resource_limit(
        limit_type="RLIMIT_AS",
        current=0,  # Not yet used
        maximum=memory_bytes,
        action="WARNING"
    )

    logger.info(f"Memory limit (RLIMIT_AS): {_bytes_to_human(memory_bytes)}")

except (ValueError, OSError) as e:
    # AUDIT: Log configuration error
    audit_logger.log_configuration(
        action="VALIDATION_ERROR",
        error=f"Failed to set RLIMIT_AS: {e}"
    )
    logger.warning(f"RLIMIT_AS not supported on this platform")

# In _handle_memory_limit_exceeded()
def _handle_memory_limit_exceeded():
    # AUDIT: Log memory exhaustion
    audit_logger.log_security_violation(
        violation_type="RESOURCE_LIMIT_EXCEEDED",
        details={
            "limit_type": "MEMORY",
            "action": "PROCESS_TERMINATED"
        }
    )

    logger.critical("Memory limit exceeded! Process aborted.")
    sys.exit(1)

# In _handle_cpu_limit_exceeded()
def _handle_cpu_limit_exceeded(signum, frame):
    # AUDIT: Log CPU exhaustion
    audit_logger.log_security_violation(
        violation_type="RESOURCE_LIMIT_EXCEEDED",
        details={
            "limit_type": "CPU",
            "action": "PROCESS_TERMINATED"
        }
    )

    logger.critical("CPU time limit exceeded!")
    sys.exit(1)
```

### 3. Decompression Monitor Integration

**Location:** `src/utils/decompression_monitor.py`

```python
# Add import at top
from .audit_logger import get_audit_logger

# Initialize audit logger
audit_logger = get_audit_logger()

# In check_expansion_ratio() - CRITICAL threshold
if stats.is_critical:
    error_msg = f"Decompression bomb detected! Expansion ratio {ratio:.1f}:1"

    # AUDIT: Log decompression bomb detection
    audit_logger.log_security_violation(
        violation_type="DECOMPRESSION_BOMB",
        details={
            "file_size_bytes": file_size,
            "bytes_processed": bytes_processed,
            "expansion_ratio": ratio,
            "threshold": self.critical_ratio,
            "action": "ABORTED"
        }
    )

    logger.critical(error_msg)
    raise DecompressionBombError(error_msg)

# In check_expansion_ratio() - WARNING threshold
if stats.is_warning and not self.warning_logged:
    # AUDIT: Log expansion warning
    audit_logger.log_security_violation(
        violation_type="DECOMPRESSION_BOMB_WARNING",
        details={
            "expansion_ratio": ratio,
            "threshold": self.max_ratio,
            "action": "MONITORING"
        }
    )

    logger.warning(f"High expansion ratio detected: {ratio:.1f}:1")
    self.warning_logged = True
```

### 4. SSH Capture Integration

**Location:** `src/ssh_capture.py`

```python
# Add import at top
from .utils.audit_logger import get_audit_logger

# Initialize audit logger in SSHCapture.__init__()
def __init__(self, host: str, username: str, ...):
    self.host = host
    self.username = username
    # ... existing code ...
    self.audit_logger = get_audit_logger()

# In connect() - SUCCESS case
try:
    self.client.connect(**connect_kwargs, timeout=10)

    # AUDIT: Log successful connection
    self.audit_logger.log_ssh_event(
        event="CONNECTED",
        host=self.host,
        username=self.username,
        outcome="SUCCESS"
    )

    console.print("[green]✓ Connecté avec succès[/green]")

except paramiko.AuthenticationException as e:
    # AUDIT: Log authentication failure
    self.audit_logger.log_authentication(
        outcome="FAILURE",
        username=self.username,
        host=self.host,
        failure_reason="Invalid credentials"
    )

    raise SSHCaptureError("Échec d'authentification SSH")

# In SSHCaptureRateLimiter.check_and_record()
if len(self.attempts) >= self.max_attempts:
    # AUDIT: Log rate limit violation
    audit_logger = get_audit_logger()
    audit_logger.log_authentication(
        outcome="RATE_LIMIT",
        username="unknown",
        host="ssh_service",
        failure_reason=f"{len(self.attempts)} attempts in {self.window}s"
    )

    raise SSHCaptureError("Rate limit exceeded")

# In execute_command()
def execute_command(self, command: str, sudo: bool = False, timeout: int = 30):
    if sudo:
        command = f"sudo {command}"

    # AUDIT: Log command execution
    self.audit_logger.log_ssh_event(
        event="COMMAND_EXECUTED",
        host=self.host,
        username=self.username,
        command=command,
        outcome="SUCCESS"
    )

    stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
    # ... existing code ...
```

### 5. CLI Path Validation Integration

**Location:** `src/cli.py`

```python
# Add import at top
from .utils.audit_logger import get_audit_logger

# In analyze() command - FILE PATH VALIDATION
@click.command()
@click.argument("pcap_file", type=click.Path(exists=True))
def analyze(pcap_file, ...):
    try:
        # Initialize audit logger
        audit_logger = get_audit_logger()

        # Validate file path (prevent path traversal)
        pcap_path = Path(pcap_file).resolve(strict=True)

        # Check for path traversal attempts
        if ".." in str(pcap_file):
            # AUDIT: Log path traversal attempt
            audit_logger.log_security_violation(
                violation_type="PATH_TRAVERSAL",
                details={
                    "requested_path": str(pcap_file),
                    "resolved_path": str(pcap_path),
                    "blocked": True
                }
            )

            console.print("[red]Error: Path traversal detected[/red]")
            raise click.Abort()

        # AUDIT: Log file processing start
        audit_logger.log_file_processing(
            file_path=str(pcap_path),
            status="START"
        )

        # Validate PCAP file
        pcap_type, file_size = validate_pcap_file(str(pcap_path), max_size_gb=max_size)

        # ... process file ...

        # AUDIT: Log file processing complete
        audit_logger.log_file_processing(
            file_path=str(pcap_path),
            status="COMPLETE",
            packets_processed=total_packets
        )

    except Exception as e:
        # AUDIT: Log processing error
        audit_logger.log_file_processing(
            file_path=str(pcap_file),
            status="ERROR",
            error_message=str(e)
        )
        raise
```

## Security Features

### 1. Tamper-Evident Logging
- **Append-only mode**: Audit log file opened in append mode prevents modification of existing records
- **File permissions**: 0600 (owner read/write only) prevents unauthorized access
- **Directory permissions**: 0700 (owner only) protects audit log directory

### 2. PII Redaction
- **File paths**: Only filename logged, full paths redacted (GDPR Article 32 compliance)
- **User data**: Optional user field, can be anonymized
- **Automatic**: Redaction happens in `_redact_pii()` before writing

### 3. Session Tracking
- **Session ID**: UUID assigned per session for event correlation
- **Record ID**: Unique UUID per audit record for precise tracking
- **Process ID**: OS process ID for multi-process environments

### 4. SIEM Integration Ready
- **Structured JSON**: One record per line (newline-delimited JSON)
- **Standard fields**: Consistent field naming for parsing
- **Severity levels**: RFC 5424 syslog levels (DEBUG to EMERGENCY)

## Audit Log Location

**Default path:** `logs/audit/security_audit.log`

**Directory structure:**
```
pcap_analyzer/
├── logs/
│   ├── audit/              (0700 permissions)
│   │   └── security_audit.log  (0600 permissions)
│   └── application.log
├── src/
│   └── utils/
│       ├── audit_events.py
│       └── audit_logger.py
└── docs/
    ├── AUDIT_COMPLIANCE.md
    └── SIEM_INTEGRATION.md
```

## Log Retention

**Minimum retention:** 90 days (NIST/PCI-DSS requirement)

**Rotation:** Configure with logrotate (Linux) or equivalent:

```bash
# /etc/logrotate.d/pcap-analyzer-audit
/path/to/pcap_analyzer/logs/audit/security_audit.log {
    daily
    rotate 90
    compress
    delaycompress
    missingok
    notifempty
    create 0600 pcap_user pcap_group
    postrotate
        # No action needed (application handles append-only)
    endscript
}
```

## Example Audit Records

### Successful File Validation
```json
{
  "component": "file_validator",
  "details": {
    "file_size_bytes": 10485760,
    "pcap_type": "pcap"
  },
  "event_type": "file.validation.success",
  "file_path": "capture.pcap",
  "hostname": "analyst-ws",
  "outcome": "SUCCESS",
  "process_id": 45678,
  "record_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "session_id": "sess_xyz789",
  "severity": "INFO",
  "source_ip": null,
  "timestamp": "2025-12-20T10:15:30.456789+00:00",
  "user": null
}
```

### Decompression Bomb Detection
```json
{
  "component": "security_monitor",
  "details": {
    "action": "ABORTED",
    "bytes_processed": 100000000000,
    "expansion_ratio": 10500.5,
    "file_size_bytes": 10000000,
    "threshold": 10000
  },
  "event_type": "security.decompression_bomb.detected",
  "file_path": "malicious.pcap",
  "hostname": "analyst-ws",
  "outcome": "BLOCKED",
  "process_id": 45678,
  "record_id": "f9e8d7c6-b5a4-3210-fedc-ba9876543210",
  "session_id": "sess_xyz789",
  "severity": "CRITICAL",
  "source_ip": null,
  "timestamp": "2025-12-20T10:16:45.789012+00:00",
  "user": null
}
```

### SSH Authentication Failure
```json
{
  "component": "ssh_auth",
  "details": {
    "failure_reason": "Invalid credentials",
    "host": "remote.example.com"
  },
  "event_type": "auth.failure",
  "file_path": null,
  "hostname": "analyst-ws",
  "outcome": "FAILURE",
  "process_id": 45678,
  "record_id": "1a2b3c4d-5e6f-7890-abcd-ef1234567890",
  "session_id": "sess_xyz789",
  "severity": "WARNING",
  "source_ip": "203.0.113.45",
  "timestamp": "2025-12-20T10:17:20.123456+00:00",
  "user": "admin"
}
```

### Resource Limit Exceeded
```json
{
  "component": "resource_monitor",
  "details": {
    "current_usage": 4294967296,
    "limit_type": "RLIMIT_AS",
    "maximum_allowed": 4294967296,
    "percentage": 100.0
  },
  "event_type": "security.resource_limit.exceeded",
  "file_path": null,
  "hostname": "analyst-ws",
  "outcome": "FAILURE",
  "process_id": 45678,
  "record_id": "9f8e7d6c-5b4a-3210-fedc-ba9876543210",
  "session_id": "sess_xyz789",
  "severity": "CRITICAL",
  "source_ip": null,
  "timestamp": "2025-12-20T10:18:55.987654+00:00",
  "user": null
}
```

## Testing Audit Logging

### Unit Tests
```python
# tests/test_audit_logger.py
import pytest
from src.utils.audit_logger import get_audit_logger, reset_audit_logger
from src.utils.audit_events import AuditEventType
import json
from pathlib import Path

def test_file_validation_success(tmp_path):
    """Test audit logging for successful file validation."""
    reset_audit_logger()

    audit_log = tmp_path / "test_audit.log"
    logger = get_audit_logger(log_dir=str(tmp_path), log_file="test_audit.log")

    logger.log_file_validation(
        file_path="/tmp/test.pcap",
        outcome="SUCCESS",
        file_size=1024000,
        pcap_type="pcap"
    )

    # Verify log file created
    assert audit_log.exists()

    # Verify record format
    with open(audit_log) as f:
        record = json.loads(f.readline())

    assert record["event_type"] == "file.validation.success"
    assert record["outcome"] == "SUCCESS"
    assert record["component"] == "file_validator"
    assert record["details"]["file_size_bytes"] == 1024000
    assert record["details"]["pcap_type"] == "pcap"
    assert "timestamp" in record
    assert "record_id" in record

def test_security_violation_logging(tmp_path):
    """Test audit logging for security violations."""
    reset_audit_logger()

    audit_log = tmp_path / "test_audit.log"
    logger = get_audit_logger(log_dir=str(tmp_path), log_file="test_audit.log")

    logger.log_security_violation(
        violation_type="DECOMPRESSION_BOMB",
        details={
            "expansion_ratio": 15000.0,
            "threshold": 10000,
            "action": "ABORTED"
        },
        file_path="/tmp/malicious.pcap"
    )

    # Verify record
    with open(audit_log) as f:
        record = json.loads(f.readline())

    assert record["event_type"] == "security.decompression_bomb.detected"
    assert record["outcome"] == "BLOCKED"
    assert record["severity"] == "CRITICAL"
    assert record["file_path"] == "malicious.pcap"  # PII redacted (path stripped)
```

### Integration Tests
```bash
# Run full analysis with audit logging enabled
python -m src.cli analyze test_capture.pcap --verbose

# Check audit log
cat logs/audit/security_audit.log | jq .

# Verify events logged
cat logs/audit/security_audit.log | jq -r '.event_type' | sort | uniq -c
```

## Next Steps

1. **Create audit log analyzer** (`scripts/analyze_audit_log.py`)
2. **Document SIEM integration** (`docs/SIEM_INTEGRATION.md`)
3. **Create compliance mapping** (`docs/AUDIT_COMPLIANCE.md`)
4. **Implement log rotation** (system-level configuration)
5. **Add alerting rules** (for critical events)

## References

- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-92: Guide to Computer Security Log Management](https://csrc.nist.gov/publications/detail/sp/800-92/final)
- [PCI-DSS 10.2: Audit Trail Requirements](https://www.pcisecuritystandards.org/)
- [ISO 27001 A.12.4.1: Event Logging](https://www.iso.org/standard/54534.html)
- [GDPR Article 32: Security of Processing](https://gdpr-info.eu/art-32-gdpr/)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)
