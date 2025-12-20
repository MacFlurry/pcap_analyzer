# Security Policy

## Overview

PCAP Analyzer v4.21.0 implements production-grade security controls following industry standards:

- **OWASP ASVS 5.0** (Application Security Verification Standard)
- **NIST SP 800-53 Rev. 5** (Security and Privacy Controls)
- **NIST SP 800-92** (Computer Security Log Management)
- **CWE Top 25 Most Dangerous Software Weaknesses (2025)**
- **GDPR Article 5, 32** (Data Protection and Security)
- **ISO 27001/27034** (Information Security Management)

## Threat Model

### Attack Surface

PCAP Analyzer processes potentially **untrusted network capture files** in production environments. Key attack vectors:

1. **Malicious PCAP Files**
   - Malformed packet structures
   - Decompression bombs (zip/gzip)
   - Path traversal in packet metadata
   - Resource exhaustion attacks

2. **User Inputs**
   - File paths (CLI arguments)
   - Configuration parameters
   - Filter expressions

3. **Outputs**
   - HTML report generation (XSS risks)
   - Log files (PII exposure)
   - Error messages (information disclosure)

### Trust Boundaries

```
┌──────────────────────────────────────────────────┐
│ UNTRUSTED: PCAP files from external sources      │
├──────────────────────────────────────────────────┤
│ File Validation Layer (magic numbers, size)     │
│ Resource Limits (memory, CPU, file size)        │
│ Decompression Bomb Detection                    │
├──────────────────────────────────────────────────┤
│ TRUSTED: Validated packets in memory             │
├──────────────────────────────────────────────────┤
│ Analysis Engine (retransmission, jitter, etc.)  │
├──────────────────────────────────────────────────┤
│ Output Sanitization (HTML escaping, PII redact) │
├──────────────────────────────────────────────────┤
│ SAFE: Reports for end users                     │
└──────────────────────────────────────────────────┘
```

## Security Controls

### 1. Input Validation (OWASP ASVS 5.2)

#### 1.1 PCAP Magic Number Validation (ASVS 5.2.2)
**Implementation**: `src/utils/file_validator.py`

Validates PCAP file type by checking magic numbers before processing:

```python
Supported formats:
- 0xa1b2c3d4 / 0xd4c3b2a1 (Standard PCAP)
- 0xa1b23c4d / 0x4d3cb2a1 (PCAP with nanosecond precision)
- 0x0a0d0d0a (PCAP-NG)
```

**Prevents**: CWE-434 (Unrestricted File Upload), CWE-502 (Deserialization of Untrusted Data)

#### 1.2 File Size Pre-Validation (NIST SC-5)
**Implementation**: `src/utils/file_validator.py`

- **Default limit**: 10 GB per file
- **Configurable**: `max_file_size_bytes` parameter
- **Early rejection**: Before loading into memory

**Prevents**: CWE-770 (Allocation of Resources Without Limits), DoS attacks

#### 1.3 Path Traversal Protection (CWE-22)
**Implementation**: `src/utils/file_validator.py`

```python
def validate_file_path(file_path: str, allowed_dirs: List[str] = None) -> str:
    """Validate file path against directory traversal (CWE-22)."""
    resolved_path = Path(file_path).resolve()

    # Block path traversal sequences
    if ".." in file_path or "~" in file_path:
        raise ValueError("Path traversal detected")

    # Verify parent directory if allowlist provided
    if allowed_dirs:
        if not any(str(resolved_path).startswith(d) for d in allowed_dirs):
            raise ValueError("Access denied: path outside allowed directories")
```

**Prevents**: CWE-22 (Path Traversal, Rank 6/2025)

### 2. Resource Management (NIST SC-5, CWE-770)

#### 2.1 OS-Level Resource Limits
**Implementation**: `src/utils/resource_limits.py`

Applied at process startup:

| Resource | Default Limit | Purpose |
|----------|---------------|---------|
| Memory (RLIMIT_AS) | 4 GB | Prevent memory exhaustion |
| CPU Time (RLIMIT_CPU) | 3600s (1 hour) | Prevent infinite loops |
| File Size (RLIMIT_FSIZE) | 10 GB | Prevent disk exhaustion |
| Open Files (RLIMIT_NOFILE) | 1024 | Prevent file descriptor exhaustion |

**Platform Support**: Linux, macOS (limited on Windows)

#### 2.2 Decompression Bomb Protection (OWASP ASVS 5.2.3)
**Implementation**: `src/utils/decompression_monitor.py`

Real-time expansion ratio monitoring:

- **WARNING threshold**: 1000:1 expansion ratio
- **CRITICAL threshold**: 10000:1 expansion ratio (abort)
- **Monitoring frequency**: Every 10,000 packets

```python
Example: 1 MB PCAP expanding to 10 GB in memory triggers abort
```

**Prevents**: CWE-770, zip bomb attacks, memory exhaustion

### 3. Error Handling (CWE-209, NIST SI-10)

#### 3.1 Stack Trace Disclosure Prevention
**Implementation**: `src/utils/error_sanitizer.py`

```python
User-facing errors: Sanitized, generic messages
Internal logs: Full stack traces (0600 permissions)
```

**Example Sanitization**:
```
Before: FileNotFoundError: [Errno 2] No such file or directory: '/home/user/secrets.pcap'
After:  Error processing file. Please verify the path and try again.
```

#### 3.2 File Path Redaction
**Implementation**: `src/utils/error_sanitizer.py`

Removes absolute paths from error messages:
- Unix: `/home/user/` → `/[USER]/`
- Windows: `C:\Users\user\` → `C:\Users\[USER]\`

**Prevents**: CWE-209 (Information Exposure Through Error Messages)

### 4. Privacy & Data Protection (GDPR, CWE-532)

#### 4.1 PII Redaction in Logs (GDPR Article 5(1)(c))
**Implementation**: `src/utils/pii_redactor.py`

Redacts Personally Identifiable Information:

| Data Type | Redaction Strategy | Example |
|-----------|-------------------|---------|
| IPv4 Addresses | Preserve first 2 octets | `192.168.1.1` → `192.168.XXX.XXX` |
| IPv6 Addresses | Preserve prefix | `2001:db8::1` → `2001:db8::[REDACTED]` |
| MAC Addresses | Full redaction | `00:11:22:33:44:55` → `[MAC_REDACTED]` |
| File Paths | Username removal | `/home/alice/file` → `/[USER]/file` |
| Credentials | Full redaction | `password=secret` → `[CREDENTIAL_REDACTED]` |

**Configuration**: `config.yaml` → `logging.pii_redaction.level`

Modes:
- **PRODUCTION**: Redact all PII (default)
- **DEVELOPMENT**: Keep IPs, redact credentials
- **DEBUG**: No redaction (WARNING: NOT GDPR-COMPLIANT)

#### 4.2 Data Retention Policy (GDPR Article 5(1)(e))

```yaml
logs/application.log: 90 days (configurable)
logs/audit.log: 365 days (compliance requirement)
reports/*.html: User-managed (no automatic deletion)
```

### 5. Audit Logging (NIST AU-2, AU-3)

#### 5.1 Security Event Logging
**Implementation**: `src/utils/audit_logger.py`

Comprehensive audit trail for security events:

**Event Types** (50+ tracked):
- File validation failures
- Resource limit violations
- Decompression bomb detections
- Path traversal attempts
- Authentication failures (SSH mode)
- Configuration changes

**NIST AU-3 Compliant Fields**:
```json
{
  "timestamp": "2025-12-20T12:34:56.789Z",
  "event_type": "FILE_VALIDATION_FAILED",
  "outcome": "BLOCKED",
  "user": "analyst@company.com",
  "source_ip": "192.168.XXX.XXX",
  "component": "FileValidator",
  "severity": "WARNING",
  "details": {
    "file_path": "/[USER]/suspicious.pcap",
    "reason": "Invalid magic number",
    "expected": "0xa1b2c3d4",
    "actual": "0x12345678"
  }
}
```

#### 5.2 Log File Security

**Permissions**: 0600 (owner read/write only)
**Rotation**: 10 MB max size, 5-10 backups
**Location**: `/var/log/pcap_analyzer/` (production) or `./logs/` (development)

### 6. Dependency Security

#### 6.1 Known CVE Fixes

| Dependency | Minimum Version | CVE Fixed | Description |
|------------|-----------------|-----------|-------------|
| Paramiko | 3.5.2 | CVE-2023-48795 | Terrapin Attack (SSH protocol vulnerability) |
| Scapy | 2.6.2 | Multiple | Security updates for packet parsing |
| PyYAML | 6.0 | CVE-2020-14343 | Arbitrary code execution via unsafe loading |
| Jinja2 | 3.1.2 | CVE-2024-22195 | XSS in HTML attribute rendering |

**Update Policy**: All dependencies pinned with upper bounds to prevent breaking changes while allowing security patches.

#### 6.2 Dependency Scanning

Recommended tools:
```bash
pip-audit  # Python dependency vulnerability scanner
safety check  # Alternative scanner
```

### 7. Authentication & Authorization

#### 7.1 SSH Remote Capture (Optional Feature)

**Configuration**: `config.yaml` → `ssh` section

**Security Requirements**:
- ✅ **Key-based authentication ONLY** (passwords disabled by design)
- ✅ Private key file permissions must be 0600
- ✅ No hardcoded credentials in config files
- ⚠️ User must configure `key_file` path manually

**Warning in config.yaml**:
```yaml
# SECURITY WARNING: Never use password authentication in production!
# Password authentication is disabled by design - use key-based auth only
key_file: "~/.ssh/id_rsa"  # REQUIRED
```

**Prevents**: CWE-798 (Hardcoded Credentials), CWE-256 (Plaintext Password Storage)

### 8. Output Sanitization

#### 8.1 HTML Report Generation
**Implementation**: `src/exporters/html_report.py`

**XSS Prevention**:
- All user-controlled data passed through Jinja2 autoescaping
- No `| safe` filters on untrusted data
- Content-Security-Policy headers recommended for deployment

**Example**:
```python
# Flow key from PCAP: <script>alert(1)</script>:80 -> 192.168.1.1:443
# Rendered in HTML: &lt;script&gt;alert(1)&lt;/script&gt;:80 -&gt; 192.168.1.1:443
```

**Prevents**: XSS (Cross-Site Scripting)

## Compliance Matrix

### OWASP ASVS 5.0

| Control | Requirement | Implementation | Status |
|---------|-------------|----------------|--------|
| V1.14 | Configuration Architecture | `config.yaml`, environment vars | ✅ |
| V5.1.3 | Input Allowlisting | File type validation (magic numbers) | ✅ |
| V5.2.2 | File Upload Verification | PCAP magic number checks | ✅ |
| V5.2.3 | Decompression Bomb Protection | Expansion ratio monitoring | ✅ |
| V5.3.6 | Resource Allocation Limits | OS-level RLIMIT controls | ✅ |
| V7.3.1 | Sensitive Data Logging Prevention | PII redaction (GDPR mode) | ✅ |
| V8.3.4 | Privacy Controls | IP/MAC/path redaction | ✅ |

### NIST SP 800-53 Rev. 5

| Control | Name | Implementation | Status |
|---------|------|----------------|--------|
| AU-2 | Audit Events | 50+ security event types logged | ✅ |
| AU-3 | Content of Audit Records | Timestamp, user, outcome, details | ✅ |
| SC-5 | Denial of Service Protection | Resource limits, file size checks | ✅ |
| SI-10 | Information Input Validation | Magic number, size, path validation | ✅ |
| SI-10(3) | Predictable Behavior | Sanitized error messages | ✅ |
| SI-11 | Error Handling | No stack traces in user output | ✅ |

### CWE Top 25 (2025)

| Rank | CWE | Weakness | Mitigation | Status |
|------|-----|----------|------------|--------|
| 6 | CWE-22 | Path Traversal | Path validation, allowlisting | ✅ |
| 9 | CWE-78 | OS Command Injection | No shell=True in subprocess | ✅ |
| 12 | CWE-434 | Unrestricted File Upload | Magic number validation | ✅ |
| 15 | CWE-502 | Deserialization of Untrusted Data | File type validation before parsing | ✅ |
| 25 | CWE-770 | Resource Allocation Without Limits | OS-level resource limits | ✅ |
| N/A | CWE-209 | Information Exposure | Error sanitization | ✅ |
| N/A | CWE-532 | Sensitive Info in Log Files | PII redaction | ✅ |
| N/A | CWE-778 | Insufficient Logging | Comprehensive audit logging | ✅ |
| N/A | CWE-1333 | ReDoS | Subdomain length limits (DNS) | ✅ |

### GDPR Compliance

| Article | Requirement | Implementation | Status |
|---------|-------------|----------------|--------|
| 5(1)(c) | Data Minimization | PII redaction in logs | ✅ |
| 5(1)(e) | Storage Limitation | 90-day log retention policy | ✅ |
| 6(1)(f) | Legitimate Interest | Security monitoring justification | ✅ |
| 32 | Security of Processing | Encryption, access controls, audit logs | ✅ |

## Security Assumptions & Limitations

### Assumptions

1. **Trusted Deployment Environment**
   - PCAP Analyzer runs in a controlled environment (not public-facing web server)
   - OS-level security (firewall, SELinux/AppArmor) is properly configured
   - File system permissions are correctly set (0600 for logs, 0700 for directories)

2. **User Trust Level**
   - Users running the tool have legitimate analysis purposes
   - Users do not intentionally bypass security controls
   - Multi-user environments use OS-level access controls

3. **Network Isolation**
   - SSH remote capture (if enabled) uses trusted, isolated networks
   - No direct internet connectivity required for core functionality

### Known Limitations

1. **Windows Resource Limits**
   - `resource` module (RLIMIT) has limited support on Windows
   - Windows users should rely on file size pre-validation and decompression monitoring

2. **Scapy Parsing Vulnerabilities**
   - Scapy 2.6.2 is used for packet parsing
   - While updated to latest stable, complex malformed packets may trigger unexpected behavior
   - Decompression bomb protection mitigates impact

3. **HTML Report XSS**
   - Jinja2 autoescaping enabled, but custom templates (if added) must be reviewed
   - Recommended: Deploy with Content-Security-Policy headers

4. **PII in PCAP Files**
   - PII redaction applies to LOGS and ERROR MESSAGES only
   - Original PCAP files and HTML reports contain unredacted data
   - Users must handle PCAP files according to their own data protection policies

5. **Audit Log Integrity**
   - Audit logs are protected by file permissions (0600)
   - No cryptographic signing or append-only storage
   - For compliance-critical environments, integrate with SIEM or write-once storage

## Production Deployment Checklist

### Pre-Deployment

- [ ] Review `config.yaml` and set production-appropriate thresholds
- [ ] Enable PII redaction: `logging.pii_redaction.enabled: true`
- [ ] Set redaction level: `logging.pii_redaction.level: PRODUCTION`
- [ ] Configure log retention: `logging.pii_redaction.retention_days: 90`
- [ ] Set resource limits in `ResourceLimitConfig` (4 GB memory, 3600s CPU)
- [ ] Configure decompression bomb thresholds (default: 1000:1 warning, 10000:1 critical)
- [ ] Verify SSH key-based authentication (if remote capture enabled)
- [ ] Update dependencies: `pip install --upgrade -r requirements.txt`
- [ ] Run security tests: `pytest tests/security/`

### Deployment

- [ ] Set file permissions:
  - Logs directory: `chmod 0700 /var/log/pcap_analyzer/`
  - Log files: `chmod 0600 /var/log/pcap_analyzer/*.log`
  - Config file: `chmod 0600 config.yaml`
  - SSH private key: `chmod 0600 ~/.ssh/id_rsa`

- [ ] Configure log rotation (logrotate on Linux):
```
/var/log/pcap_analyzer/*.log {
    daily
    rotate 90
    compress
    missingok
    notifempty
    create 0600 pcap_analyzer pcap_analyzer
}
```

- [ ] Set up monitoring alerts:
  - File validation failures
  - Resource limit violations
  - Decompression bomb detections
  - High expansion ratios (>1000:1)

- [ ] Integrate audit logs with SIEM (optional):
  - Configure log forwarding to Splunk/ELK/Datadog
  - Set up correlation rules for security events

### Post-Deployment

- [ ] Verify resource limits are active: Check `ulimit -a` output
- [ ] Test with sample malicious PCAP (path traversal, oversized file)
- [ ] Confirm PII redaction in logs: `grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" logs/application.log` (should return redacted IPs)
- [ ] Review audit log for security events: `logs/audit.log`
- [ ] Monitor memory/CPU usage under load
- [ ] Schedule periodic dependency scans: `pip-audit`

## Incident Response

### Security Event Categories

1. **CRITICAL: Exploitation Attempt Detected**
   - Path traversal attempt
   - Malformed PCAP with exploit payload
   - Resource exhaustion attack (>10000:1 expansion ratio)

   **Response**:
   - Block source IP (if network capture)
   - Preserve audit logs for forensic analysis
   - Review all logs from same source in past 24 hours

2. **HIGH: Suspicious Activity**
   - Repeated file validation failures
   - Decompression bomb warning (1000:1 ratio)
   - Unusual file sizes or patterns

   **Response**:
   - Investigate user intent
   - Review file provenance
   - Monitor for repeated attempts

3. **MEDIUM: Configuration Issue**
   - PII redaction disabled in production
   - Weak resource limits (<1 GB memory)
   - Missing audit log rotation

   **Response**:
   - Correct configuration immediately
   - Audit logs for PII exposure
   - Notify security team

### Forensic Data Collection

**Logs to preserve**:
```
logs/audit.log           # Security events (NIST AU-2/AU-3)
logs/application.log     # Application behavior
config.yaml              # Configuration at time of incident
/tmp/pcap_analyzer_*     # Temporary files (if not auto-cleaned)
```

**System information**:
```bash
ulimit -a                # Resource limits in effect
ps aux | grep pcap       # Running processes
df -h                    # Disk usage (DoS check)
free -m                  # Memory usage
```

## Vulnerability Disclosure

### Reporting Security Issues

**DO NOT** open public GitHub issues for security vulnerabilities.

**Contact**: [Your security contact email or security.txt reference]

**Expected Response Time**: 48 hours (acknowledgment), 7 days (initial assessment)

**Scope**:
- Remote code execution
- Authentication bypass
- Path traversal
- Information disclosure
- Denial of service vulnerabilities

**Out of Scope**:
- Social engineering attacks
- Physical security issues
- Vulnerabilities in dependencies (report to upstream maintainers)

### Disclosure Timeline

1. **Day 0**: Vulnerability reported privately
2. **Day 1-7**: Assessment and reproduction
3. **Day 7-30**: Patch development and testing
4. **Day 30**: Coordinated public disclosure (CVE assignment if applicable)
5. **Day 30+**: Security advisory published

## Security Testing

### Automated Testing

**Unit Tests**: `tests/security/`
```bash
pytest tests/security/test_file_validator.py      # Input validation
pytest tests/security/test_resource_limits.py     # Resource management
pytest tests/security/test_pii_redactor.py        # Privacy controls
pytest tests/security/test_error_sanitizer.py     # Error handling
```

**Integration Tests**:
```bash
pytest tests/integration/test_malicious_pcap.py   # Malformed PCAP handling
pytest tests/integration/test_decompression_bomb.py  # Zip bomb protection
```

### Manual Testing

**Malicious PCAP Samples**:
```bash
# Path traversal attempt
echo -e "\xa1\xb2\xc3\xd4" > traversal.pcap
# Add packet with filename: ../../../../etc/passwd

# Oversized file
dd if=/dev/zero of=huge.pcap bs=1M count=11000  # 11 GB file

# Invalid magic number
echo "NOTAPCAP" > invalid.pcap
```

**Expected Behavior**:
- Path traversal: Blocked by `validate_file_path()`, audit log entry
- Oversized file: Rejected by `validate_file_size()`, user-friendly error
- Invalid magic: Rejected by `validate_pcap_magic_number()`, specific error message

### Penetration Testing

**Recommended Tools**:
- **Radamsa**: Fuzzing tool for generating malformed PCAP files
- **tcpreplay**: Replay and modify PCAP files
- **Wireshark**: Inspect PCAP structure before testing

**Test Scenarios**:
1. Decompression bomb (1 MB → 100 GB expansion)
2. Malformed packet headers (truncated, invalid checksums)
3. Extremely long DNS subdomains (ReDoS test)
4. Path traversal in file metadata
5. Rapid-fire file uploads (DoS test)

## Security Maintenance

### Regular Tasks

**Monthly**:
- [ ] Run `pip-audit` to check for new CVEs
- [ ] Review audit logs for anomalies
- [ ] Verify log rotation is working

**Quarterly**:
- [ ] Update dependencies to latest stable versions
- [ ] Re-run full security test suite
- [ ] Review and update threat model

**Annually**:
- [ ] Conduct penetration test
- [ ] Review compliance with updated standards (OWASP ASVS, NIST)
- [ ] Audit data retention policies for GDPR compliance
- [ ] Update security documentation

### Version Compatibility

| PCAP Analyzer | Python | Scapy | Paramiko | Notes |
|---------------|--------|-------|----------|-------|
| v4.21.0 | 3.9+ | 2.6.2+ | 3.5.2+ | CVE-2023-48795 fix required |
| v4.20.0 | 3.9+ | 2.5.0+ | 3.0+ | Pre-Terrapin Attack |

## References

### Standards
- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SP 800-53 Rev. 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST SP 800-92](https://csrc.nist.gov/publications/detail/sp/800-92/final) (Computer Security Log Management)
- [CWE Top 25 (2025)](https://cwe.mitre.org/top25/)
- [GDPR Official Text](https://gdpr-info.eu/)
- [ISO 27001:2022](https://www.iso.org/standard/27001)

### Security Resources
- [OpenSSF Secure Coding Guide for Python](https://best.openssf.org/Secure-Coding-Guide-for-Python/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [Python Security Best Practices](https://python.readthedocs.io/en/stable/library/security_warnings.html)

### Project Documentation
- `docs/security/threat_model.md` - Detailed threat modeling
- `docs/security/compliance_audit.md` - Full compliance audit report
- `docs/security/incident_response_plan.md` - IR procedures
- `tests/security/README.md` - Security test suite documentation

---

**Version**: 4.21.0
**Last Updated**: 2025-12-20
**Security Contact**: [Configure in deployment]
