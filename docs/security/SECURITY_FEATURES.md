# PCAP Analyzer - Security Features

## Table of Contents

1. [PII Redaction (GDPR/NIST Compliance)](#pii-redaction-gdprnist-compliance)
2. [Decompression Bomb Protection (OWASP ASVS 5.2.3)](#decompression-bomb-protection-owasp-asvs-523)

---

## PII Redaction (GDPR/NIST Compliance)

### Overview

PCAP Analyzer implements comprehensive PII (Personally Identifiable Information) redaction in logging to comply with:

- **GDPR Article 5(1)(c)**: Data Minimization - IP addresses are PII under EU law
- **CWE-532**: Insertion of Sensitive Information into Log File
- **NIST SP 800-122**: Guide to Protecting the Confidentiality of PII
- **CCPA (California)**: IP addresses considered personal information

### Quick Start

PII redaction is **enabled by default** in PRODUCTION mode:

```python
import logging
from src.utils.logging_filters import PIIRedactionFilter

logger = logging.getLogger(__name__)
logger.addFilter(PIIRedactionFilter())

# Automatically redacts PII
logger.info("Connection from 192.168.1.100")
# Logs: "Connection from 192.168.XXX.XXX"
```

### What Gets Redacted

#### IPv4 Addresses (GDPR Art. 4(1))
- **Pattern**: `192.168.1.100`
- **Redacted**: `192.168.XXX.XXX` (preserves network prefix)
- **Full Redaction**: `[IP_REDACTED]` (if configured)

#### IPv6 Addresses
- **Pattern**: `2001:db8::1`
- **Redacted**: `[IPV6_REDACTED]`

#### MAC Addresses
- **Pattern**: `aa:bb:cc:dd:ee:ff`
- **Redacted**: `aa:bb:cc:[REDACTED]` (preserves OUI for troubleshooting)

#### File Paths
- **Pattern**: `/home/john_doe/capture.pcap`
- **Redacted**: `/home/[USER]/capture.pcap`
- **Windows**: `C:\Users\Alice\file.pcap` → `C:\Users\[USER]\file.pcap`

#### Credentials (CWE-532)
- **Passwords**: `password=secret` → `password=[REDACTED]`
- **API Keys**: `api_key=abc123` → `api_key=[REDACTED]`
- **Bearer Tokens**: `Bearer eyJhbG...` → `Bearer [REDACTED]`
- **Basic Auth**: `Basic dXNlcj...` → `Basic [REDACTED]`

### Redaction Levels

#### PRODUCTION (Default)
Redacts all PII for maximum privacy protection:
```python
# Environment variable
export PCAP_ANALYZER_REDACTION_LEVEL=PRODUCTION

# Or in code
from src.utils.pii_redactor import redact_for_logging, REDACTION_PRODUCTION
safe_msg = redact_for_logging("IP: 10.0.0.1", level=REDACTION_PRODUCTION)
# Result: "IP: 10.0.XXX.XXX"
```

**Redacts**:
- IP addresses (preserves first 2 octets)
- MAC addresses (preserves OUI)
- File paths (preserves structure)
- All credentials

#### DEVELOPMENT
Keeps IPs for debugging, but redacts credentials:
```python
export PCAP_ANALYZER_REDACTION_LEVEL=DEVELOPMENT

safe_msg = redact_for_logging("Testing 10.0.0.1 with api_key=secret")
# Result: "Testing 10.0.0.1 with api_key=[REDACTED]"
```

**Keeps**:
- IP addresses (for debugging)

**Redacts**:
- MAC addresses
- File paths
- All credentials

#### DEBUG
No redaction (WARNING: NOT GDPR-COMPLIANT):
```python
export PCAP_ANALYZER_REDACTION_LEVEL=DEBUG

# ⚠️ WARNING: Only use in isolated development environments
# Never store or transmit DEBUG logs
```

### Configuration

#### config.yaml
```yaml
logging:
  pii_redaction:
    enabled: true  # MUST be true in production
    level: "PRODUCTION"  # PRODUCTION | DEVELOPMENT | DEBUG
    preserve_network_prefixes: true  # Keep first 2 octets of IPs

    # Legal basis for logging (GDPR Art. 6)
    legal_basis: "legitimate_interest_security_monitoring"

    # Data retention (GDPR Art. 5(1)(e))
    retention_days: 90

    # Audit logging (unredacted - requires secure infrastructure)
    audit_log:
      enabled: false
      path: "/var/log/pcap_analyzer/secure_audit.log"
      encryption_required: true
      access_control: "security_team_only"
      retention_days: 365
```

#### Environment Variables
```bash
# Set redaction level globally
export PCAP_ANALYZER_REDACTION_LEVEL=PRODUCTION

# Verify environment detection
python -c "from src.utils.pii_redactor import is_production_environment; print(is_production_environment())"
```

### Integration Examples

#### Automatic Filter (Recommended)
```python
import logging
from src.utils.logging_filters import PIIRedactionFilter

logger = logging.getLogger(__name__)
logger.addFilter(PIIRedactionFilter())

# All logs automatically redacted
logger.info("Flow: 10.28.104.211:16586 → 10.179.161.14:10100")
# Logs: "Flow: 10.28.XXX.XXX:16586 → 10.179.XXX.XXX:10100"
```

#### Manual Redaction
```python
from src.utils.pii_redactor import redact_for_logging

message = "User at 192.168.1.100 accessed /home/alice/file.pcap"
safe_message = redact_for_logging(message)
logger.info(safe_message)
# Logs: "User at 192.168.XXX.XXX accessed /home/[USER]/file.pcap"
```

#### Conditional Redaction
```python
from src.utils.logging_filters import ConditionalPIIRedactionFilter
import logging

# Different redaction for different log levels
filter = ConditionalPIIRedactionFilter(
    level_overrides={
        logging.DEBUG: 'DEVELOPMENT',  # Keep IPs in DEBUG logs
        logging.INFO: 'PRODUCTION',    # Redact IPs in INFO+ logs
    }
)
logger.addFilter(filter)
```

#### Secure Audit Logs
```python
from src.utils.logging_filters import AuditLogFilter

# ⚠️ SECURITY CRITICAL: Only for encrypted, access-controlled logs
audit_handler = logging.FileHandler('/secure/audit.log')
audit_handler.addFilter(AuditLogFilter())  # No redaction

# Regular logs get redaction
console_handler = logging.StreamHandler()
console_handler.addFilter(PIIRedactionFilter())

logger.addHandler(audit_handler)  # Unredacted
logger.addHandler(console_handler)  # Redacted
```

### Compliance

#### GDPR Requirements

| Requirement | Implementation |
|-------------|---------------|
| **Art. 5(1)(c)**: Data Minimization | Default PRODUCTION mode redacts all PII |
| **Art. 5(1)(e)**: Storage Limitation | Configurable retention policy (default: 90 days) |
| **Art. 6**: Legal Basis | Documented: Legitimate interest (security monitoring) |
| **Art. 25**: Data Protection by Design | Redaction enabled by default (opt-out, not opt-in) |
| **Art. 32**: Security of Processing | Encryption required for audit logs |

#### NIST SP 800-122 Requirements

| Control | Implementation |
|---------|---------------|
| **3.1**: PII Identification | IP addresses, MAC addresses, paths, credentials |
| **4.1**: Technical Safeguards | Automatic redaction filters |
| **4.2**: Confidentiality | Production logs redact all PII |
| **5.1**: Retention | Configurable retention policy |

#### CWE-532 Mitigation

**Insertion of Sensitive Information into Log File**:
- Credentials automatically redacted in all modes except DEBUG
- IP addresses redacted by default
- File paths sanitized to remove usernames
- MAC addresses preserve OUI only (manufacturer info)

### Testing

Run comprehensive PII redaction tests:
```bash
python -m pytest tests/test_pii_redaction.py -v
```

**Test Coverage**:
- IPv4/IPv6 redaction (all formats)
- MAC address redaction
- File path redaction (Unix/Windows)
- Credential redaction (passwords, API keys, tokens)
- Logging filter integration
- GDPR compliance validation
- NIST compliance validation
- CWE-532 compliance validation

### Security Best Practices

✅ **DO**:
- Keep redaction enabled in production (default)
- Use PRODUCTION level for public-facing systems
- Configure retention policies per compliance requirements
- Encrypt audit logs if unredacted logging is needed
- Document legal basis for logging (GDPR Art. 6)
- Review logs regularly for PII leakage

❌ **DON'T**:
- Use DEBUG mode in production
- Store or transmit DEBUG logs
- Disable redaction without legal justification
- Share logs containing unredacted PII externally
- Keep logs longer than necessary (GDPR Art. 5(1)(e))

### Troubleshooting

#### IPs still appearing in logs

**Check redaction level**:
```python
from src.utils.pii_redactor import get_redaction_level
print(get_redaction_level())  # Should be 'PRODUCTION'
```

**Verify filter is applied**:
```python
import logging
logger = logging.getLogger('your_module')
print(logger.filters)  # Should include PIIRedactionFilter
```

#### Need IPs for debugging

**Use DEVELOPMENT mode temporarily**:
```bash
export PCAP_ANALYZER_REDACTION_LEVEL=DEVELOPMENT
```

**Or create separate debug logger**:
```python
debug_logger = logging.getLogger('debug')
debug_logger.addFilter(PIIRedactionFilter(redaction_level='DEVELOPMENT'))
```

#### Compliance audit requirements

**Generate compliance report**:
```python
from src.utils.pii_redactor import log_redaction_status
log_redaction_status()
# Logs: "PII Redaction Configuration: Level=PRODUCTION, Environment=PRODUCTION"
```

**Document retention policy**:
1. Update `config.yaml` with retention_days
2. Implement log rotation (logrotate, systemd)
3. Document in privacy policy

### Legal Documentation

#### Legal Basis for Logging (GDPR Art. 6)

**Legitimate Interest** (Art. 6(1)(f)):
- **Purpose**: Security monitoring, incident response, performance analysis
- **Necessity**: Essential for system security and operation
- **Balancing Test**: Security interest outweighs privacy impact (with minimization)
- **Safeguards**: PII redaction by default, limited retention

**Documented in**: `config.yaml` → `logging.pii_redaction.legal_basis`

#### Data Subject Rights

Users have rights to:
1. **Access**: Request copy of their logs (Art. 15)
2. **Erasure**: Request deletion (Art. 17) - respect retention policy
3. **Portability**: Receive data in machine-readable format (Art. 20)

**Implementation Notes**:
- Redacted logs make identification difficult (privacy-by-design)
- Audit logs may contain unredacted data (secure access only)
- Document data subject request procedures

---

## Decompression Bomb Protection (OWASP ASVS 5.2.3)

### Quick Start

```bash
# Default protection (recommended)
pcap_analyzer analyze suspicious.pcap

# Custom threshold for high-bandwidth networks
pcap_analyzer analyze datacenter.pcap --max-expansion-ratio 5000

# Bypass for trusted files (use with caution)
pcap_analyzer analyze trusted.pcap --allow-large-expansion
```

### What It Protects Against

**Decompression Bomb Attack** (also called Zip Bomb):
- Small compressed file (e.g., 100 KB)
- Expands to massive size (e.g., 100 GB)
- Exhausts system memory/CPU
- Causes denial of service

**Example Attack Scenario**:
```
Attacker sends:     100 KB PCAP file
System attempts:    Expand to 100 GB in memory
Result:            System crashes (without protection)
Protection:        Detects 1,000,000:1 ratio and aborts
```

### How It Works

1. **Monitor File Size**: Track original PCAP file size
2. **Track Bytes Processed**: Sum of all packet bytes read
3. **Calculate Ratio**: `bytes_processed / file_size`
4. **Check Periodically**: Every 10,000 packets (efficient)
5. **Progressive Alerts**:
   - Ratio >= 1000:1 → WARNING (log only)
   - Ratio >= 10000:1 → CRITICAL (abort immediately)

### Default Thresholds (OWASP Recommended)

| Threshold | Ratio | Action |
|-----------|-------|--------|
| Warning | 1000:1 | Log security warning |
| Critical | 10000:1 | Abort processing |
| Check Interval | 10000 packets | Performance optimization |

### CLI Options

```bash
--max-expansion-ratio INTEGER
    Maximum safe expansion ratio (default: 1000)
    OWASP ASVS 5.2.3 recommended threshold

--allow-large-expansion
    Disable protection completely
    ⚠️  WARNING: Use only for trusted files
```

### When to Adjust Thresholds

**Use Higher Threshold** (e.g., 5000):
- High-bandwidth networks (10Gbps+)
- Long-duration captures (days/weeks)
- Known legitimate large captures

**Use Lower Threshold** (e.g., 500):
- Untrusted external sources
- User-uploaded files
- Public-facing analysis tools
- Maximum security environments

### Examples

#### Example 1: Default Protection (Recommended)
```bash
pcap_analyzer analyze untrusted_source.pcap
```

**Output if bomb detected**:
```
SECURITY: Decompression bomb detected!
Expansion ratio 15000.0:1 exceeds critical threshold of 10000:1.
File size: 1,000,000 bytes, Bytes processed: 15,000,000,000 bytes
Processing aborted to prevent resource exhaustion.
Reference: OWASP ASVS 5.2.3, CWE-409
```

#### Example 2: High-Bandwidth Network
```bash
pcap_analyzer analyze datacenter_10gbps.pcap --max-expansion-ratio 5000
```

#### Example 3: Trusted Internal File
```bash
pcap_analyzer analyze internal_monitor.pcap --allow-large-expansion
```

### Python API

```python
from src.utils.decompression_monitor import DecompressionMonitor

# Create monitor with custom thresholds
monitor = DecompressionMonitor(
    max_ratio=1000,        # Warning threshold
    critical_ratio=10000,  # Abort threshold
    enabled=True
)

# Check expansion ratio
try:
    stats = monitor.check_expansion_ratio(
        file_size=os.path.getsize("capture.pcap"),
        bytes_processed=total_bytes,
        packets_count=packet_num
    )
except DecompressionBombError as e:
    print(f"Security alert: {e}")
    # Handle bomb detection
```

### Performance Impact

| Metric | Value |
|--------|-------|
| CPU Overhead | ~0.1% |
| Memory Overhead | 24 bytes |
| Check Frequency | Every 10,000 packets |
| Processing Impact | None (negligible) |

### Security Standards

✓ **OWASP ASVS v4.0.3 - 5.2.3**: Compressed File Validation
✓ **CWE-409**: Improper Handling of Highly Compressed Data
✓ **NIST SP 800-53 SI-10**: Information Input Validation
✓ **OpenSSF Python Guide**: Data amplification attacks

### Testing

```bash
# Run comprehensive test suite
python test_decompression_protection.py

# Run module self-test
python -m src.utils.decompression_monitor
```

**Expected Output**:
```
Testing DecompressionMonitor...
Test 1: Safe ratio (100:1)       ✓ PASS
Test 2: Warning ratio (1500:1)   ✓ PASS
Test 3: Critical ratio (15000:1) ✓ PASS
All tests completed!
```

### Troubleshooting

#### Warning: High expansion ratio detected

**Meaning**: File expansion between 1000:1 and 10000:1

**Actions**:
1. Review file source (trusted vs untrusted)
2. Check file integrity (corruption?)
3. Adjust threshold if legitimate: `--max-expansion-ratio 2000`
4. Continue monitoring logs

#### Error: Decompression bomb detected

**Meaning**: File expansion exceeds 10000:1 (critical)

**Actions if untrusted source**:
1. ❌ **STOP** - Do not process further
2. 🔍 Investigate file origin
3. 🛡️ Quarantine file
4. 📝 Report to security team

**Actions if trusted source**:
1. Verify file is legitimate large capture
2. Use bypass flag: `--allow-large-expansion`
3. Or adjust threshold: `--max-expansion-ratio 20000`

#### Processing stops at packet N

**Meaning**: Bomb detected during analysis

**Recovery**:
- Partial results are preserved
- Check logs for expansion ratio
- Validate file integrity
- Consider using smaller time windows

### False Positives

Legitimate scenarios that may trigger warnings:

1. **10Gbps+ Networks**: High packet rate, full capture
   - **Solution**: `--max-expansion-ratio 5000`

2. **Long Captures**: Days/weeks of continuous monitoring
   - **Solution**: `--max-expansion-ratio 2000`

3. **Loopback Traffic**: Heavy localhost communication
   - **Solution**: `--allow-large-expansion` (if trusted)

### Security Best Practices

✅ **DO**:
- Keep protection enabled by default
- Use default thresholds for untrusted input
- Monitor logs for warnings
- Validate file sources
- Adjust thresholds based on known network characteristics

❌ **DON'T**:
- Disable protection globally
- Process untrusted files with `--allow-large-expansion`
- Ignore warning messages
- Set extremely high thresholds without justification

### Documentation

- **Full Guide**: `DECOMPRESSION_BOMB_PROTECTION.md`
- **Implementation**: `IMPLEMENTATION_SUMMARY.md`
- **API Reference**: `src/utils/decompression_monitor.py` (docstrings)
- **Tests**: `test_decompression_protection.py`

### Support

For security issues:
1. Check logs for detailed messages
2. Review `DECOMPRESSION_BOMB_PROTECTION.md`
3. Consult security team if suspicious activity
4. Report potential attacks to administrators

---

**🛡️ Security Notice**: Decompression bomb protection is a critical security control that prevents resource exhaustion attacks. Only disable when absolutely necessary and with proper authorization.

**📚 Learn More**:
- [OWASP ASVS](https://github.com/OWASP/ASVS)
- [CWE-409 Details](https://cwe.mitre.org/data/definitions/409.html)
- [ZIP Bomb Attack Overview](https://en.wikipedia.org/wiki/Zip_bomb)
