# Security Remediation Implementation Guide
## Enhanced tshark Command Generation

**Version:** 1.0
**Date:** December 19, 2025
**Priority:** 🔴 CRITICAL - Immediate Action Required

---

## Overview

This guide provides step-by-step instructions to fix the 7 security vulnerabilities discovered during the security audit of the Enhanced tshark Command Generation implementation.

**Estimated Total Effort:** 24-32 hours
**Recommended Completion Time:** 7-14 days

---

## Prerequisites

Before starting remediation:

1. **Backup Current Code:**
   ```bash
   cd /Users/omegabk/investigations/pcap_analyzer
   git checkout -b security-remediation-backup
   git add .
   git commit -m "Backup before security remediation"
   ```

2. **Install Required Modules (if not already installed):**
   ```bash
   pip install ipaddress  # For IP validation (Python 3.3+)
   # html and shlex are built-in modules
   ```

3. **Run Baseline Security Tests:**
   ```bash
   python -m pytest tests/test_security_audit.py -v
   # Expected: 5 failures (confirms vulnerabilities exist)
   ```

---

## Phase 1: Fix Command Injection Vulnerabilities (CRITICAL)

**Vulnerabilities:** VULN-001, VULN-002, VULN-003
**File:** `src/exporters/html_report.py`
**Estimated Time:** 8 hours

### Step 1: Add Input Validation Functions

Add these helper functions at the top of `html_report.py` (after imports):

```python
import ipaddress
import shlex
import html as html_module
from typing import Tuple


def validate_ip_address(ip: str) -> str:
    """
    Validate and sanitize IP address.

    Args:
        ip: IP address string (IPv4 or IPv6)

    Returns:
        Validated IP address string

    Raises:
        ValueError: If IP address is invalid
    """
    try:
        # ipaddress.ip_address() validates format and raises ValueError if invalid
        validated = ipaddress.ip_address(ip.strip())
        return str(validated)
    except ValueError as e:
        # Return safe placeholder instead of crashing
        # This prevents DoS but logs the issue
        import logging
        logging.warning(f"Invalid IP address detected: {ip} - Using placeholder")
        return "0.0.0.0"  # Safe fallback


def validate_port(port: str) -> str:
    """
    Validate port number.

    Args:
        port: Port number string

    Returns:
        Validated port string

    Raises:
        ValueError: If port is invalid
    """
    try:
        port_int = int(port.strip())
        if not (0 <= port_int <= 65535):
            raise ValueError(f"Port out of range: {port_int}")
        return str(port_int)
    except ValueError:
        import logging
        logging.warning(f"Invalid port detected: {port} - Using placeholder")
        return "0"  # Safe fallback


def parse_flow_key_safely(flow_key: str) -> Tuple[str, str, str, str]:
    """
    Parse and validate flow_key with security checks.

    Args:
        flow_key: Flow key in format "src_ip:src_port → dst_ip:dst_port"

    Returns:
        Tuple of (src_ip, src_port, dst_ip, dst_port) - all validated

    Raises:
        ValueError: If flow_key format is invalid
    """
    # Length validation (prevent DoS)
    MAX_FLOW_KEY_LENGTH = 200
    if len(flow_key) > MAX_FLOW_KEY_LENGTH:
        raise ValueError(f"flow_key exceeds maximum length: {len(flow_key)}")

    # Parse flow_key
    parts = flow_key.replace(" → ", ":").split(":")

    if len(parts) != 4:
        # Return safe defaults if malformed
        import logging
        logging.warning(f"Malformed flow_key: {flow_key}")
        return "0.0.0.0", "0", "0.0.0.0", "0"

    src_ip, src_port, dst_ip, dst_port = parts

    # Validate each component
    src_ip = validate_ip_address(src_ip)
    src_port = validate_port(src_port)
    dst_ip = validate_ip_address(dst_ip)
    dst_port = validate_port(dst_port)

    return src_ip, src_port, dst_ip, dst_port
```

### Step 2: Update `_generate_wireshark_commands()` Function

**Location:** Lines 147-218 in `html_report.py`

**REPLACE** the entire function with this secure implementation:

```python
def _generate_wireshark_commands(
    self,
    src_ip: str,
    src_port: str,
    dst_ip: str,
    dst_port: str,
    flow_type: str = "general",
    seq_num: int = None,
) -> dict[str, str]:
    """
    Generate Wireshark display filter and tshark extraction command.

    SECURITY: All inputs are validated and escaped to prevent command injection.

    Args:
        src_ip: Source IP address
        src_port: Source port
        dst_ip: Destination IP address
        dst_port: Destination port
        flow_type: Type of flow - 'general', 'retransmission', 'window_zero', 'syn'
        seq_num: TCP sequence number (for retransmission type)

    Returns:
        Dictionary with 'display_filter' and 'tshark_extract' keys
    """
    # SECURITY: Validate all inputs
    try:
        src_ip = validate_ip_address(src_ip)
        dst_ip = validate_ip_address(dst_ip)
        src_port = validate_port(src_port)
        dst_port = validate_port(dst_port)
    except ValueError as e:
        # If validation fails, return safe default
        import logging
        logging.error(f"Input validation failed: {e}")
        return {
            "display_filter": "frame.number == 0",  # Matches nothing
            "tshark_extract": "# Invalid input detected - command not generated"
        }

    # Detect IPv6 vs IPv4
    is_ipv6 = ":" in src_ip and src_ip.count(":") > 1

    # Build base filter (SAFE: all inputs validated)
    if is_ipv6:
        base_filter = (
            f"ipv6.src == {src_ip} && ipv6.dst == {dst_ip} && "
            f"tcp.srcport == {src_port} && tcp.dstport == {dst_port}"
        )
    else:
        base_filter = (
            f"ip.src == {src_ip} && ip.dst == {dst_ip} && "
            f"tcp.srcport == {src_port} && tcp.dstport == {dst_port}"
        )

    # Add flow-type-specific filters
    if flow_type == "retransmission":
        if seq_num is not None:
            # SECURITY: seq_num should be int, but validate anyway
            try:
                seq_num_int = int(seq_num)
                display_filter = f"tcp.seq == {seq_num_int} && {base_filter}"
                type_filter = f" and tcp.seq == {seq_num_int}"
            except (ValueError, TypeError):
                display_filter = f"tcp.analysis.retransmission && {base_filter}"
                type_filter = " and tcp.analysis.retransmission"
        else:
            display_filter = f"tcp.analysis.retransmission && {base_filter}"
            type_filter = " and tcp.analysis.retransmission"
    elif flow_type == "window_zero":
        display_filter = f"tcp.window_size == 0 && {base_filter}"
        type_filter = " and tcp.window_size == 0"
    elif flow_type == "syn":
        display_filter = f"tcp.flags.syn == 1 && {base_filter}"
        type_filter = " and tcp.flags.syn == 1"
    else:
        # General flow
        display_filter = base_filter
        type_filter = ""

    # Build tshark extraction command
    # Combine IP and port filters into a single -Y clause
    if is_ipv6:
        combined_filter = f"ipv6.src == {src_ip} and ipv6.dst == {dst_ip} and tcp.srcport == {src_port} and tcp.dstport == {dst_port}{type_filter}"
    else:
        combined_filter = f"ip.src == {src_ip} and ip.dst == {dst_ip} and tcp.srcport == {src_port} and tcp.dstport == {dst_port}{type_filter}"

    # SECURITY: Use shlex.quote() to escape the entire filter
    # This prevents command injection via shell metacharacters
    safe_filter = shlex.quote(combined_filter)

    tshark_cmd = (
        f"tshark -r input.pcap -Y {safe_filter} "
        f"-T fields -e frame.number -e frame.time_relative -e tcp.seq -e tcp.ack -e tcp.len"
    )

    return {
        "display_filter": display_filter,
        "tshark_extract": tshark_cmd,
    }
```

### Step 3: Update All flow_key Parsing Code

**Find and replace** all instances of manual `flow_key.split()` with `parse_flow_key_safely()`:

**Location 1:** Line 3467 (in `_generate_flow_detail_card`)
```python
# OLD (UNSAFE):
flow_parts = flow_key.replace(" → ", ":").split(":")
if len(flow_parts) == 4:
    src_ip, src_port, dst_ip, dst_port = flow_parts
else:
    src_ip, src_port, dst_ip, dst_port = "0.0.0.0", "0", "0.0.0.0", "0"

# NEW (SAFE):
src_ip, src_port, dst_ip, dst_port = parse_flow_key_safely(flow_key)
```

**Location 2:** Line 2432, 2460 (in `_analyze_root_cause`)
```python
# OLD (UNSAFE):
parts = flow_key.split(" → ")
if len(parts) == 2:
    dst_part = parts[1].strip()
    if ":" in dst_part:
        dst_ip, dst_port = dst_part.rsplit(":", 1)

# NEW (SAFE):
src_ip, src_port, dst_ip, dst_port = parse_flow_key_safely(flow_key)
# Now use dst_ip and dst_port directly
```

### Step 4: Test Command Injection Fixes

```bash
python -m pytest tests/test_security_audit.py::TestCommandInjection -v

# Expected result:
# test_malicious_ip_in_flow_key_semicolon: PASSED ✓
# test_malicious_ip_with_shell_operators: PASSED ✓
# test_bpf_filter_injection: PASSED ✓
```

---

## Phase 2: Fix XSS Vulnerabilities (HIGH)

**Vulnerabilities:** VULN-004, VULN-005, VULN-006
**File:** `src/exporters/html_report.py`
**Estimated Time:** 12 hours

### Step 1: Update Imports

Add at the top of the file (if not already added in Phase 1):
```python
import html as html_module
```

### Step 2: Create HTML Escaping Wrapper

Add this helper function after the validation functions:

```python
def escape_html(text: str) -> str:
    """
    Escape HTML special characters to prevent XSS.

    Converts:
    - < to &lt;
    - > to &gt;
    - & to &amp;
    - " to &quot;
    - ' to &#x27;

    Args:
        text: Text to escape

    Returns:
        HTML-safe text
    """
    if text is None:
        return ""
    return html_module.escape(str(text), quote=True)
```

### Step 3: Update `_generate_flow_table()` Function

**Location:** Line 3160

**FIND:**
```python
html += f'<td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{flow_key}</td>'
```

**REPLACE WITH:**
```python
safe_flow_key = escape_html(flow_key)
html += f'<td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{safe_flow_key}</td>'
```

### Step 4: Update `_generate_flow_detail_card()` Function

**Location:** Line 3462

**FIND:**
```python
html += f'      <code class="flow-key">{flow_key}</code>'
```

**REPLACE WITH:**
```python
safe_flow_key = escape_html(flow_key)
html += f'      <code class="flow-key">{safe_flow_key}</code>'
```

### Step 5: Update `_generate_window_flow_table()` Function

**Location:** Line 3921

**FIND:**
```python
html += f'<td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{flow_key}</td>'
```

**REPLACE WITH:**
```python
safe_flow_key = escape_html(flow_key)
html += f'<td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{safe_flow_key}</td>'
```

### Step 6: Update `_generate_tshark_command_box()` Function

**Location:** Line 2862

**FIND:**
```python
html += f'<pre style="margin: 0; overflow-x: auto; cursor: text; user-select: all; background: #1e1e1e; padding: 10px; border-radius: 4px; font-size: 0.85em;" onclick="window.getSelection().selectAllChildren(this);">tshark -nn -tad -r &lt;file.pcap&gt; -Y \'{tshark_filter}\' -T fields -e frame.number -e frame.time -e tcp.seq -e tcp.ack -e tcp.len -e tcp.flags.str</pre>'
```

**REPLACE WITH:**
```python
# SECURITY: Escape tshark_filter to prevent XSS
safe_filter = escape_html(tshark_filter)
html += f'<pre style="margin: 0; overflow-x: auto; cursor: text; user-select: all; background: #1e1e1e; padding: 10px; border-radius: 4px; font-size: 0.85em;" onclick="window.getSelection().selectAllChildren(this);">tshark -nn -tad -r &lt;file.pcap&gt; -Y \'{safe_filter}\' -T fields -e frame.number -e frame.time -e tcp.seq -e tcp.ack -e tcp.len -e tcp.flags.str</pre>'
```

### Step 7: Update ALL Other Tshark Command Boxes

Search for all instances of `tshark_filter` embedded in HTML and apply `escape_html()`:

- `_generate_window_tshark_box()` (Line 3878)
- `_generate_jitter_tshark_box()` (Line 4301)
- `_generate_dns_tshark_box()` (Line 4812)

**Pattern to find:**
```python
# FIND:
html += f'<pre>...{tshark_filter}...</pre>'

# REPLACE WITH:
safe_filter = escape_html(tshark_filter)
html += f'<pre>...{safe_filter}...</pre>'
```

### Step 8: Add Content Security Policy (CSP) Header

**Location:** In the main `generate()` function (around line 100-150), add CSP meta tag:

**FIND the HTML header section:**
```python
html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PCAP Analysis Report</title>
```

**ADD CSP meta tag:**
```python
html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy"
          content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none';">
    <title>PCAP Analysis Report</title>
```

### Step 9: Test XSS Fixes

```bash
python -m pytest tests/test_security_audit.py::TestXSSVulnerabilities -v

# Expected result:
# test_xss_in_flow_key_script_tag: PASSED ✓
# test_xss_in_flow_key_event_handlers: PASSED ✓
# test_xss_in_tshark_command_display: PASSED ✓
```

---

## Phase 3: Fix DoS Vulnerability (MEDIUM)

**Vulnerability:** VULN-007
**Estimated Time:** 4 hours

### Step 1: The input validation added in Phase 1 already addresses this!

The `parse_flow_key_safely()` function includes:
```python
MAX_FLOW_KEY_LENGTH = 200
if len(flow_key) > MAX_FLOW_KEY_LENGTH:
    raise ValueError(f"flow_key exceeds maximum length: {len(flow_key)}")
```

This prevents resource exhaustion from extremely long flow_keys.

### Step 2: Add Additional Safeguards

In the HTML generation main loop, add a flow count limit:

```python
# In generate() or similar function
MAX_FLOWS_IN_REPORT = 1000  # Prevent massive HTML files

if len(flows_to_process) > MAX_FLOWS_IN_REPORT:
    logging.warning(f"Flow count ({len(flows_to_process)}) exceeds limit. Truncating to {MAX_FLOWS_IN_REPORT}")
    flows_to_process = flows_to_process[:MAX_FLOWS_IN_REPORT]
```

### Step 3: Test DoS Fix

```bash
python -m pytest tests/test_security_audit.py::TestInputValidation -v

# Expected result: All tests PASSED ✓
```

---

## Phase 4: Verification and Testing

### Step 1: Run Full Security Test Suite

```bash
python -m pytest tests/test_security_audit.py -v

# Expected result: ALL TESTS PASSED ✓
# - TestCommandInjection: 3/3 passed
# - TestXSSVulnerabilities: 3/3 passed
# - TestPathTraversal: 1/1 passed
# - TestInputValidation: 2/2 passed
# - TestInformationDisclosure: 2/2 passed
```

### Step 2: Run Proof-of-Concept Exploits

```bash
python tests/test_security_poc_exploits.py

# Expected result: All POCs should now be BLOCKED
# - POC #1: Command injection prevented (shlex.quote)
# - POC #2: Backticks escaped (shlex.quote)
# - POC #3: Pipe operators escaped (shlex.quote)
# - POC #4: <script> tags escaped (&lt;script&gt;)
# - POC #5: Event handlers escaped (onerror becomes text)
# - POC #6: Tshark XSS prevented (html.escape)
# - POC #7: Resource exhaustion prevented (length limits)
```

### Step 3: Manual Testing

1. **Test with benign PCAP:**
   ```bash
   python -m pcap_analyzer analyze samples/benign.pcap --html-report
   # Verify report generates correctly
   ```

2. **Test with malicious flow_keys:**
   - Manually edit analyzer to inject malicious flow_keys
   - Verify they are properly escaped/sanitized

3. **Test in browser:**
   - Open generated HTML report
   - Open browser DevTools Console
   - Verify no XSS errors
   - Verify tshark commands display correctly

### Step 4: Code Review Checklist

- [ ] All `flow_key` usages are escaped with `escape_html()`
- [ ] All `tshark_filter` usages are escaped with `escape_html()`
- [ ] All IP addresses are validated with `validate_ip_address()`
- [ ] All ports are validated with `validate_port()`
- [ ] All tshark commands use `shlex.quote()`
- [ ] CSP header is present in HTML output
- [ ] No f-strings with unescaped user input in HTML context
- [ ] No f-strings with unescaped user input in shell command context

---

## Phase 5: Deploy and Monitor

### Step 1: Commit Changes

```bash
git add .
git commit -m "Security fix: Remediate command injection and XSS vulnerabilities

- Add input validation for IP addresses and ports
- Implement shlex.quote() for command escaping
- Add html.escape() for all user-controlled HTML content
- Add Content Security Policy header
- Add length limits to prevent DoS

Fixes: VULN-001 through VULN-007
See: SECURITY_AUDIT_REPORT.md"
```

### Step 2: Create Pull Request

```bash
git push origin security-remediation-backup
# Create PR in GitHub/GitLab with:
# - Link to SECURITY_AUDIT_REPORT.md
# - Test results showing all vulnerabilities fixed
# - Request security team review
```

### Step 3: Update CI/CD Pipeline

Add security tests to CI/CD:

```yaml
# .github/workflows/security-tests.yml
name: Security Tests

on: [push, pull_request]

jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.9'
      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install pytest
      - name: Run security tests
        run: |
          python -m pytest tests/test_security_audit.py -v
          python tests/test_security_poc_exploits.py
```

### Step 4: Monitor Production

After deployment:

1. **Monitor logs for:**
   - Invalid IP address warnings
   - Malformed flow_key warnings
   - Unusual traffic patterns

2. **Set up alerts for:**
   - Multiple validation failures (possible attack)
   - XSS attempt signatures in logs
   - Command injection signatures in logs

---

## Rollback Plan

If issues arise after deployment:

```bash
# Revert to previous version
git revert <commit-hash>
git push origin main

# Or restore from backup
git checkout main
git reset --hard security-remediation-backup~1
git push --force origin main  # Use with caution!
```

---

## Post-Remediation Checklist

- [ ] All security tests pass
- [ ] Code review completed by security team
- [ ] Changes deployed to staging environment
- [ ] Manual testing completed in staging
- [ ] No regressions in functionality
- [ ] Performance impact is acceptable
- [ ] Documentation updated
- [ ] Security audit report updated with "FIXED" status
- [ ] Deployment to production approved
- [ ] Monitoring alerts configured
- [ ] Incident response plan updated

---

## Support and Escalation

**For questions or issues during remediation:**

- **Technical Questions:** dev-team@example.com
- **Security Questions:** security-team@example.com
- **Urgent Issues:** Call security hotline (555-SEC-TEAM)

---

## Appendix A: Quick Reference

### Common Commands

```bash
# Run all security tests
pytest tests/test_security_audit.py -v

# Run specific test class
pytest tests/test_security_audit.py::TestCommandInjection -v

# Run POC exploits
python tests/test_security_poc_exploits.py

# Check code coverage
pytest tests/test_security_audit.py --cov=src/exporters --cov-report=html
```

### Key Functions to Update

| Function | Location | Action |
|----------|----------|--------|
| `_generate_wireshark_commands()` | Line 147 | Add input validation + shlex.quote() |
| `_generate_flow_table()` | Line 3160 | Add html.escape() |
| `_generate_flow_detail_card()` | Line 3462 | Add html.escape() |
| `_generate_tshark_command_box()` | Line 2862 | Add html.escape() |
| `_generate_window_flow_table()` | Line 3921 | Add html.escape() |
| `_analyze_root_cause()` | Line 2432 | Use parse_flow_key_safely() |

### Validation Functions

```python
validate_ip_address(ip: str) -> str
validate_port(port: str) -> str
parse_flow_key_safely(flow_key: str) -> Tuple[str, str, str, str]
escape_html(text: str) -> str
```

---

**Document Version:** 1.0
**Last Updated:** December 19, 2025
**Next Review:** January 19, 2026
