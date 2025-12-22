# Packet Timeline Implementation Guide

**Quick Start Guide for Developers**

---

## Overview

This guide provides step-by-step instructions for implementing the packet timeline visual interface in HTML reports. The design is complete and production-ready.

---

## Quick Integration Checklist

- [ ] Review design documentation (`UX_DESIGN_PACKET_TIMELINE.md`)
- [ ] Copy CSS styles to `html_report.py`
- [ ] Update HTML generation functions
- [ ] Test accessibility (WCAG 2.1 compliance)
- [ ] Test responsive design (mobile, tablet, desktop)
- [ ] Test print stylesheet
- [ ] Validate with real PCAP data

---

## File Structure

```
docs/
├── UX_DESIGN_PACKET_TIMELINE.md      # Complete UX design specification
├── packet-timeline-styles.css        # Production-ready CSS stylesheet
├── packet-timeline-mockup.html       # Interactive HTML demo
├── DESIGN_SYSTEM_REFERENCE.md        # Color palette, typography, accessibility
└── IMPLEMENTATION_GUIDE.md           # This file
```

---

## Step 1: Integrate CSS

### Location
Add styles to `/Users/omegabk/investigations/pcap_analyzer/src/exporters/html_report.py`

### Method
Insert packet timeline CSS after line 2063 (end of existing `</style>` block):

```python
def generate(self, results: dict[str, Any], output_path: Path) -> None:
    """Generate HTML report."""

    html_parts = []
    html_parts.append('<!DOCTYPE html>')
    html_parts.append('<html lang="en">')
    html_parts.append('<head>')
    html_parts.append('  <meta charset="UTF-8">')
    html_parts.append('  <meta name="viewport" content="width=device-width, initial-scale=1.0">')
    html_parts.append('  <title>PCAP Analysis Report</title>')
    html_parts.append('  <style>')

    # ... existing styles (lines 864-2063) ...

    # ADD PACKET TIMELINE STYLES HERE
    html_parts.append(self._get_packet_timeline_css())

    html_parts.append('  </style>')
    html_parts.append('</head>')
    # ... rest of HTML ...

def _get_packet_timeline_css(self) -> str:
    """Return packet timeline CSS styles."""
    return """
    /* Packet Timeline Styles */
    /* Copy content from packet-timeline-styles.css */
    """
```

**Alternative:** Inline the CSS directly (for self-contained HTML):

```python
html_parts.append("""
    /* ============================================
       PACKET TIMELINE STYLES
       ============================================ */

    /* CSS Variables */
    :root {
      --font-mono: 'Monaco', 'Consolas', 'Courier New', monospace;
      --bg-handshake: #f0f9f4;
      --bg-rto: #fff5f5;
      /* ... rest of variables ... */
    }

    /* Component Styles */
    .packet-table-wrapper { /* ... */ }
    /* ... rest of styles ... */
""")
```

---

## Step 2: Generate Packet Timeline HTML

### Create Helper Method

Add to `HTMLReportGenerator` class:

```python
def _render_packet_timeline(
    self,
    flow_key: str,
    packets: list[dict],
    retransmissions: list[dict]
) -> str:
    """
    Render packet timeline for a TCP flow.

    Args:
        flow_key: Flow identifier "src_ip:src_port → dst_ip:dst_port"
        packets: List of all packets in the flow
        retransmissions: List of retransmission events

    Returns:
        HTML string with complete packet timeline
    """
    html = []

    # Generate unique ID for collapsible section
    flow_id = flow_key.replace(":", "_").replace(" → ", "_to_").replace(".", "_")

    # Collapsible container
    html.append(f'<input type="checkbox" id="flow-{flow_id}" class="flow-expand-checkbox" aria-controls="details-{flow_id}">')

    # Summary stats (visible when collapsed)
    html.append('<div class="flow-summary">')
    html.append(f'  <div class="flow-summary-stat">')
    html.append(f'    <span class="label">Retransmissions:</span>')
    html.append(f'    <span class="value">{len(retransmissions)}</span>')
    html.append(f'  </div>')
    html.append('</div>')

    # Expand button
    html.append(f'<label for="flow-{flow_id}" class="flow-expand-btn" role="button">')
    html.append('  <span class="expand-icon">➕</span>')
    html.append('  <span>Expand Packet Timeline</span>')
    html.append('</label>')

    # Timeline details (hidden by default)
    html.append(f'<div id="details-{flow_id}" class="flow-details">')

    # Section 1: Handshake
    handshake_packets = self._get_handshake_packets(packets)
    if handshake_packets:
        html.append(self._render_handshake_section(handshake_packets))

    # Section 2: Retransmissions
    if retransmissions:
        html.append(self._render_retransmission_sections(packets, retransmissions))

    # Section 3: Teardown
    teardown_packets = self._get_teardown_packets(packets)
    if teardown_packets:
        html.append(self._render_teardown_section(teardown_packets))

    html.append('</div>')  # End flow-details

    return '\n'.join(html)
```

### Render Packet Table

```python
def _render_packet_table(
    self,
    packets: list[dict],
    section_type: str = "normal"
) -> str:
    """
    Render packet table with proper styling.

    Args:
        packets: List of packet dictionaries
        section_type: "handshake", "retransmission", "teardown", or "normal"

    Returns:
        HTML table with packets
    """
    html = []

    html.append('<div class="packet-table-wrapper">')
    html.append('  <table class="packet-table" role="table">')
    html.append('    <thead>')
    html.append('      <tr>')
    html.append('        <th scope="col" class="col-number">#</th>')
    html.append('        <th scope="col" class="col-time">Time</th>')
    html.append('        <th scope="col" class="col-direction">Dir</th>')
    html.append('        <th scope="col" class="col-flags">Flags</th>')
    html.append('        <th scope="col" class="col-seq">Seq</th>')
    html.append('        <th scope="col" class="col-ack">Ack</th>')
    html.append('        <th scope="col" class="col-length">Len</th>')
    html.append('        <th scope="col" class="col-type">Type</th>')
    html.append('      </tr>')
    html.append('    </thead>')
    html.append('    <tbody>')

    for packet in packets:
        row_class = self._get_packet_row_class(packet)
        html.append(f'      <tr class="{row_class}" tabindex="0">')

        # Packet number
        html.append(f'        <td class="col-number">{packet["number"]}</td>')

        # Timestamp
        time_str = f'{packet["timestamp"]:.3f}s'
        html.append(f'        <td class="col-time mono time-relative">{time_str}</td>')

        # Direction
        direction_class = "direction-outbound" if packet.get("outbound") else "direction-inbound"
        html.append(f'        <td class="col-direction">')
        html.append(f'          <span class="direction {direction_class}"></span>')
        html.append(f'        </td>')

        # Flags
        flags_html = self._render_tcp_flags(packet.get("flags", ""))
        html.append(f'        <td class="col-flags">{flags_html}</td>')

        # Seq/Ack
        html.append(f'        <td class="col-seq mono">{packet.get("seq", 0)}</td>')
        html.append(f'        <td class="col-ack mono">{packet.get("ack", 0)}</td>')

        # Length
        html.append(f'        <td class="col-length mono">{packet.get("length", 0)}</td>')

        # Type badge
        badge_html = self._render_packet_type_badge(packet)
        html.append(f'        <td class="col-type">{badge_html}</td>')

        html.append('      </tr>')

    html.append('    </tbody>')
    html.append('  </table>')
    html.append('</div>')

    return '\n'.join(html)
```

### Helper Functions

```python
def _get_packet_row_class(self, packet: dict) -> str:
    """Determine CSS class for packet row."""
    packet_type = packet.get("type", "normal")

    if packet_type == "handshake":
        return "packet-handshake"
    elif packet_type == "rto":
        return "packet-rto"
    elif packet_type == "fast_retrans":
        return "packet-fast-retrans"
    elif packet_type == "teardown_fin":
        return "packet-teardown-clean"
    elif packet_type == "teardown_rst":
        return "packet-teardown-rst"
    else:
        return "packet-normal"

def _render_tcp_flags(self, flags: str) -> str:
    """Render TCP flags with icons."""
    flag_map = {
        "SYN": ("🤝", "flag-syn"),
        "ACK": ("✅", "flag-ack"),
        "FIN": ("📭", "flag-fin"),
        "RST": ("🚨", "flag-rst"),
        "PSH": ("📤", "flag-psh"),
    }

    # Parse flags (e.g., "PSH,ACK" or "SYN")
    flag_parts = [f.strip() for f in flags.split(",")]

    # Special case: combined flags
    if "SYN" in flag_parts and "ACK" in flag_parts:
        return '<span class="tcp-flag flag-syn"><span class="icon">🤝</span> <span class="flag-text">SYN/ACK</span></span>'
    elif "PSH" in flag_parts and "ACK" in flag_parts:
        return '<span class="tcp-flag flag-psh"><span class="icon">📤✅</span> <span class="flag-text">PSH/ACK</span></span>'
    elif "FIN" in flag_parts and "ACK" in flag_parts:
        return '<span class="tcp-flag flag-fin"><span class="icon">📭</span> <span class="flag-text">FIN/ACK</span></span>'

    # Single flag
    for flag in flag_parts:
        if flag in flag_map:
            icon, css_class = flag_map[flag]
            return f'<span class="tcp-flag {css_class}"><span class="icon">{icon}</span> <span class="flag-text">{flag}</span></span>'

    return flags

def _render_packet_type_badge(self, packet: dict) -> str:
    """Render packet type badge."""
    packet_type = packet.get("type", "normal")

    badge_map = {
        "handshake": ("badge-success", "🤝", "Handshake"),
        "rto": ("badge-danger", "🔴", "RTO"),
        "fast_retrans": ("badge-warning", "⚡", "Fast Retrans"),
        "generic_retrans": ("badge-info", "📋", "Retransmit"),
        "data": ("badge-info", "📤", "Data"),
        "ack": ("badge-success", "✅", "ACK"),
        "teardown_fin": ("badge-info", "📭", "Close"),
        "teardown_rst": ("badge-danger", "🚨", "RST"),
    }

    badge_class, icon, text = badge_map.get(packet_type, ("badge-info", "📋", "Normal"))

    return f'<span class="badge {badge_class}"><span class="icon">{icon}</span> <span>{text}</span></span>'
```

---

## Step 3: Data Structure

### Expected Packet Dictionary Format

```python
packet = {
    "number": 1,                    # Packet number in capture
    "timestamp": 0.000,             # Relative timestamp (seconds)
    "absolute_time": "15:34:22.000", # Absolute timestamp (optional)
    "outbound": True,               # Direction (True=outbound, False=inbound)
    "flags": "SYN",                 # TCP flags (comma-separated: "SYN", "ACK", "PSH,ACK")
    "seq": 1234567890,              # Sequence number
    "ack": 0,                       # Acknowledgment number
    "length": 0,                    # Payload length (bytes)
    "type": "handshake",            # Packet type (see below)
}
```

### Packet Types

| Type | Description | Badge Color | Row Class |
|------|-------------|-------------|-----------|
| `"handshake"` | SYN, SYN-ACK, or ACK during 3-way handshake | Green | `.packet-handshake` |
| `"rto"` | RTO retransmission (timeout-based) | Red | `.packet-rto` |
| `"fast_retrans"` | Fast retransmission (3 dup ACKs) | Yellow | `.packet-fast-retrans` |
| `"generic_retrans"` | Generic retransmission | Blue | `.packet-generic-retrans` |
| `"data"` | Normal data packet (PSH) | Blue | `.packet-normal` |
| `"ack"` | Pure ACK packet | Green | `.packet-normal` |
| `"teardown_fin"` | FIN packet (clean shutdown) | Blue | `.packet-teardown-clean` |
| `"teardown_rst"` | RST packet (abrupt close) | Red | `.packet-teardown-rst` |
| `"normal"` | Any other packet | Gray | `.packet-normal` |

---

## Step 4: Testing

### Unit Tests

Create test file: `tests/test_packet_timeline.py`

```python
import pytest
from src.exporters.html_report import HTMLReportGenerator

def test_render_packet_table():
    """Test packet table rendering."""
    gen = HTMLReportGenerator()

    packets = [
        {
            "number": 1,
            "timestamp": 0.000,
            "outbound": True,
            "flags": "SYN",
            "seq": 1234567890,
            "ack": 0,
            "length": 0,
            "type": "handshake",
        },
        {
            "number": 2,
            "timestamp": 0.023,
            "outbound": False,
            "flags": "SYN,ACK",
            "seq": 9876543210,
            "ack": 1234567891,
            "length": 0,
            "type": "handshake",
        },
    ]

    html = gen._render_packet_table(packets)

    # Verify HTML structure
    assert '<table class="packet-table"' in html
    assert 'packet-handshake' in html
    assert '1234567890' in html  # Sequence number
    assert '🤝' in html  # Handshake icon

def test_tcp_flags_rendering():
    """Test TCP flag icon rendering."""
    gen = HTMLReportGenerator()

    # Test SYN/ACK
    html = gen._render_tcp_flags("SYN,ACK")
    assert '🤝' in html
    assert 'SYN/ACK' in html

    # Test PSH/ACK
    html = gen._render_tcp_flags("PSH,ACK")
    assert '📤✅' in html
    assert 'PSH/ACK' in html

def test_packet_type_badge():
    """Test packet type badge rendering."""
    gen = HTMLReportGenerator()

    # RTO badge
    packet = {"type": "rto"}
    html = gen._render_packet_type_badge(packet)
    assert 'badge-danger' in html
    assert '🔴' in html
    assert 'RTO' in html

    # Fast retransmission badge
    packet = {"type": "fast_retrans"}
    html = gen._render_packet_type_badge(packet)
    assert 'badge-warning' in html
    assert '⚡' in html
```

### Accessibility Tests

```python
def test_accessibility_aria_labels():
    """Test ARIA labels for screen readers."""
    gen = HTMLReportGenerator()

    packets = [
        {
            "number": 1,
            "timestamp": 0.000,
            "outbound": True,
            "flags": "SYN",
            "seq": 1234567890,
            "ack": 0,
            "length": 0,
            "type": "handshake",
        }
    ]

    html = gen._render_packet_table(packets)

    # Check ARIA attributes
    assert 'role="table"' in html
    assert 'scope="col"' in html
    assert 'aria-label' in html.lower()

def test_keyboard_navigation():
    """Test tabindex on interactive elements."""
    gen = HTMLReportGenerator()

    packets = [{"number": 1, "timestamp": 0.0, "type": "normal"}]
    html = gen._render_packet_table(packets)

    # Rows should be focusable
    assert 'tabindex="0"' in html
```

### Visual Regression Tests

```python
def test_color_contrast_ratios():
    """Test WCAG color contrast compliance."""
    # Use pytest-accessibility or manual validation

    from accessibility_checker import check_contrast

    # Test badge combinations
    assert check_contrast("#155724", "#d4edda") >= 4.5  # Success badge
    assert check_contrast("#721c24", "#f8d7da") >= 4.5  # Danger badge
    assert check_contrast("#856404", "#fff3cd") >= 4.5  # Warning badge
```

---

## Step 5: Documentation

### Add Docstrings

```python
def _render_packet_timeline(
    self,
    flow_key: str,
    packets: list[dict],
    retransmissions: list[dict]
) -> str:
    """
    Render complete packet timeline for a TCP flow.

    Generates a collapsible, accessible HTML timeline showing:
    - TCP 3-way handshake
    - Data transfer with retransmissions
    - Connection teardown (FIN or RST)

    Design complies with WCAG 2.1 Level AAA for accessibility.

    Args:
        flow_key: Flow identifier in format "src_ip:src_port → dst_ip:dst_port"
        packets: List of packet dictionaries with keys:
            - number (int): Packet number in capture
            - timestamp (float): Relative timestamp in seconds
            - outbound (bool): True if client→server, False if server→client
            - flags (str): TCP flags (comma-separated: "SYN", "ACK", "PSH,ACK")
            - seq (int): Sequence number
            - ack (int): Acknowledgment number
            - length (int): Payload length in bytes
            - type (str): Packet classification (see _get_packet_row_class)
        retransmissions: List of retransmission events (subset of packets)

    Returns:
        str: HTML string with complete packet timeline

    References:
        - UX Design: docs/UX_DESIGN_PACKET_TIMELINE.md
        - Design System: docs/DESIGN_SYSTEM_REFERENCE.md
        - WCAG 2.1: https://www.w3.org/WAI/WCAG21/quickref/

    Example:
        >>> gen = HTMLReportGenerator()
        >>> packets = [
        ...     {"number": 1, "timestamp": 0.0, "flags": "SYN", "type": "handshake"},
        ...     {"number": 2, "timestamp": 0.023, "flags": "SYN,ACK", "type": "handshake"},
        ... ]
        >>> html = gen._render_packet_timeline("192.168.1.1:1234 → 8.8.8.8:443", packets, [])
        >>> assert "packet-handshake" in html
    """
```

---

## Step 6: Example Usage

### Complete Integration Example

```python
# In html_report.py, update _generate_tcp_section method

def _generate_tcp_section(self, results: dict[str, Any]) -> str:
    """Generate TCP analysis section with packet timelines."""
    html = ["<h2>🔌 TCP Analysis</h2>"]

    # ... existing retransmission summary code ...

    # Add packet timelines for flows with retransmissions
    retrans_data = results.get("retransmission", {})
    if retrans_data:
        retrans_list = retrans_data.get("retransmissions", [])

        # Group retransmissions by flow
        flows = self._group_retransmissions_by_flow(retrans_list)

        for flow_key, flow_retrans in flows.items():
            # Get all packets for this flow
            all_packets = self._get_flow_packets(results, flow_key)

            # Render timeline
            html.append('<div class="flow-card">')
            html.append(f'<h3 class="flow-title">{escape_html(flow_key)}</h3>')
            html.append(self._render_packet_timeline(
                flow_key=flow_key,
                packets=all_packets,
                retransmissions=flow_retrans
            ))
            html.append('</div>')

    return '\n'.join(html)

def _group_retransmissions_by_flow(self, retrans_list: list[dict]) -> dict:
    """Group retransmissions by flow key."""
    flows = {}
    for r in retrans_list:
        flow_key = f"{r['src_ip']}:{r['src_port']} → {r['dst_ip']}:{r['dst_port']}"
        if flow_key not in flows:
            flows[flow_key] = []
        flows[flow_key].append(r)
    return flows

def _get_flow_packets(self, results: dict, flow_key: str) -> list[dict]:
    """
    Extract all packets for a specific flow.

    This is a placeholder - actual implementation depends on
    how packet data is stored in the analyzer results.
    """
    # TODO: Implement based on analyzer data structure
    # Should return list of packet dictionaries

    # Example (adapt to actual data structure):
    all_packets = results.get("packets", [])
    flow_packets = []

    for pkt in all_packets:
        pkt_flow = f"{pkt['src_ip']}:{pkt['src_port']} → {pkt['dst_ip']}:{pkt['dst_port']}"
        if pkt_flow == flow_key:
            flow_packets.append(pkt)

    return flow_packets
```

---

## Step 7: Validation

### Manual Testing Checklist

#### Desktop Browser (Chrome, Firefox, Safari)
- [ ] Expand/collapse buttons work (pure CSS, no JavaScript)
- [ ] Hover effects on table rows
- [ ] Focus indicators visible when tabbing
- [ ] Color contrast meets WCAG 2.1 AA (4.5:1 minimum)
- [ ] All icons paired with text (not icon-only)
- [ ] Print preview shows all expanded content

#### Mobile Browser (iOS Safari, Chrome Mobile)
- [ ] Touch targets ≥ 44×44px
- [ ] Horizontal scrolling works (frozen columns)
- [ ] Columns hide at appropriate breakpoints
- [ ] Expand buttons easy to tap
- [ ] Text readable at default zoom

#### Screen Reader (NVDA, JAWS, VoiceOver)
- [ ] All table headers announced
- [ ] Row content read in logical order
- [ ] Icons have text alternatives
- [ ] Expand/collapse state announced
- [ ] No "unlabeled" or "clickable" warnings

#### Keyboard Navigation
- [ ] Tab order is logical
- [ ] All interactive elements focusable
- [ ] Enter/Space activates expand buttons
- [ ] No keyboard traps
- [ ] Focus visible at all times

---

## Common Issues & Solutions

### Issue 1: Icons Not Displaying

**Symptom:** Emoji icons show as boxes or missing

**Solution:** Ensure UTF-8 encoding:
```python
with open(output_path, "w", encoding="utf-8") as f:
    f.write(html)
```

### Issue 2: Expand/Collapse Not Working

**Symptom:** Clicking expand button does nothing

**Checklist:**
- [ ] Checkbox ID matches label `for` attribute
- [ ] Checkbox has correct CSS class: `flow-expand-checkbox`
- [ ] Details div has correct ID matching `aria-controls`
- [ ] CSS includes `:checked` pseudo-selector rules

**Debug:**
```html
<!-- Ensure these IDs match -->
<input type="checkbox" id="flow-expand-1" class="flow-expand-checkbox" aria-controls="flow-details-1">
<label for="flow-expand-1" class="flow-expand-btn">Expand</label>
<div id="flow-details-1" class="flow-details"><!-- content --></div>
```

### Issue 3: Color Contrast Failures

**Symptom:** Automated tools flag contrast issues

**Solution:** Use design system colors from `DESIGN_SYSTEM_REFERENCE.md`:
- All badge text: 7.2:1 to 8.9:1 (AAA compliant)
- Normal text (#333 on white): 12.6:1
- Avoid custom colors not in palette

### Issue 4: Mobile Columns Not Hiding

**Symptom:** All columns visible on mobile

**Checklist:**
- [ ] Viewport meta tag present: `<meta name="viewport" content="width=device-width, initial-scale=1.0">`
- [ ] Media queries in correct order (max-width descending)
- [ ] Column classes match exactly: `.col-length`, `.col-ack`, etc.

### Issue 5: Print Stylesheet Not Working

**Symptom:** Printed page has collapsed sections or color backgrounds

**Solution:** Ensure print media query is last in CSS:
```css
@media print {
  .flow-details {
    display: block !important;  /* !important to override inline styles */
  }
}
```

---

## Performance Optimization

### For Large Packet Counts (> 1000 packets)

**Problem:** Rendering thousands of table rows causes slow page load

**Solutions:**

1. **Pagination:** Show first 100 packets per section
   ```python
   MAX_PACKETS_PER_SECTION = 100

   if len(packets) > MAX_PACKETS_PER_SECTION:
       packets = packets[:MAX_PACKETS_PER_SECTION]
       html.append(f'<p class="text-muted">Showing first {MAX_PACKETS_PER_SECTION} of {len(packets)} packets</p>')
   ```

2. **Lazy Loading:** Keep sections collapsed by default
   ```html
   <!-- Don't check checkbox by default -->
   <input type="checkbox" id="flow-1" class="flow-expand-checkbox">
   ```

3. **Context Windows:** Show only 5 packets before/after retransmissions
   ```python
   CONTEXT_WINDOW = 5

   retrans_idx = packet["index"]
   context_packets = packets[retrans_idx - CONTEXT_WINDOW : retrans_idx + CONTEXT_WINDOW]
   ```

---

## Deployment Checklist

### Pre-Deployment
- [ ] All CSS inlined (no external files)
- [ ] UTF-8 encoding for emoji support
- [ ] WCAG 2.1 AA compliance validated
- [ ] Browser testing (Chrome, Firefox, Safari, Edge)
- [ ] Mobile testing (iOS, Android)
- [ ] Print testing (B&W printer)

### Post-Deployment
- [ ] Monitor user feedback
- [ ] Track accessibility complaints
- [ ] Measure page load time (< 3 seconds target)
- [ ] Validate with real PCAP files (various sizes)

---

## Support & Resources

### Documentation
- **UX Design Spec:** `docs/UX_DESIGN_PACKET_TIMELINE.md`
- **Design System:** `docs/DESIGN_SYSTEM_REFERENCE.md`
- **CSS Stylesheet:** `docs/packet-timeline-styles.css`
- **HTML Demo:** `docs/packet-timeline-mockup.html`

### Testing Tools
- **WCAG Contrast Checker:** https://webaim.org/resources/contrastchecker/
- **axe DevTools:** https://www.deque.com/axe/devtools/
- **WAVE:** https://wave.webaim.org/
- **Lighthouse:** Built into Chrome DevTools

### References
- **WCAG 2.1 Guidelines:** https://www.w3.org/WAI/WCAG21/quickref/
- **MDN Accessibility:** https://developer.mozilla.org/en-US/docs/Web/Accessibility
- **TCP RFC 793:** https://www.rfc-editor.org/rfc/rfc793

---

**Questions?** Review the design documentation or refer to the HTML mockup for working examples.

**End of Implementation Guide**
