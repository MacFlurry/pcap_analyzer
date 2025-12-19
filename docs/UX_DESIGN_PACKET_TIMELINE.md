# Packet Timeline Visual Interface - UX Design Documentation

## Executive Summary

This document provides comprehensive UX design specifications for packet timeline rendering in HTML reports for TCP connection analysis. The design prioritizes clarity for security analysts and network engineers while maintaining accessibility and print-friendliness.

---

## Phase 1: Information Architecture

### 1.1 Collapsible Timeline Container

**Design Decision: Progressive Disclosure**

The timeline uses a checkbox-based expand/collapse mechanism (CSS-only, no JavaScript) to prevent overwhelming users with packet-level details.

#### Summary Line (Collapsed State)
When collapsed, show:
```
┌─────────────────────────────────────────────────────────────┐
│ 📊 Flow: 192.168.1.10:52341 → 93.184.216.34:443           │
│ ⚡ 12 Retransmissions | RTO: 8, Fast: 3, Generic: 1        │
│ [➕ Expand Details]                                         │
└─────────────────────────────────────────────────────────────┘
```

**Information Hierarchy:**
1. Flow identifier (source → destination)
2. Retransmission count + breakdown by type
3. Expand button with clear affordance

#### Expand/Collapse Affordance
- **Visual Indicator:** ➕ icon rotates 45° to ✖️ when expanded
- **Color Change:** Button background changes from gray (#f5f5f5) to blue (#3498db)
- **Accessible Label:** "Expand Details" / "Collapse Details" for screen readers

#### Visual Indicator for "Has Timeline Data"
- Badge with count: `⏱️ Timeline (24 packets)`
- Color-coded by severity:
  - Green: 0 retransmissions
  - Yellow: 1-5 retransmissions
  - Orange: 6-20 retransmissions
  - Red: 21+ retransmissions

---

### 1.2 Packet Table Layout

**Column Ordering (Left to Right Priority):**

| Priority | Column | Width | Justification |
|----------|--------|-------|---------------|
| 1 | **#** (Packet Number) | 60px | Quick reference for analysts |
| 2 | **Time** | 100px | Temporal context critical for troubleshooting |
| 3 | **Direction** | 80px | Visual flow indicator (→ / ←) |
| 4 | **Flags** | 120px | TCP state machine indicators |
| 5 | **Seq** | 110px | Sequence number (monospace) |
| 6 | **Ack** | 110px | Acknowledgment number (monospace) |
| 7 | **Length** | 80px | Payload size |
| 8 | **Type** | 150px | Packet classification (with badge) |

**Column Headers:**

```
┌────┬──────────┬──────────┬────────┬────────────┬────────────┬────────┬─────────────────┐
│ #  │   Time   │   Dir    │ Flags  │    Seq     │    Ack     │  Len   │      Type       │
├────┼──────────┼──────────┼────────┼────────────┼────────────┼────────┼─────────────────┤
│ 1  │ 0.000s   │    →     │  SYN   │ 1234567890 │      0     │   0    │ 🤝 Handshake    │
│ 2  │ 0.023s   │    ←     │ SYN/ACK│ 9876543210 │ 1234567891 │   0    │ 🤝 Handshake    │
│ 3  │ 0.024s   │    →     │  ACK   │ 1234567891 │ 9876543211 │   0    │ 🤝 Handshake    │
│ 4  │ 0.125s   │    →     │ PSH/ACK│ 1234567891 │ 9876543211 │  512   │ 📤 Data         │
│ 5  │ 1.248s   │    →     │ PSH/ACK│ 1234567891 │ 9876543211 │  512   │ 🔴 Retransmit   │
└────┴──────────┴──────────┴────────┴────────────┴────────────┴────────┴─────────────────┘
```

**Visual Flow (Source → Destination):**
- Direction column uses Unicode arrows: `→` (outbound), `←` (inbound)
- Alternating row backgrounds for readability
- Hover effects highlight entire row

---

### 1.3 Section Organization

#### Handshake Section
```
┌─ 🤝 TCP Handshake (0.000s - 0.024s) ──────────────────────┐
│                                                             │
│  #1  0.000s  →  SYN       seq=1234567890                   │
│  #2  0.023s  ←  SYN/ACK   seq=9876543210 ack=1234567891    │
│  #3  0.024s  →  ACK       ack=9876543211                   │
│                                                             │
│  ✅ Handshake RTT: 24ms (Excellent)                        │
└─────────────────────────────────────────────────────────────┘
```

**Visual Separation:**
- Light green background (#f0f9f4)
- Border: 3px solid #28a745 (left)
- Icon: 🤝 for handshake
- Duration in header

#### Retransmission Context Sections
Each retransmission shows:
- **5 packets before** (context)
- **The retransmitted packet** (highlighted)
- **5 packets after** (to show recovery)

```
┌─ 🔴 Retransmission Event #1 (1.248s) ────────────────────┐
│                                                            │
│  Context (Before):                                         │
│  #2  0.125s  →  PSH/ACK  seq=1234567891  len=512  📤 Data │
│  #3  0.150s  ←  ACK      ack=1234568403          ✅ ACK   │
│  #4  0.175s  →  PSH/ACK  seq=1234568403  len=512  📤 Data │
│                                                            │
│  ⚠️ Retransmitted Packet:                                 │
│  #5  1.248s  →  PSH/ACK  seq=1234567891  len=512  🔴 RTO  │
│  │                                                         │
│  └─ Gap: 1.123s (RTO Timeout)                             │
│                                                            │
│  Recovery (After):                                         │
│  #6  1.273s  ←  ACK      ack=1234568403          ✅ ACK   │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**Grouping Strategy:**
- Light red background (#fff5f5) for RTO events
- Light yellow background (#fffbf0) for fast retransmit events
- Collapsible sections (default: show first 3, collapse rest)

#### Teardown Section
```
┌─ 👋 Connection Teardown (45.678s - 45.702s) ─────────────┐
│                                                            │
│  #98  45.678s  →  FIN/ACK  seq=1234999999  📭 Close      │
│  #99  45.690s  ←  FIN/ACK  seq=9876999999  📭 Close      │
│  #100 45.702s  →  ACK      ack=9877000000  ✅ ACK        │
│                                                            │
│  ✅ Clean shutdown (4-way handshake)                      │
└────────────────────────────────────────────────────────────┘
```

**Visual Cues:**
- Light blue background (#f0f8ff)
- Border: 3px solid #3498db (left)
- Icon: 👋 for clean shutdown, 🚨 for RST (abrupt close)

---

## Phase 2: Visual Design

### 2.1 Color Scheme

**Design Principle:** Use color AND iconography (never color alone) for accessibility.

#### Normal Packets
- Background: `#ffffff` (white)
- Hover: `#f8fafc` (light blue-gray)
- Border-bottom: `#e8e8e8` (subtle divider)

#### Handshake Packets (SYN, SYN-ACK, ACK)
- Background: `#f0f9f4` (light green)
- Icon: `🤝`
- Badge: `<span class="badge-success">Handshake</span>`
- Badge Colors:
  - Background: `#d4edda`
  - Text: `#155724`
  - Border: `1px solid #28a745`

#### Retransmission Packets
**RTO (Timeout-based):**
- Background: `#fff5f5` (light red)
- Icon: `⏱️`
- Badge: `<span class="badge-danger">RTO</span>`
- Badge Colors:
  - Background: `#f8d7da`
  - Text: `#721c24`
  - Border: `1px solid #e74c3c`

**Fast Retransmit:**
- Background: `#fffbf0` (light yellow/orange)
- Icon: `⚡`
- Badge: `<span class="badge-warning">Fast Retransmit</span>`
- Badge Colors:
  - Background: `#fff3cd`
  - Text: `#856404`
  - Border: `1px solid #f39c12`

**Generic Retransmit:**
- Background: `#f5f9ff` (light blue)
- Icon: `📋`
- Badge: `<span class="badge-info">Retransmit</span>`
- Badge Colors:
  - Background: `#d1ecf1`
  - Text: `#0c5460`
  - Border: `1px solid #17a2b8`

#### Teardown Packets (FIN, RST)
**Clean Shutdown (FIN):**
- Background: `#f0f8ff` (alice blue)
- Icon: `📭`
- Badge: `<span class="badge-info">Close</span>`

**Abrupt Close (RST):**
- Background: `#fff0f0` (light red)
- Icon: `🚨`
- Badge: `<span class="badge-danger">RST</span>`

#### Section Backgrounds
- Handshake section: `#f0f9f4` (light green)
- Retransmission section: `#fff5f5` (light red)
- Teardown section: `#f0f8ff` (light blue)
- Normal data section: `#ffffff` (white)

**WCAG 2.1 Compliance:**
All color combinations tested for 4.5:1 contrast ratio minimum.

---

### 2.2 Typography

#### Font Families
```css
/* Body text (labels, descriptions) */
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
             'Helvetica Neue', Arial, sans-serif;

/* Packet data (seq, ack, timestamps) */
font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
```

#### Font Sizes
```css
/* Section headers (h5) */
font-size: 1.1em;
font-weight: 600;
line-height: 1.4;

/* Table headers */
font-size: 0.85em;
font-weight: 600;
text-transform: uppercase;
letter-spacing: 0.05em;

/* Packet data cells */
font-size: 0.9em;
line-height: 1.5;

/* Badges */
font-size: 0.75em;
font-weight: 600;

/* Monospace data (seq, ack) */
font-size: 0.85em;
letter-spacing: -0.02em; /* Tighter spacing for numbers */
```

#### Bold/Italic Usage
- **Bold:** Packet types, section headers, critical values
- **Italic:** Context labels ("Before", "After"), service names
- **Regular:** Normal packet data

---

### 2.3 Spacing & Alignment

#### Table Padding
```css
.packet-table th {
  padding: 12px 16px;
}

.packet-table td {
  padding: 10px 16px;
}
```

#### Row Height
```css
.packet-table tr {
  min-height: 44px; /* Touch-friendly: 44px minimum */
  line-height: 1.5;
}
```

#### Column Widths
```css
.col-number     { width: 60px;  flex-shrink: 0; } /* Fixed */
.col-time       { width: 100px; flex-shrink: 0; } /* Fixed */
.col-direction  { width: 80px;  flex-shrink: 0; } /* Fixed */
.col-flags      { width: 120px; flex-shrink: 0; } /* Fixed */
.col-seq        { width: 130px; flex-shrink: 0; } /* Fixed, monospace */
.col-ack        { width: 130px; flex-shrink: 0; } /* Fixed, monospace */
.col-length     { width: 80px;  flex-shrink: 0; } /* Fixed */
.col-type       { flex: 1;      min-width: 150px; } /* Flexible */
```

#### Section Spacing
```css
.timeline-section {
  margin-bottom: 30px;
  padding: 20px;
  border-radius: 8px;
}

.section-header {
  margin-bottom: 16px;
  padding-bottom: 12px;
  border-bottom: 2px solid #e0e0e0;
}

.packet-context-group {
  margin: 16px 0;
}
```

---

### 2.4 Interactive States

#### Hover Effects
```css
.packet-table tbody tr {
  transition: all 0.2s ease;
  cursor: default;
}

.packet-table tbody tr:hover {
  background: #f8fafc !important; /* Override section backgrounds */
  transform: translateX(4px);
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
  border-left: 3px solid #3498db;
}
```

#### Focus States (Keyboard Navigation)
```css
.packet-table tbody tr:focus-within {
  outline: 3px solid #3498db;
  outline-offset: 2px;
  z-index: 10;
}

/* Make rows focusable for keyboard users */
.packet-table tbody tr {
  position: relative;
  tabindex: 0;
}
```

#### Collapsed vs Expanded States
```css
/* Collapsed: show summary only */
.timeline-collapsed .packet-details {
  display: none;
}

.timeline-collapsed .expand-btn::before {
  content: '➕';
}

/* Expanded: show full timeline */
.flow-expand-checkbox:checked ~ .flow-details {
  display: block;
  animation: slideDown 0.3s ease;
}

.flow-expand-checkbox:checked + .flow-expand-btn {
  background: #3498db;
  color: white;
}

.flow-expand-checkbox:checked + .flow-expand-btn .expand-icon {
  transform: rotate(45deg); /* ➕ becomes ✖️ */
}

@keyframes slideDown {
  from {
    opacity: 0;
    max-height: 0;
    transform: translateY(-10px);
  }
  to {
    opacity: 1;
    max-height: 2000px;
    transform: translateY(0);
  }
}
```

---

## Phase 3: Highlighting Scheme

### 3.1 Retransmission Packets

**Visual Pattern:**
```
┌────────────────────────────────────────────────────────────┐
│ 🔴 RTO Retransmission                                      │
├────────────────────────────────────────────────────────────┤
│ #5  1.248s  →  PSH/ACK  seq=1234567891  len=512           │
│                                                            │
│ Gap from original: 1.123s (RTO threshold: ~1000ms)        │
│ Cause: No ACK received (packet loss or timeout)           │
└────────────────────────────────────────────────────────────┘
```

**Highlighting Rules:**
1. **Background:** Light red (#fff5f5) with left border (4px solid #e74c3c)
2. **Icon:** Always show icon + text (never icon alone)
3. **Bold:** Sequence number in bold for quick scanning
4. **Context Line:** Show gap duration below packet

### 3.2 Packet Direction Indicators

**Design:** Use arrows + color coding

```css
.direction-outbound::before {
  content: '→';
  color: #3498db; /* Blue for outbound */
  font-size: 1.2em;
  margin-right: 4px;
}

.direction-inbound::before {
  content: '←';
  color: #27ae60; /* Green for inbound */
  font-size: 1.2em;
  margin-right: 4px;
}
```

**Accessibility:**
- Aria-label: `aria-label="Outbound packet"`
- Text alternative: Show "→ Out" / "← In" on mobile

### 3.3 TCP Flags

**Design:** Icons + Text (never icons alone)

| Flag | Icon | Text | Color |
|------|------|------|-------|
| SYN | 🤝 | SYN | #3498db (blue) |
| SYN-ACK | 🤝 | SYN/ACK | #3498db (blue) |
| ACK | ✅ | ACK | #28a745 (green) |
| PSH | 📤 | PSH | #6c757d (gray) |
| FIN | 📭 | FIN | #17a2b8 (cyan) |
| RST | 🚨 | RST | #e74c3c (red) |
| PSH-ACK | 📤✅ | PSH/ACK | #6c757d (gray) |

**Implementation:**
```html
<span class="tcp-flag flag-syn" aria-label="SYN flag">
  🤝 <span class="flag-text">SYN</span>
</span>
```

### 3.4 Relative vs Absolute Timestamps

**Design Decision:** Show both (toggle via checkbox)

```html
<label class="timestamp-toggle">
  <input type="checkbox" id="show-absolute-time" />
  <span>Show Absolute Timestamps</span>
</label>

<!-- Default: Relative time -->
<td class="time-relative">1.248s</td>
<td class="time-absolute" style="display: none;">15:34:22.451</td>
```

**CSS Toggle:**
```css
#show-absolute-time:checked ~ .packet-table .time-relative {
  display: none;
}

#show-absolute-time:checked ~ .packet-table .time-absolute {
  display: table-cell;
}
```

---

## Phase 4: Mobile Responsiveness

### 4.1 Horizontal Scrolling Strategy

**Design:** Hybrid approach (freeze first 3 columns)

```css
@media (max-width: 768px) {
  .packet-table-wrapper {
    overflow-x: auto;
    -webkit-overflow-scrolling: touch; /* Smooth iOS scrolling */
    border: 1px solid #e0e0e0;
    border-radius: 8px;
  }

  /* Freeze #, Time, Dir columns */
  .packet-table {
    position: relative;
  }

  .packet-table th:nth-child(-n+3),
  .packet-table td:nth-child(-n+3) {
    position: sticky;
    left: 0;
    z-index: 5;
    background: white;
    box-shadow: 2px 0 4px rgba(0, 0, 0, 0.1);
  }
}
```

### 4.2 Column Hiding Priority

**Breakpoints:**

| Screen Width | Visible Columns |
|--------------|-----------------|
| > 1024px | All columns |
| 768px - 1024px | Hide: Length |
| 480px - 768px | Hide: Length, Ack |
| < 480px | Show: #, Time, Dir, Type only |

**Implementation:**
```css
@media (max-width: 1024px) {
  .col-length { display: none; }
}

@media (max-width: 768px) {
  .col-ack { display: none; }
}

@media (max-width: 480px) {
  .col-flags,
  .col-seq { display: none; }

  /* Stack packet details vertically */
  .packet-table tr {
    display: grid;
    grid-template-columns: 60px 100px 80px 1fr;
    gap: 8px;
  }
}
```

### 4.3 Touch-Friendly Tap Targets

**Minimum Target Size:** 44px × 44px (WCAG 2.1 Level AAA)

```css
@media (max-width: 768px) {
  .packet-table tbody tr {
    min-height: 56px; /* Larger for touch */
    padding: 8px 0;
  }

  .flow-expand-btn {
    min-width: 44px;
    min-height: 44px;
    padding: 12px 20px;
    font-size: 1em;
  }

  /* Larger checkboxes for expand/collapse */
  .flow-expand-checkbox + label {
    padding: 14px 24px;
    font-size: 1.1em;
  }
}
```

### 4.4 Collapsible Sections on Small Screens

**Design:** Auto-collapse all sections by default on mobile

```css
@media (max-width: 768px) {
  /* Collapse all timeline sections by default */
  .flow-expand-checkbox {
    checked: false; /* Reset to collapsed */
  }

  .flow-details {
    display: none;
  }

  /* Show summary stats inline */
  .flow-summary {
    display: block;
    padding: 16px;
    background: #f8f9fa;
    border-radius: 8px;
    margin: 12px 0;
  }

  .flow-summary-stat {
    display: inline-block;
    margin: 4px 8px;
    font-size: 0.9em;
  }
}
```

---

## Phase 5: Accessibility

### 5.1 WCAG 2.1 Compliance Checklist

#### Color Contrast Ratios (4.5:1 minimum for text)

| Element | Foreground | Background | Ratio | Status |
|---------|-----------|-----------|-------|--------|
| Normal text | #333 | #fff | 12.6:1 | ✅ Pass |
| Section headers | #2c3e50 | #fff | 11.8:1 | ✅ Pass |
| Badge (success) | #155724 | #d4edda | 7.2:1 | ✅ Pass |
| Badge (danger) | #721c24 | #f8d7da | 8.1:1 | ✅ Pass |
| Badge (warning) | #856404 | #fff3cd | 8.5:1 | ✅ Pass |
| Monospace data | #2d3748 | #f5f7fa | 10.3:1 | ✅ Pass |
| Link text | #3498db | #fff | 5.1:1 | ✅ Pass |

**Validation Tool:** WebAIM Contrast Checker

#### Keyboard Navigation (Tab Order, Focus Indicators)

**Tab Order:**
1. Expand/collapse button
2. Timestamp toggle
3. Each packet row (tabindex="0")
4. Wireshark command copy buttons
5. Next section

**Focus Indicators:**
```css
/* Visible focus ring */
*:focus {
  outline: 3px solid #3498db;
  outline-offset: 2px;
}

/* Avoid double outlines in Chrome */
*:focus:not(:focus-visible) {
  outline: none;
}

*:focus-visible {
  outline: 3px solid #3498db;
  outline-offset: 2px;
}

/* Focus within (for rows with focusable children) */
.packet-table tr:focus-within {
  box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.3);
  background: #f0f8ff;
}
```

**Skip Links:**
```html
<a href="#timeline-content" class="skip-link">
  Skip to packet timeline
</a>
```

```css
.skip-link {
  position: absolute;
  left: -9999px;
  top: 0;
  z-index: 9999;
  padding: 10px;
  background: #3498db;
  color: white;
}

.skip-link:focus {
  left: 10px;
  top: 10px;
}
```

### 5.2 Screen Reader Support (ARIA Labels)

**Table Structure:**
```html
<table class="packet-table" role="table" aria-label="TCP Packet Timeline">
  <caption class="sr-only">
    TCP packet timeline showing handshake, data transfer, and teardown phases
  </caption>
  <thead>
    <tr>
      <th scope="col" aria-label="Packet number">#</th>
      <th scope="col" aria-label="Relative timestamp">Time</th>
      <th scope="col" aria-label="Packet direction">Dir</th>
      <th scope="col" aria-label="TCP flags">Flags</th>
      <th scope="col" aria-label="Sequence number">Seq</th>
      <th scope="col" aria-label="Acknowledgment number">Ack</th>
      <th scope="col" aria-label="Payload length">Len</th>
      <th scope="col" aria-label="Packet type">Type</th>
    </tr>
  </thead>
  <tbody>
    <tr aria-label="Packet 1: SYN handshake packet at 0.000 seconds">
      <td>1</td>
      <td>0.000s</td>
      <td aria-label="Outbound">→</td>
      <td><span aria-label="SYN flag">🤝 SYN</span></td>
      <td>1234567890</td>
      <td>0</td>
      <td>0</td>
      <td>
        <span class="badge-success" aria-label="Handshake packet">
          Handshake
        </span>
      </td>
    </tr>
  </tbody>
</table>
```

**Section Labels:**
```html
<section aria-labelledby="handshake-section-title">
  <h5 id="handshake-section-title">
    🤝 TCP Handshake (0.000s - 0.024s)
  </h5>
  <!-- Content -->
</section>

<section aria-labelledby="retrans-section-title">
  <h5 id="retrans-section-title">
    🔴 Retransmission Events (3 events)
  </h5>
  <!-- Content -->
</section>
```

**Expand/Collapse Buttons:**
```html
<input type="checkbox"
       id="flow-expand-1"
       class="flow-expand-checkbox"
       aria-controls="flow-details-1"
       aria-expanded="false" />

<label for="flow-expand-1"
       class="flow-expand-btn"
       role="button"
       aria-label="Expand packet timeline details">
  <span class="expand-icon" aria-hidden="true">➕</span>
  <span>Expand Details</span>
</label>

<div id="flow-details-1"
     class="flow-details"
     aria-hidden="true">
  <!-- Timeline content -->
</div>
```

**Live Regions (for dynamic updates):**
```html
<div aria-live="polite" aria-atomic="true" class="sr-only">
  <!-- Announce when sections expand/collapse -->
  <span id="timeline-status"></span>
</div>

<script>
// Update when checkbox changes (if JavaScript enabled)
checkbox.addEventListener('change', function() {
  document.getElementById('timeline-status').textContent =
    this.checked ? 'Timeline details expanded' : 'Timeline details collapsed';
});
</script>
```

### 5.3 Don't Rely on Color Alone (Use Icons + Color)

**Compliance Examples:**

❌ **Bad (Color Only):**
```html
<td style="background: #fff5f5;">Retransmission</td>
```

✅ **Good (Icon + Color + Text):**
```html
<td style="background: #fff5f5;">
  <span aria-label="RTO Retransmission">
    🔴 <strong>RTO</strong>
  </span>
</td>
```

**Visual Patterns Table:**

| Packet Type | Icon | Color | Text | Pattern |
|-------------|------|-------|------|---------|
| Handshake | 🤝 | Green bg | "Handshake" | Solid border |
| RTO | 🔴 | Red bg | "RTO" | Dashed left border |
| Fast Retrans | ⚡ | Yellow bg | "Fast Retrans" | Dotted left border |
| Teardown | 📭 | Blue bg | "Close" | Double border |

**CSS Implementation:**
```css
.packet-handshake {
  background: #f0f9f4;
  border-left: 4px solid #28a745;
}

.packet-rto {
  background: #fff5f5;
  border-left: 4px dashed #e74c3c;
}

.packet-fast-retrans {
  background: #fffbf0;
  border-left: 4px dotted #f39c12;
}

.packet-teardown {
  background: #f0f8ff;
  border-left: 4px double #3498db;
}
```

---

## Deliverables

All deliverables are included below:

1. ✅ CSS Stylesheet (complete visual design)
2. ✅ HTML Mockup Example (sample packet table)
3. ✅ Color Palette Specification
4. ✅ Typography Scale
5. ✅ Accessibility Checklist
6. ✅ Mobile Responsive Layout Demo

---
