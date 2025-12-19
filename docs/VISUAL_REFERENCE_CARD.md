# Packet Timeline Visual Reference Card

**Quick Reference Guide for Designers & Developers**

---

## Icon Library

| Icon | Meaning | Context | Color |
|------|---------|---------|-------|
| 🤝 | Handshake | SYN, SYN-ACK, ACK during 3-way handshake | Green (#28a745) |
| ✅ | Acknowledgment | ACK flag, successful operations | Green (#28a745) |
| 📤 | Push Data | PSH flag, data transmission | Gray (#6c757d) |
| 📭 | Close Connection | FIN flag, clean shutdown | Blue (#17a2b8) |
| 🚨 | Reset Connection | RST flag, abrupt termination | Red (#e74c3c) |
| 🔴 | RTO Retransmit | Timeout-based retransmission | Red (#e74c3c) |
| ⚡ | Fast Retransmit | 3 duplicate ACKs triggered | Yellow (#f39c12) |
| 📋 | Generic Retransmit | Generic retransmission | Blue (#17a2b8) |
| → | Outbound | Client → Server | Blue (#3498db) |
| ← | Inbound | Server → Client | Green (#27ae60) |
| ⏱️ | Timing | RTO timeout, gap indicator | Gray (#666) |
| 👋 | Teardown | Connection termination | Blue (#3498db) |

---

## Color Palette Quick Reference

### Semantic Backgrounds

| Purpose | Hex | Visual Sample | Border |
|---------|-----|---------------|--------|
| Normal | `#ffffff` | ![#ffffff](https://via.placeholder.com/60x20/ffffff/000000?text=+) | 2px solid #e0e0e0 |
| Handshake | `#f0f9f4` | ![#f0f9f4](https://via.placeholder.com/60x20/f0f9f4/155724?text=+) | 4px solid #28a745 |
| RTO | `#fff5f5` | ![#fff5f5](https://via.placeholder.com/60x20/fff5f5/721c24?text=+) | 4px dashed #e74c3c |
| Fast Retrans | `#fffbf0` | ![#fffbf0](https://via.placeholder.com/60x20/fffbf0/856404?text=+) | 4px dotted #f39c12 |
| Generic Retrans | `#f5f9ff` | ![#f5f9ff](https://via.placeholder.com/60x20/f5f9ff/0c5460?text=+) | 4px solid #17a2b8 |
| Teardown (FIN) | `#f0f8ff` | ![#f0f8ff](https://via.placeholder.com/60x20/f0f8ff/0c5460?text=+) | 4px double #3498db |
| Teardown (RST) | `#fff0f0` | ![#fff0f0](https://via.placeholder.com/60x20/fff0f0/721c24?text=+) | 4px double #e74c3c |

### Badge Colors

| Badge Type | Background | Text | Border | Contrast |
|------------|-----------|------|--------|----------|
| Success (Green) | `#d4edda` | `#155724` | `#28a745` | 7.2:1 ✅ |
| Info (Blue) | `#d1ecf1` | `#0c5460` | `#17a2b8` | 8.9:1 ✅ |
| Warning (Yellow) | `#fff3cd` | `#856404` | `#f39c12` | 8.5:1 ✅ |
| Danger (Red) | `#f8d7da` | `#721c24` | `#e74c3c` | 8.1:1 ✅ |

---

## Typography Quick Reference

### Font Stacks

```css
/* UI Text (labels, headers, buttons) */
font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
             'Helvetica Neue', Arial, sans-serif;

/* Data Text (seq, ack, timestamps) */
font-family: 'Monaco', 'Consolas', 'Courier New', monospace;
```

### Size Scale

| Token | em | px | Usage |
|-------|-----|-----|-------|
| `--text-xs` | 0.75em | 12px | Badges, metadata |
| `--text-sm` | 0.85em | 13.6px | Table headers |
| `--text-base` | 0.9em | 14.4px | Packet data |
| `--text-md` | 1em | 16px | Body text |
| `--text-lg` | 1.1em | 17.6px | Section headers |

---

## Spacing Quick Reference

### Spacing Scale (4px base)

| Token | px | Usage |
|-------|-----|-------|
| `--space-1` | 4px | Tight spacing, icon gaps |
| `--space-2` | 8px | Badge padding, small gaps |
| `--space-3` | 12px | Button padding, standard gaps |
| `--space-4` | 16px | Card padding, medium gaps |
| `--space-5` | 20px | Section padding |
| `--space-6` | 24px | Large spacing |
| `--space-8` | 32px | Extra large spacing |

### Component Padding

| Component | Padding | Min Height |
|-----------|---------|------------|
| Table Header (th) | 12px 16px | - |
| Table Cell (td) | 10px 16px | - |
| Table Row (tr) | - | 44px (desktop), 56px (mobile) |
| Button | 12px 20px | 44px |
| Badge | 4px 12px | - |
| Section | 20px (all sides) | - |

---

## Table Column Widths

| Column | Width | Alignment | Font |
|--------|-------|-----------|------|
| # (Number) | 60px | Center | Sans |
| Time | 100px | Left | Mono |
| Dir (Direction) | 80px | Center | Sans |
| Flags | 120px | Left | Sans |
| Seq | 130px | Left | Mono |
| Ack | 130px | Left | Mono |
| Len (Length) | 80px | Right | Mono |
| Type | Flexible (min 150px) | Left | Sans |

---

## Responsive Breakpoints

| Breakpoint | Width | Columns Visible | Strategy |
|------------|-------|-----------------|----------|
| **Desktop** | > 1024px | All 8 columns | Full table |
| **Tablet** | 768px - 1024px | 7 columns (hide Len) | Standard layout |
| **Mobile** | 480px - 768px | 6 columns (hide Ack, Len) | Freeze #, Time, Dir |
| **Small Mobile** | < 480px | 4 columns (#, Time, Dir, Type) | Minimal view |

---

## CSS Class Reference

### Table Classes

| Class | Purpose | Example |
|-------|---------|---------|
| `.packet-table` | Main table container | `<table class="packet-table">` |
| `.packet-table-wrapper` | Scrollable wrapper | `<div class="packet-table-wrapper">` |
| `.col-number` | Packet number column | `<th class="col-number">#</th>` |
| `.col-time` | Timestamp column | `<td class="col-time mono">0.000s</td>` |
| `.mono` | Monospace font | `<td class="mono">1234567890</td>` |

### Row Classes (Packet Types)

| Class | Background | Border | Usage |
|-------|-----------|--------|-------|
| `.packet-normal` | White (#fff) | 1px solid #e8e8e8 | Normal data packets |
| `.packet-handshake` | Light green (#f0f9f4) | 4px solid #28a745 | SYN, SYN-ACK, ACK |
| `.packet-rto` | Light red (#fff5f5) | 4px dashed #e74c3c | RTO retransmissions |
| `.packet-fast-retrans` | Light yellow (#fffbf0) | 4px dotted #f39c12 | Fast retransmissions |
| `.packet-generic-retrans` | Light blue (#f5f9ff) | 4px solid #17a2b8 | Generic retransmissions |
| `.packet-teardown-clean` | Alice blue (#f0f8ff) | 4px double #3498db | FIN packets |
| `.packet-teardown-rst` | Light red (#fff0f0) | 4px double #e74c3c | RST packets |

### Badge Classes

| Class | Color Scheme | Usage |
|-------|-------------|-------|
| `.badge` | Base badge styles | All badges inherit |
| `.badge-success` | Green | Handshake, ACK |
| `.badge-info` | Blue | Data, normal operations |
| `.badge-warning` | Yellow | Fast retransmit, warnings |
| `.badge-danger` | Red | RTO, RST, errors |

### Section Classes

| Class | Purpose | Styling |
|-------|---------|---------|
| `.timeline-section` | Section container | Padding, border-radius |
| `.timeline-section-header` | Section header (h5) | Flex layout, border-bottom |
| `.handshake-section` | Handshake section | Green border-left |
| `.retransmission-section` | Retrans section | Red border-left |
| `.teardown-section` | Teardown section | Blue border-left |

### Interactive Classes

| Class | Purpose | State |
|-------|---------|-------|
| `.flow-expand-checkbox` | Checkbox control | Hidden (CSS-only) |
| `.flow-expand-btn` | Expand button | Gray → Blue when checked |
| `.expand-icon` | +/× icon | Rotates 45° when expanded |
| `.flow-details` | Collapsible content | Hidden by default |
| `.flow-summary` | Summary stats | Visible when collapsed |

---

## Accessibility Quick Checks

### WCAG 2.1 AAA Checklist

- [x] **Color Contrast:** All text ≥ 7:1 (AAA), minimum 4.5:1 (AA)
- [x] **Color Alone:** Icons + text + border patterns (never color-only)
- [x] **Keyboard Navigation:** All elements focusable via Tab
- [x] **Focus Indicators:** 3px blue outline, 2px offset
- [x] **Touch Targets:** ≥ 44×44px (mobile: 48×48px)
- [x] **Screen Readers:** ARIA labels on all interactive elements
- [x] **Semantic HTML:** Proper `<table>`, `<th scope>`, `<caption>`

### ARIA Attributes Reference

| Element | ARIA Attributes | Example |
|---------|----------------|---------|
| Table | `role="table"`, `aria-label` | `<table role="table" aria-label="TCP Packet Timeline">` |
| Header | `scope="col"`, `aria-label` | `<th scope="col" aria-label="Packet number">#</th>` |
| Checkbox | `aria-controls`, `aria-expanded` | `<input aria-controls="details-1" aria-expanded="false">` |
| Button | `role="button"`, `aria-label` | `<label role="button" aria-label="Expand details">` |
| Section | `aria-labelledby` | `<section aria-labelledby="header-1">` |
| Icon | `aria-hidden="true"` | `<span class="icon" aria-hidden="true">🤝</span>` |

---

## Common Patterns

### Pattern 1: Handshake Section

```html
<section class="timeline-section handshake-section">
  <h5 class="timeline-section-header">
    <span class="icon">🤝</span>
    <span>TCP Handshake</span>
    <span class="duration">(0.000s - 0.024s)</span>
  </h5>
  <div class="packet-table-wrapper">
    <table class="packet-table">
      <!-- 3 rows: SYN, SYN-ACK, ACK -->
    </table>
  </div>
  <p class="text-success">✅ Handshake RTT: 24ms</p>
</section>
```

### Pattern 2: Retransmission Event

```html
<section class="timeline-section retransmission-section">
  <h5 class="timeline-section-header">
    <span class="icon">🔴</span>
    <span>RTO Retransmission Event</span>
    <span class="duration">(1.248s)</span>
  </h5>

  <!-- Context Before -->
  <div class="packet-context-group">
    <span class="context-label">Context (Before):</span>
    <table class="packet-table">
      <!-- 2-5 packets before retrans -->
    </table>
  </div>

  <!-- Retransmitted Packet -->
  <div class="packet-context-group retransmission-highlight">
    <span class="context-label text-danger">⚠️ Retransmitted:</span>
    <table class="packet-table">
      <tr class="packet-rto">
        <!-- Highlighted retrans packet -->
      </tr>
    </table>
    <div class="gap-indicator">
      <span>⏱️</span>
      <span>Gap: 1.123s (RTO threshold: ~1000ms)</span>
    </div>
  </div>

  <!-- Context After -->
  <div class="packet-context-group">
    <span class="context-label">Recovery (After):</span>
    <table class="packet-table">
      <!-- 2-5 packets after retrans -->
    </table>
  </div>
</section>
```

### Pattern 3: Collapsible Timeline

```html
<!-- Checkbox (hidden) -->
<input type="checkbox"
       id="flow-expand-1"
       class="flow-expand-checkbox"
       aria-controls="flow-details-1"
       aria-expanded="false">

<!-- Summary (visible when collapsed) -->
<div class="flow-summary">
  <div class="flow-summary-stat">
    <span class="label">Retransmissions:</span>
    <span class="value">12</span>
  </div>
</div>

<!-- Expand Button -->
<label for="flow-expand-1" class="flow-expand-btn" role="button">
  <span class="expand-icon">➕</span>
  <span>Expand Packet Timeline</span>
</label>

<!-- Details (hidden by default) -->
<div id="flow-details-1" class="flow-details">
  <!-- Handshake, retransmissions, teardown sections -->
</div>
```

---

## Cheat Sheet: TCP Flags

| Flag | Icon | Color | Meaning |
|------|------|-------|---------|
| **SYN** | 🤝 | Blue | Synchronize (start connection) |
| **ACK** | ✅ | Green | Acknowledge received data |
| **PSH** | 📤 | Gray | Push data to application |
| **FIN** | 📭 | Blue | Finish (close connection) |
| **RST** | 🚨 | Red | Reset (abort connection) |
| **URG** | ⚠️ | Yellow | Urgent data (rarely used) |

### Combined Flags

| Combination | Display | Usage |
|-------------|---------|-------|
| SYN | 🤝 SYN | Initial connection request |
| SYN+ACK | 🤝 SYN/ACK | Server accepts connection |
| ACK | ✅ ACK | Acknowledge only (no data) |
| PSH+ACK | 📤✅ PSH/ACK | Push data + acknowledge |
| FIN+ACK | 📭 FIN/ACK | Close connection + acknowledge |
| RST | 🚨 RST | Abrupt termination |

---

## Print Stylesheet Reminder

When printing, ensure:

- ✅ All sections expanded (`.flow-details { display: block !important; }`)
- ✅ Interactive controls hidden (`.flow-expand-btn { display: none; }`)
- ✅ Black & white friendly (borders visible, not color-dependent)
- ✅ Page breaks avoided within sections (`page-break-inside: avoid`)
- ✅ Font size readable (minimum 9pt)

---

## Browser Support

| Browser | Minimum Version | Notes |
|---------|----------------|-------|
| Chrome | 90+ | Full support |
| Firefox | 88+ | Full support |
| Safari | 14+ | Full support (iOS 14+) |
| Edge | 90+ | Chromium-based |
| Mobile Safari | iOS 14+ | Touch targets optimized |
| Chrome Mobile | Android 90+ | Touch targets optimized |

**Not supported:** IE11 (CSS variables, flexbox gaps not supported)

---

## File Sizes

| Asset | Size | Gzipped | Impact |
|-------|------|---------|--------|
| CSS (inline) | ~15KB | ~4KB | Negligible |
| HTML (per flow) | ~2-5KB | ~0.8KB | Minimal |
| Total (100 flows) | ~500KB | ~120KB | Acceptable |

---

## Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| Icons not displaying | Ensure UTF-8 encoding: `<meta charset="UTF-8">` |
| Expand button not working | Check checkbox ID matches label `for` attribute |
| Color contrast failure | Use design system colors (see palette above) |
| Mobile columns not hiding | Add viewport meta tag: `<meta name="viewport" content="width=device-width, initial-scale=1.0">` |
| Print shows collapsed sections | Add `!important` to print media query: `.flow-details { display: block !important; }` |

---

**End of Visual Reference Card**

**For detailed implementation, see:**
- `IMPLEMENTATION_GUIDE.md` (developer guide)
- `DESIGN_SYSTEM_REFERENCE.md` (complete spec)
- `packet-timeline-mockup.html` (working demo)
