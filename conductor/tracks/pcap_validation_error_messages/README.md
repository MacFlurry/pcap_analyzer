# Track: PCAP Validation with User-Friendly Error Messages

## 📋 Quick Context

**Issue**: When uploading invalid/educational PCAPs (like "The Ultimate PCAP"), the app shows generic error "Erreur lors de l'analyse" with no explanation. Users don't understand WHY it failed.

**Solution**: Add pre-upload validation to detect incompatible PCAPs and show **clear, actionable error messages** explaining:
- What's wrong with the file
- Why PCAP Analyzer can't process it
- What the user should do instead (use Wireshark)

**Version**: v5.2.2 (PATCH - improved error handling)

---

## 🎯 Objectives

- Validate PCAP files BEFORE analysis (check timestamps, duplicates, sanity)
- Provide **specific, educational error messages** (not generic "error")
- Display errors in a **well-designed, integrated UI** (not just a corner toast)
- Guide users toward appropriate tools (Wireshark) when file is incompatible
- Maintain fast upload flow for valid PCAPs (minimal overhead)

---

## 🔍 Validation Checks to Implement

### 1. **Timestamp Sanity Check**
- Detect jumps > 1 year between consecutive packets
- Flag: "Invalid timestamps detected - appears to be synthetic/educational PCAP"

### 2. **Duplicate Packet Detection**
- Sample first 100-200 packets
- If > 50% duplicates → Flag: "High duplicate ratio detected - file may be corrupted or synthetic"

### 3. **Minimum Packet Count**
- Require at least 2 packets for latency analysis
- Flag: "Insufficient packets for analysis"

### 4. **Self-Looping Flows**
- Detect packets where source MAC/IP = destination MAC/IP
- Flag: "Invalid network flows detected (self-looping)"

### 5. **File Format Validation**
- Ensure it's actually a PCAP/PCAPNG file
- Flag: "Invalid file format - expected .pcap or .pcapng"

---

## 📁 Files to Modify

**Backend**:
- `app/services/analyzer.py` - Add `validate_pcap()` function
- `app/api/routes/upload.py` - Call validation before queuing analysis
- `app/models/schemas.py` - Add error response schema

**Frontend**:
- `app/templates/upload.html` - Replace generic error display
- Create new partial: `app/templates/components/error_message.html` - Reusable error component
- `app/static/js/upload.js` - Handle error display logic

**Tests**:
- `tests/unit/test_pcap_validation.py` - Unit tests for validation logic
- `tests/integration/test_upload_validation.py` - E2E upload with invalid PCAPs
- Add test fixtures: `tests/fixtures/invalid_pcaps/` with sample bad files

---

## 🎨 UI Design for Error Messages

**Current (mauvais)** :
```
[X] Erreur lors de l'analyse
```

**Proposed (bien intégré)** :

```html
┌──────────────────────────────────────────────────────────────┐
│  ⚠️  Fichier PCAP incompatible avec l'analyse de latence    │
│                                                              │
│  Problèmes détectés :                                        │
│  • Timestamps incohérents (sauts > 1 an)                    │
│  • Paquets dupliqués (ratio: 95%)                           │
│  • Flux réseau invalides (source = destination)             │
│                                                              │
│  💡 Ce fichier semble être un PCAP éducatif/synthétique.   │
│                                                              │
│  PCAP Analyzer analyse les captures réseau réelles pour     │
│  détecter les latences et problèmes de performance.         │
│                                                              │
│  Pour ce type de fichier, utilisez Wireshark :              │
│  [Télécharger Wireshark] [Documentation]                    │
│                                                              │
│  [Réessayer avec un autre fichier]                          │
└──────────────────────────────────────────────────────────────┘
```

**Style** :
- Background: `bg-red-50 dark:bg-red-900/20`
- Border: `border-l-4 border-red-500`
- Icon: `⚠️` large, couleur warning
- Buttons: Primary (Wireshark link), Secondary (Retry)
- Responsive: Full width sur mobile, max-width sur desktop

---

## 🔄 Version Synchronization

**This is a PATCH version bump: 5.2.1 → 5.2.2**

After completing implementation, you MUST synchronize:

1. **`src/__version__.py`**
   ```python
   __version__ = "5.2.2"
   ```

2. **`helm-chart/pcap-analyzer/Chart.yaml`**
   ```yaml
   version: 1.4.2
   appVersion: "5.2.2"
   ```

3. **`helm-chart/pcap-analyzer/values.yaml`**
   ```yaml
   image:
     tag: "v5.2.2"
   ```

4. **`CHANGELOG.md`**
   ```markdown
   ## [5.2.2] - YYYY-MM-DD

   ### Improved
   - **Error Handling**: Added pre-upload PCAP validation with detailed, user-friendly error messages
   - **UX**: Users now get clear explanations when uploading incompatible PCAPs (educational/synthetic files)
   - **Validation**: Detect timestamp anomalies, duplicate packets, and invalid network flows
   ```

---

## ✅ Implementation Checklist

- [ ] Add validation logic in `analyzer.py`
- [ ] Create error message component in `templates/components/`
- [ ] Update upload API to return structured error responses
- [ ] Implement frontend error display (replace generic alerts)
- [ ] Add unit tests for validation (100% coverage target)
- [ ] Add integration tests with invalid PCAP fixtures
- [ ] Test with "The Ultimate PCAP" file
- [ ] Synchronize version numbers (5.2.2)
- [ ] Update CHANGELOG.md
- [ ] Build Docker image v5.2.2
- [ ] Deploy to Kubernetes
- [ ] Manual testing (upload valid + invalid PCAPs)
- [ ] Archive this track

---

## 🧪 Testing Strategy

### Unit Tests (`test_pcap_validation.py`)
```python
def test_validate_timestamp_jumps():
    """Detect timestamps with > 1 year jumps"""

def test_validate_duplicate_packets():
    """Detect files with > 50% duplicates"""

def test_validate_minimum_packets():
    """Reject files with < 2 packets"""

def test_validate_self_looping_flows():
    """Detect source = destination flows"""
```

### Integration Tests (`test_upload_validation.py`)
```python
def test_upload_ultimate_pcap_rejects_with_message():
    """Upload 'The Ultimate PCAP' → Should reject with detailed message"""

def test_upload_valid_pcap_succeeds():
    """Upload normal PCAP → Should succeed"""

def test_upload_non_pcap_file_rejects():
    """Upload .txt file → Should reject"""
```

### Manual Testing
1. Upload "The Ultimate PCAP v20251206.pcapng" → Should show detailed error
2. Upload a normal PCAP → Should succeed normally
3. Upload a text file renamed to .pcap → Should reject
4. Upload a PCAP with < 2 packets → Should reject
5. Test dark mode rendering of error message

---

## 📝 Notes

- Keep validation **fast** (< 500ms for 14MB files)
- Sample only first 100-200 packets to check (don't load entire file)
- Use Scapy's `rdpcap(count=100)` for efficient sampling
- Error messages should be **bilingual-ready** (FR/EN) if i18n planned
- Link to Wireshark download: `https://www.wireshark.org/download.html`

---

**Track Status**: 🟢 Ready for Implementation
