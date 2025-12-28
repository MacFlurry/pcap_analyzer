# Track: tshark Backend Integration (v5.4.0)

**Status**: 🚧 In Progress
**Priority**: 🔴 High
**Version**: 5.4.0
**Created**: 2025-12-28

---

## 🎯 Objective

Implement hybrid tshark/builtin backend to achieve **100% retransmission detection accuracy** when tshark is available, with graceful fallback to builtin analyzer (85% accuracy).

---

## 📊 Current State (v5.3.0)

| Metric | Value | Status |
|--------|-------|--------|
| **Detection Method** | Built-in (Python) | ✅ |
| **Accuracy** | 85% recall | 🟡 |
| **Precision** | ~100% | 🟢 |
| **False Positives** | 0 | 🟢 |
| **False Negatives** | 4/27 (15%) | 🟡 |
| **Test PCAP** | c1.pcap: 23/27 detected | 🟡 |

**Limitation**: Misses retransmissions when original packet was lost before capture point.

---

## 🎯 Target State (v5.4.0)

| Metric | tshark Backend | builtin Backend |
|--------|----------------|-----------------|
| **Accuracy** | 100% (27/27) 🟢 | 85% (23/27) 🟡 |
| **Precision** | 100% | ~100% |
| **Detection** | Automatic | Fallback |
| **Docker/K8s** | Default ✅ | N/A |
| **CLI** | If installed | Always available |

---

## 🏗️ Architecture

### Path Detection Strategy

```python
def find_tshark() -> Optional[str]:
    """
    Find tshark binary with platform-specific logic.

    Returns:
        Full path to tshark or None if not found
    """
    import platform
    import shutil
    from pathlib import Path

    system = platform.system()

    # 1. macOS: Check Wireshark.app bundle
    if system == "Darwin":
        macos_path = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
        if macos_path.exists() and macos_path.is_file():
            return str(macos_path)

    # 2. Linux/Windows: Use shutil.which (checks PATH)
    tshark_in_path = shutil.which("tshark")
    if tshark_in_path:
        return tshark_in_path

    # 3. Common Linux paths
    if system == "Linux":
        linux_paths = [
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/wireshark/bin/tshark"
        ]
        for path in linux_paths:
            if Path(path).exists():
                return path

    return None
```

### Backend Selection Logic

```python
class RetransmissionAnalyzerFactory:
    @staticmethod
    def create(backend: str = "auto", pcap_path: str = None):
        """
        Factory to create retransmission analyzer.

        Args:
            backend: "auto", "tshark", or "builtin"
            pcap_path: Path to PCAP file

        Returns:
            Appropriate analyzer instance
        """
        if backend == "builtin":
            logger.info("Using built-in retransmission analyzer (may have 15% under-detection)")
            return BuiltinRetransmissionAnalyzer()

        if backend == "tshark" or backend == "auto":
            tshark_path = find_tshark()

            if tshark_path:
                logger.info(f"Using tshark backend for 100% accuracy: {tshark_path}")
                return TsharkRetransmissionAnalyzer(tshark_path)

            if backend == "tshark":
                raise RuntimeError(
                    "tshark backend requested but tshark not found. "
                    "Install Wireshark or use --retrans-backend builtin"
                )

            # Auto fallback
            logger.warning(
                "tshark not found, falling back to built-in analyzer. "
                "Install Wireshark for 100% accuracy. "
                "Detection accuracy: 85% (may miss 4-6 retransmissions per 27)"
            )
            return BuiltinRetransmissionAnalyzer()
```

### tshark Subprocess Call

```python
class TsharkRetransmissionAnalyzer:
    def __init__(self, tshark_path: str):
        self.tshark_path = tshark_path

    def analyze(self, pcap_path: str) -> List[TCPRetransmission]:
        """
        Analyze PCAP using tshark for retransmission detection.

        Returns:
            List of TCPRetransmission objects
        """
        import subprocess
        import json

        # tshark command to extract retransmissions as JSON
        cmd = [
            self.tshark_path,
            '-r', pcap_path,
            '-Y', 'tcp.analysis.retransmission',  # Filter retransmissions only
            '-T', 'json',
            '-e', 'frame.number',
            '-e', 'frame.time_epoch',
            '-e', 'ip.src',
            '-e', 'ip.dst',
            '-e', 'tcp.srcport',
            '-e', 'tcp.dstport',
            '-e', 'tcp.seq',
            '-e', 'tcp.len',
            '-e', 'tcp.analysis.retransmission',
            '-e', 'tcp.analysis.fast_retransmission',
            '-e', 'tcp.analysis.spurious_retransmission',
            '-e', 'tcp.analysis.rto',
            '-e', 'tcp.flags'
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=300  # 5 min timeout
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"tshark failed: {e.stderr}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("tshark timeout (>5min)")

        # Parse JSON output
        packets = json.loads(result.stdout)

        retransmissions = []
        for pkt in packets:
            layers = pkt.get('_source', {}).get('layers', {})

            retrans = TCPRetransmission(
                packet_num=int(layers.get('frame.number', [0])[0]),
                timestamp=float(layers.get('frame.time_epoch', [0])[0]),
                src_ip=layers.get('ip.src', [''])[0],
                dst_ip=layers.get('ip.dst', [''])[0],
                src_port=int(layers.get('tcp.srcport', [0])[0]),
                dst_port=int(layers.get('tcp.dstport', [0])[0]),
                seq_num=int(layers.get('tcp.seq', [0])[0]),
                # ... map all fields
                is_spurious='tcp.analysis.spurious_retransmission' in layers,
                retrans_type=self._classify_retrans_type(layers),
                # tshark doesn't provide original packet, set to None
                original_packet_num=None,
                delay=None
            )

            retransmissions.append(retrans)

        return retransmissions
```

---

## 📋 Implementation Plan

### Phase 1: Core tshark Backend ✅

- [x] ~~Create `src/analyzers/retransmission_tshark.py`~~
- [ ] Implement `TsharkRetransmissionAnalyzer` class
- [ ] Subprocess call to tshark with JSON output
- [ ] Parse JSON and map to `TCPRetransmission` dataclass
- [ ] Handle tshark errors gracefully

**Files**:
- `src/analyzers/retransmission_tshark.py` (NEW)

---

### Phase 2: Path Detection ⏳

- [ ] Implement `find_tshark()` function
- [ ] macOS: `/Applications/Wireshark.app/Contents/MacOS/tshark`
- [ ] Linux: `shutil.which('tshark')` + common paths
- [ ] Windows: Program Files paths
- [ ] Unit tests for path detection

**Files**:
- `src/analyzers/retransmission_tshark.py` (find_tshark function)
- `tests/unit/analyzers/test_tshark_backend.py` (NEW)

---

### Phase 3: Backend Selection 🔜

- [ ] Create `RetransmissionAnalyzerFactory`
- [ ] Auto-detection logic
- [ ] Graceful fallback with logging
- [ ] Backend selection in main analyzer

**Files**:
- `src/analyzers/retransmission.py` (modify to use factory)

---

### Phase 4: CLI Integration 🔜

- [ ] Add `--retrans-backend {auto,tshark,builtin}` option
- [ ] Update `analyze` command
- [ ] Add backend info to HTML report footer
- [ ] Warning messages when fallback occurs

**Files**:
- `src/cli.py` (add option)
- `src/exporters/html_report.py` (show backend used)

---

### Phase 5: Testing & Documentation 🔜

- [ ] Test with `c1.pcap` (expect 27 retrans with tshark)
- [ ] Test fallback (rename tshark temporarily)
- [ ] Update `README.md` installation section
- [ ] Update `CHANGELOG.md` with v5.4.0 entry
- [ ] Update `docs/installation.md`
- [ ] Verify Docker image uses tshark by default

**Files**:
- `README.md`
- `CHANGELOG.md`
- `docs/installation.md`
- `tests/integration/test_tshark_backend.py` (NEW)

---

## 🧪 Test Cases

### Test 1: tshark Backend with c1.pcap

```bash
pcap_analyzer analyze c1.pcap --retrans-backend tshark
```

**Expected**:
- ✅ 27 retransmissions detected (100% vs tshark ground truth)
- ✅ Report shows "Backend: tshark v4.6.2"
- ✅ All 10 spurious retransmissions identified separately

### Test 2: Fallback to Builtin

```bash
# Temporarily hide tshark
sudo mv /Applications/Wireshark.app /Applications/Wireshark.app.bak

pcap_analyzer analyze c1.pcap --retrans-backend auto
```

**Expected**:
- ⚠️ Warning: "tshark not found, falling back to built-in analyzer"
- ✅ 23 retransmissions detected (85% accuracy)
- ✅ Report shows "Backend: builtin (85% accuracy)"

### Test 3: Force Builtin

```bash
pcap_analyzer analyze c1.pcap --retrans-backend builtin
```

**Expected**:
- ✅ 23 retransmissions detected
- ✅ No warning (intentional choice)
- ✅ Report shows "Backend: builtin"

### Test 4: Force tshark (not available)

```bash
pcap_analyzer analyze c1.pcap --retrans-backend tshark
# (with tshark not installed)
```

**Expected**:
- ❌ Error: "tshark backend requested but tshark not found. Install Wireshark..."
- Exit code 1

---

## 📈 Success Criteria

- [x] v5.3.0 committed and tagged
- [ ] `TsharkRetransmissionAnalyzer` implemented and tested
- [ ] `find_tshark()` works on macOS and Linux
- [ ] Auto-detection selects tshark when available
- [ ] Graceful fallback to builtin when tshark unavailable
- [ ] CLI option `--retrans-backend` works
- [ ] c1.pcap: 27/27 retrans detected with tshark backend
- [ ] c1.pcap: 23/27 retrans detected with builtin backend
- [ ] Docker image uses tshark by default
- [ ] HTML report shows backend used
- [ ] Documentation updated
- [ ] CHANGELOG.md updated with v5.4.0

---

## 🔗 Related Files

**Core Implementation**:
- `src/analyzers/retransmission_tshark.py` (NEW)
- `src/analyzers/retransmission.py` (MODIFIED)
- `src/cli.py` (MODIFIED)
- `src/exporters/html_report.py` (MODIFIED)

**Tests**:
- `tests/unit/analyzers/test_tshark_backend.py` (NEW)
- `tests/integration/test_tshark_backend.py` (NEW)

**Documentation**:
- `README.md` (MODIFIED)
- `CHANGELOG.md` (MODIFIED)
- `docs/tshark_backend_analysis.md` (EXISTS)
- `docs/installation.md` (MODIFIED)

---

## 📝 Notes

- tshark is already installed in Docker image (see `Dockerfile` line 45)
- No additional dependencies needed (subprocess is stdlib)
- Performance should be comparable (single tshark call vs multiple packet iterations)
- Fallback ensures no breaking changes for existing users

---

**Created**: 2025-12-28
**Last Updated**: 2025-12-28
**Track Status**: 🚧 In Progress (Phase 1)
