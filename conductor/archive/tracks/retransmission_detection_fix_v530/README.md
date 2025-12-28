# Track: Fix Retransmission Detection Over-Sensitivity (v5.3.0)

**Version**: v5.3.0 (MINOR)
**Priority**: HIGH 🟠
**Type**: Bug Fix / Accuracy Improvement
**Impact**: Data Accuracy & User Trust
**Status**: 📋 PLANNED

## Problem Statement

PCAP Analyzer's retransmission detection algorithm is **over-sensitive** and reports significantly more retransmissions than Wireshark/tshark, leading to:
- Inflated retransmission counts (59% higher on test data)
- Incorrect classification (Fast Retrans vs RTO)
- Pessimistic Health Scores
- Loss of user trust when comparing with Wireshark

### Discovered Issues

**Test Flow**: 178.79.195.246:80 → 10.20.0.165:1871

| Metric | PCAP Analyzer | tshark (baseline) | Discrepancy |
|--------|---------------|-------------------|-------------|
| **Total retransmissions** | 43 | 27 | +59% 🔴 |
| **Unique segments retrans** | 27 | 27 | ✅ Match |
| **Fast Retrans** | 25 | 6 | +317% 🔴 |
| **RTO (non-SYN)** | 3 | 16 | -81% 🔴 |
| **SYN retrans** | 7 | 5 | +40% 🟡 |
| **Spurious retrans** | 0 | 10 | Not detected 🔴 |

### False Positive Examples

Frames detected as retransmissions by PCAP Analyzer but **NOT** by tshark:

| Frame | SEQ | Len | tshark Status | PCAP Analyzer | Issue |
|-------|-----|-----|---------------|---------------|-------|
| 8991 | 9831 | 1460 | Normal transmission | ✅ Retrans | False positive |
| 9010 | 24431 | 1460 | Normal transmission | ✅ Retrans | False positive |
| 9052 | 38824 | 1460 | Normal transmission | ✅ Retrans | False positive |
| 9062 | 46124 | 1460 | Normal transmission | ✅ Retrans | False positive |
| 9073 | 51964 | 1460 | Normal transmission | ✅ Retrans | False positive |
| 9077 | 54884 | 1460 | Normal transmission | ✅ Retrans | False positive |

**Pattern**: Progressive SEQ numbers with new data → NOT retransmissions!

## Root Cause Analysis

### Current Detection Algorithm
**File**: `src/analyzers/retransmission.py`

The hybrid dpkt+Scapy detection appears to have issues with:

1. **Out-of-Order Packet Handling**
   - Normal out-of-order packets classified as retransmissions
   - Missing stateful sequence number tracking

2. **Spurious Retransmission Detection**
   - tshark detects 10 spurious retransmissions
   - PCAP Analyzer doesn't distinguish spurious from genuine

3. **Fast Retrans vs RTO Classification**
   - Over-aggressive Fast Retrans classification
   - Missing proper duplicate ACK counting
   - RTO detection under-sensitive

4. **Lack of RFC 793 Compliance**
   - tshark uses RFC 793 stateful engine
   - PCAP Analyzer may be using heuristics only

## Impact

### User Experience
- ❌ **Trust Issues**: Users comparing with Wireshark see mismatches
- ❌ **False Alarms**: Network appears worse than reality
- ❌ **Misleading Diagnostics**: Wrong severity levels and recommendations

### Technical Metrics
- ❌ **Health Score**: Pessimistic (network quality underestimated)
- ❌ **Retransmission Rate**: Inflated by 59%
- ❌ **Classification Accuracy**: Fast vs RTO misclassified
- ❌ **Missing Detection**: Spurious retransmissions not identified

## Proposed Solution

### Phase 1: Root Cause Investigation 🔍
**Goal**: Understand current detection logic

- [ ] Read and analyze `src/analyzers/retransmission.py` in detail
- [ ] Trace detection logic for test flow (port 1871)
- [ ] Identify exact conditions triggering false positives
- [ ] Document current algorithm vs RFC 793

### Phase 2: Reference Implementation Study 📚
**Goal**: Learn from tshark's RFC 793 implementation

- [ ] Study Wireshark's `packet-tcp.c` retransmission detection
- [ ] Document RFC 793 stateful sequence tracking
- [ ] Identify key differences from PCAP Analyzer
- [ ] Create test cases from RFC 793 examples

### Phase 3: Algorithm Refinement 🔧
**Goal**: Align detection with RFC 793

- [ ] Implement proper stateful SEQ/ACK tracking
- [ ] Add spurious retransmission detection
- [ ] Fix Fast Retrans criteria (3 duplicate ACKs)
- [ ] Improve RTO detection (timeout-based, not heuristic)
- [ ] Add confidence scoring for each detection

### Phase 4: Testing & Validation ✅
**Goal**: Achieve <5% discrepancy with tshark

- [ ] Test with c1.pcap baseline (target: 27 retrans ±1)
- [ ] Verify all 14 tshark-detected retrans are found
- [ ] Ensure false positive rate <5%
- [ ] Test with additional PCAPs (diverse scenarios)
- [ ] Create regression tests

## Test Data

**Primary PCAP**: `/Users/omegabk/Downloads/c1.pcap`

**Baseline Validation Commands**:
```bash
# Total retransmissions (should be 27)
tshark -r c1.pcap -Y 'tcp.analysis.retransmission' | wc -l

# Fast retransmissions (should be 6)
tshark -r c1.pcap -Y 'tcp.analysis.fast_retransmission' | wc -l

# Spurious retransmissions (should be 10)
tshark -r c1.pcap -Y 'tcp.analysis.spurious_retransmission' | wc -l

# RTO (should be 16)
tshark -r c1.pcap -Y 'tcp.analysis.retransmission and not tcp.analysis.fast_retransmission and not tcp.flags.syn==1' | wc -l

# SYN retransmissions (should be 5)
tshark -r c1.pcap -Y 'tcp.analysis.retransmission and tcp.flags.syn==1' | wc -l
```

**Test Flow (port 1871)** - 14 retransmissions expected:
```bash
tshark -r c1.pcap -Y 'tcp.port == 1871 and tcp.analysis.retransmission' \
  -T fields -e frame.number | tr '\n' ',' | sed 's/,$/\n/'
```
Expected: `9006,9050,9060,9082,9085,9087,9092,9094,9097,9218,9258,9268,9273,9282`

## Success Criteria

- [ ] **Total retrans match**: PCAP Analyzer detects 27 ±1 retransmissions (tshark baseline)
- [ ] **False positive rate**: <5% (max 1-2 false positives)
- [ ] **False negative rate**: 0% (all 27 tshark retrans detected)
- [ ] **Spurious detection**: Identify all 10 spurious retransmissions
- [ ] **Classification accuracy**: Fast vs RTO matches tshark ±10%
- [ ] **No regression**: SYN retrans detection still accurate
- [ ] **Performance**: No significant slowdown in analysis time
- [ ] **Documentation**: Algorithm documented with RFC 793 references

## Files to Modify

**Primary**:
- `src/analyzers/retransmission.py` - Core detection logic

**Secondary**:
- `src/parsers/fast_parser.py` - May need SEQ/ACK state tracking
- `src/exporters/html_report.py` - May need to display spurious retrans
- `src/exporters/json_exporter.py` - Add spurious retrans field

**Tests**:
- `tests/unit/test_retransmission_detector.py` (new)
- `tests/integration/test_retransmission_accuracy.py` (new)
- `tests/data/c1.pcap` (add to test fixtures)

## Resources

### References
- [RFC 793 - TCP Specification](https://www.rfc-editor.org/rfc/rfc793)
- [Wireshark TCP Analysis](https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html)
- [Wireshark source: packet-tcp.c](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-tcp.c)

### Wireshark Analysis Flags
- `tcp.analysis.retransmission` - Retransmitted data detected
- `tcp.analysis.fast_retransmission` - Fast retransmit (3 dup ACKs)
- `tcp.analysis.spurious_retransmission` - Spurious retransmit detected
- `tcp.analysis.rto` - Retransmission timeout value

## Notes

- This is a **pre-existing issue**, not introduced by v5.2.5
- Documented as "Known Limitation" in CHANGELOG v5.2.5
- Critical for user trust and tool credibility
- May require significant refactoring of detection logic
- Consider adding optional tshark backend for validation mode

## Timeline (Estimated)

- **Phase 1**: 2-3 days (investigation)
- **Phase 2**: 2 days (study RFC 793 + tshark)
- **Phase 3**: 5-7 days (implementation)
- **Phase 4**: 2-3 days (testing & validation)

**Total**: ~2 weeks for complete fix

## Related Issues

- v5.2.4: Frame numbering fixed (accurate frame refs now available)
- v5.2.5: SYN diagnostic messages fixed (correct direction)
- v5.3.0: This track (detection accuracy)
