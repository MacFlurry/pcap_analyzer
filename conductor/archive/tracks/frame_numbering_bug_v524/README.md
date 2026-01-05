# Track: Frame Numbering Bug Fix (v5.2.4)

**Version**: v5.2.4 (PATCH)
**Priority**: CRITICAL 🔴
**Type**: Bug Fix
**Impact**: Data Integrity
**Status**: ✅ COMPLETED

## Problem Statement

Frame numbers throughout the application were incorrect and did not match Wireshark/tshark. This affected all analyzers and made it impossible to correlate findings with Wireshark's packet view.

### Discovered Issues

Flow: `2.19.147.191:80 ↔ 10.20.0.165:1831`

**Expected (tshark)**:
- SYN: Frame 7458
- SYN-ACK: Frame 7462
- SYN-ACK retrans: Frames 7492, 7608, 7616, 7989, 8099

**Actual (before fix)**:
- SYN: Frame 7419 (off by 39) ❌
- SYN-ACK: Frame 8099 (wrong - last retransmission instead of first!) ❌
- Retransmissions: Correct frames ✓

## Root Causes (Triple Bug)

### Bug #1: FastPacketParser Only Counted IP Packets
**File**: `src/parsers/fast_parser.py:171`

**Problem**: Parser only incremented `packet_num` for IP packets that were yielded. Non-IP packets (ARP, etc.) were skipped but NOT counted in frame numbering.

**Impact**: Frame numbers were off by the number of non-IP packets (39 in test case).

**Fix**: Moved `packet_num += 1` to execute for ALL packets, even skipped ones:
```python
# v5.2.4 CRITICAL FIX: Increment packet_num for ALL packets (even skipped ones)
# to match Wireshark frame numbering (includes non-IP packets)
metadata = self._extract_metadata(buf, packet_num, timestamp, datalink)
packet_num += 1  # Always increment, even if metadata is None
```

### Bug #2: CLI Passed Wrong Counter to Analyzers
**File**: `src/cli.py:421-464`

**Problem**: CLI maintained two counters:
- `packet_count`: Number of IP packets yielded (7419)
- `metadata.packet_num`: Wireshark frame number (7458)

But passed the WRONG one (`packet_count`) to all analyzers.

**Fix**: Changed all analyzer calls to use `metadata.packet_num`:
```python
# v5.2.4: Use metadata.packet_num (includes non-IP packets) to match Wireshark
timestamp_analyzer.process_packet(metadata, metadata.packet_num)
handshake_analyzer.process_packet(metadata, metadata.packet_num)
# ... etc
```

### Bug #3: Handshake Analyzer Recorded Last SYN-ACK
**File**: `src/analyzers/tcp_handshake.py:208, 323`

**Problem**: Analyzer overwrote `synack_packet_num` every time it saw a SYN-ACK. For flows with retransmissions, it recorded the LAST SYN-ACK (frame 8099) instead of the FIRST (frame 7462).

**Fix**: Added check to record only the first SYN-ACK:
```python
# v5.2.4: Only record the FIRST SYN-ACK (ignore retransmissions)
if handshake.synack_packet_num is None:
    handshake.synack_time = packet_time
    handshake.synack_packet_num = packet_num
    # ...
```

## Test Data

PCAP file: `/Users/omegabk/Downloads/c1.pcap`

**Key flow**: `10.20.0.165:1831 → 2.19.147.191:80`

**Verification**:
```bash
/Applications/Wireshark.app/Contents/MacOS/tshark -r c1.pcap \
  -Y "tcp.port == 1831 and tcp.flags.syn == 1" \
  -T fields -e frame.number -e ip.src -e tcp.srcport -e tcp.dstport -e tcp.flags.str
```

Output:
```
7458	10.20.0.165	1831	80	··········S·      ← SYN
7462	2.19.147.191	80	1831	·······A··S·   ← SYN-ACK (first)
7492	2.19.147.191	80	1831	·······A··S·   ← Retrans #1
7608	2.19.147.191	80	1831	·······A··S·   ← Retrans #2
7616	2.19.147.191	80	1831	·······A··S·   ← Retrans #3
7989	2.19.147.191	80	1831	·······A··S·   ← Retrans #4
8099	2.19.147.191	80	1831	·······A··S·   ← Retrans #5
```

## Resolution ✅

All three bugs have been fixed:

1. ✅ Parser counts ALL packets (IP + non-IP)
2. ✅ CLI passes `metadata.packet_num` to analyzers
3. ✅ Handshake analyzer records FIRST SYN-ACK only

**Verification Results**:
- SYN: Frame 7458 ✅ (matches tshark)
- SYN-ACK: Frame 7462 ✅ (matches tshark, not 8099)
- Retransmissions: Frames 7492, 7608, 7616, 7989, 8099 ✅ (all correct)

**Report**: `/Users/omegabk/investigations/pcap_analyzer/reports/pcap_analysis_20251228_025427.html`

All frame numbers in JSON and HTML reports now match Wireshark/tshark exactly.

## Files Modified

- `src/parsers/fast_parser.py` (packet counting logic)
- `src/cli.py` (analyzer parameter passing)
- `src/analyzers/tcp_handshake.py` (SYN-ACK recording logic)
- `CHANGELOG.md` (documented fixes)

## Impact

✅ **Data Integrity Restored**: All frame numbers are now correct and verifiable with tshark
✅ **User Confidence**: Reports can be trusted to match Wireshark's packet numbering
✅ **Troubleshooting**: Users can correlate findings with Wireshark seamlessly
