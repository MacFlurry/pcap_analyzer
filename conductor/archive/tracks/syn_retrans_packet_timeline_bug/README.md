# Track: SYN Retransmission Packet Timeline Bug Fix

**Version**: v5.2.3 (PATCH)
**Priority**: CRITICAL 🔴
**Type**: Bug Fix
**Impact**: Data Integrity

## Problem Statement

The packet timeline feature displays **incorrect frame numbers** from wrong TCP flows when showing SYN retransmission context. This is a critical data integrity bug that makes the timeline completely unusable for troubleshooting.

### User Report

Flow: `2.19.147.191:80 ↔ 10.20.0.165:1831`

**Expected behavior**: Show packets from this flow only (tcp.stream 131)

**Actual behavior**: Shows frames from completely different TCP streams:
- Frame 7422: tcp.stream 130 (port 1830) ❌
- Frame 7452: tcp.stream 129 (port 1829) ❌
- Frame 7566: tcp.stream 137 (port 1837) ❌
- Frame 7574: tcp.stream 137 (port 1837) ❌

**Correct frames** (from tcp.stream 131):
- Frame 7458: SYN ✓
- Frame 7462: SYN,ACK ✓
- Frames 7492, 7608, 7616, 7989, 8099: SYN,ACK retransmissions ✓

### Additional Issue: Wrong Diagnostic

The tool also incorrectly reports:
- **Displayed**: "SYN retrans = Connection failed (server unreachable)"
- **Reality**: Server IS reachable (sends SYN,ACK), but CLIENT never completes handshake

**Root cause**: Client unable to complete 3-way handshake (missing final ACK)

## Test Data

PCAP file provided: `/Users/omegabk/investigations/pcap_analyzer/tests/data/syn_retrans_bug.pcap`

**Key flow to test**:
- Flow: `10.20.0.165:1831 → 2.19.147.191:80`
- Stream ID: tcp.stream 131
- Packets: 7 total (1 SYN + 6 SYN,ACK)
- Issue: SYN,ACK retransmissions (server trying to complete handshake)

**Verification command**:
```bash
/Applications/Wireshark.app/Contents/MacOS/tshark -r tests/data/syn_retrans_bug.pcap \
  -Y "tcp.stream==131" \
  -T fields -e frame.number -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e tcp.flags.str
```

Expected output:
```
7458	10.20.0.165	1831	2.19.147.191	80	··········S·
7462	2.19.147.191	80	10.20.0.165	1831	·······A··S·
7492	2.19.147.191	80	10.20.0.165	1831	·······A··S·
7608	2.19.147.191	80	10.20.0.165	1831	·······A··S·
7616	2.19.147.191	80	10.20.0.165	1831	·······A··S·
7989	2.19.147.191	80	10.20.0.165	1831	·······A··S·
8099	2.19.147.191	80	10.20.0.165	1831	·······A··S·
```

## Acceptance Criteria

- [ ] Handshake section shows ONLY packets from correct TCP stream
- [ ] Frame numbers match tcp.stream filter (7458, 7462, 7492...)
- [ ] No frames from other TCP streams appear
- [ ] Diagnostic correctly identifies "Client unable to complete handshake"
- [ ] All unit tests pass
- [ ] Regression test added with provided PCAP

## Files

- `plan.md`: Detailed implementation plan
- `metadata.json`: Track metadata
- Test PCAP: `tests/data/syn_retrans_bug.pcap`
