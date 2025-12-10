# Sprint 8: Security Detector Validation Guide

This guide explains how to validate the DDoS and DNS Tunneling detectors using the provided simulation scripts.

## Prerequisites

- Python 3.9+
- Network access to a test target (use your own infrastructure only!)
- `tcpdump` for packet capture (requires sudo/root)
- PCAP Analyzer installed and configured

## ⚠️ Important Warnings

- **ONLY use these scripts on systems you own or have explicit authorization to test**
- These scripts generate attack-like traffic patterns
- Running them against unauthorized targets is illegal
- Use isolated test networks when possible

## Test Scenarios

### Scenario 1: DDoS Detection

**Script**: `scripts/simulate_ddos.py`

**Attack Types**:
1. SYN Flood (150 packets @ 150 pkt/s)
2. UDP Flood (600 packets @ 600 pkt/s)
3. ICMP Flood (150 packets @ 150 pkt/s)
4. Distributed SYN Flood (10 simulated sources)

**Expected Detections**:
- SYN Flood: Critical/High severity
- UDP Flood: Critical/High severity
- ICMP Flood: Medium/High severity

**Usage**:
```bash
# On local machine - capture traffic
sudo tcpdump -i any -w ddos_test.pcap &
TCPDUMP_PID=$!

# On another terminal - run attack simulation
python3 scripts/simulate_ddos.py 192.168.25.15

# Stop capture
kill $TCPDUMP_PID

# Analyze
pcap_analyzer analyze ddos_test.pcap --export-dir reports/ddos_validation
```

**Duration**: ~2 minutes

### Scenario 2: DNS Tunneling Detection

**Script**: `scripts/simulate_dns_tunneling.py`

**Attack Types**:
1. Base64-encoded exfiltration (25 queries)
2. Hex-encoded C2 communication (20 queries)
3. Random high-entropy covert channel (18 queries)
4. High-frequency beaconing (30 queries)
5. TXT record exfiltration (15 queries)

**Expected Detections**:
- 5 suspicious DNS tunneling activities
- High entropy indicators (>3.5 bits/char)
- Long query lengths (>50 chars)
- High query rates (>10 queries/min)
- Encoding patterns (base64, hex)

**Usage**:
```bash
# Capture DNS traffic
sudo tcpdump -i any -w dns_tunnel_test.pcap udp port 53 &
TCPDUMP_PID=$!

# Run DNS tunneling simulation (takes ~5 minutes)
python3 scripts/simulate_dns_tunneling.py

# Stop capture
kill $TCPDUMP_PID

# Analyze
pcap_analyzer analyze dns_tunnel_test.pcap --export-dir reports/dns_tunnel_validation
```

**Duration**: ~5 minutes

### Scenario 3: Combined Test (Recommended)

Test all detectors together with mixed attack traffic:

```bash
# Start comprehensive capture
sudo tcpdump -i any -w sprint8_validation.pcap 'tcp or udp or icmp' &
TCPDUMP_PID=$!

# Run DDoS attacks
echo "=== Part 1/2: DDoS Attacks ==="
python3 scripts/simulate_ddos.py 192.168.25.15

# Wait between scenarios
sleep 5

# Run DNS tunneling
echo "=== Part 2/2: DNS Tunneling ==="
python3 scripts/simulate_dns_tunneling.py

# Stop capture
kill $TCPDUMP_PID

# Analyze all attacks
pcap_analyzer analyze sprint8_validation.pcap \\
    --export-dir reports/sprint8_full_validation
```

**Total Duration**: ~7 minutes

## Validation Checklist

After running the tests and generating reports, verify:

### DDoS Detector:
- [ ] SYN Flood detected (check: packets/sec > 100, SYN-ACK ratio < 10%)
- [ ] UDP Flood detected (check: packets/sec > 500)
- [ ] ICMP Flood detected (check: packets/sec > 100)
- [ ] Severity levels appropriate (high volume = higher severity)
- [ ] Multi-source attacks correlated correctly

### DNS Tunneling Detector:
- [ ] Base64-encoded queries flagged
- [ ] Hex-encoded queries flagged
- [ ] High-entropy subdomains detected (entropy > 3.5)
- [ ] Long queries detected (> 50 characters)
- [ ] High query rates detected (> 10 queries/min)
- [ ] Suspicious patterns identified in report

### Port Scan Detector (Sprint 6 improvement):
- [ ] Vertical scan threshold lowered (3 targets instead of 5)
- [ ] Small vertical scans now detected

### General:
- [ ] No false positives from localhost traffic (::1, 127.0.0.0/8)
- [ ] LAN traffic properly analyzed (192.168.x.x)
- [ ] HTML report generated successfully
- [ ] JSON/CSV exports complete
- [ ] All severity badges display correctly

## Interpreting Results

### DDoS Results (JSON):
```json
{
  "ddos_detection": {
    "total_attacks_detected": 3,
    "severity_breakdown": {
      "critical": 1,
      "high": 2
    },
    "attack_type_breakdown": {
      "syn_flood": 1,
      "udp_flood": 1,
      "icmp_flood": 1
    },
    "ddos_events": [
      {
        "attack_type": "syn_flood",
        "target_ip": "192.168.25.15",
        "packets_per_second": 150.5,
        "severity": "critical"
      }
    ]
  }
}
```

### DNS Tunneling Results (JSON):
```json
{
  "dns_tunneling_detection": {
    "total_tunneling_detected": 5,
    "severity_breakdown": {
      "high": 3,
      "medium": 2
    },
    "tunneling_events": [
      {
        "domain": "suspicious-tunnel.malicious",
        "avg_entropy": 5.2,
        "avg_query_length": 45.3,
        "suspicious_patterns": [
          "base64",
          "long_queries (avg: 45 chars)",
          "high_rate (15.5 queries/min)"
        ]
      }
    ]
  }
}
```

## Troubleshooting

### tcpdump: Permission Denied
- Run with `sudo` or configure capabilities: `sudo setcap cap_net_raw+ep /usr/bin/tcpdump`

### DNS Queries Failing
- Normal! The domains don't exist, but queries are sent to DNS resolver
- The detector analyzes the query patterns, not responses

### ICMP Flood Not Working
- May require root/admin privileges for raw ICMP
- Falls back to `ping` command if available
- Lower packet counts are normal

### No Attacks Detected
- Check capture file size: `ls -lh *.pcap`
- Verify traffic was captured: `tcpdump -r file.pcap -c 10`
- Ensure thresholds aren't too high (see detector configuration)

## Performance Notes

- **DDoS simulation**: Generates ~1000 packets (~50KB)
- **DNS tunneling**: Generates ~108 DNS queries (~10KB)
- **Analysis time**: < 5 seconds for these small captures
- **Memory usage**: Minimal (< 100MB)

## Next Steps

After validation:
1. Document any issues found
2. Adjust detector thresholds if needed
3. Run tests with larger packet counts for stress testing
4. Consider adding more attack types
5. Implement automated regression tests

## Reference

- **DDoS Thresholds**: `src/analyzers/ddos_detector.py` lines 51-75
- **DNS Tunneling Thresholds**: `src/analyzers/dns_tunneling_detector.py` lines 65-86
- **Detection Algorithms**: See inline documentation in detector files

## Security Notice

These simulation scripts are designed for **security testing and validation only**. Misuse of these tools for unauthorized testing or actual attacks is:
- Illegal in most jurisdictions
- Violation of computer fraud laws
- Subject to civil and criminal penalties

Always ensure you have proper authorization before running any security tests.
