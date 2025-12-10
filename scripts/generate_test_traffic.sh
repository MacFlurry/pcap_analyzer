#!/bin/bash
# Traffic Generation Script for PCAP Analyzer Testing
# Generates diverse network traffic patterns for comprehensive analysis

set -e

echo "🌐 Traffic Generation Script for PCAP Analyzer"
echo "=============================================="
echo ""

# Scenario 1: Normal HTTP Traffic
echo "📡 Scenario 1: Generating HTTP/HTTPS traffic..."
curl -s https://example.com > /dev/null &
curl -s https://www.google.com > /dev/null &
curl -s https://github.com > /dev/null &
wget -q -O /dev/null https://www.wikipedia.org &
sleep 2

# Scenario 2: SSH Connections (legitimate)
echo "🔐 Scenario 2: Generating SSH traffic..."
# Test SSH connectivity (will prompt for auth, but generates traffic)
timeout 2 ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no localhost 2>/dev/null || true
timeout 2 ssh -o ConnectTimeout=1 -o StrictHostKeyChecking=no 192.168.25.1 2>/dev/null || true
sleep 1

# Scenario 3: DNS Queries (diverse)
echo "🔍 Scenario 3: Generating diverse DNS queries..."
nslookup google.com >/dev/null 2>&1 || true
nslookup github.com >/dev/null 2>&1 || true
nslookup cloudflare.com >/dev/null 2>&1 || true
dig amazon.com >/dev/null 2>&1 || true
sleep 1

# Scenario 4: Port Scan Simulation (light, non-intrusive)
echo "🔎 Scenario 4: Simulating port scan pattern..."
# Connect to common ports on localhost to generate scan-like pattern
for port in 22 80 443 8080 3306 5432 6379 27017; do
    timeout 0.5 nc -zv localhost $port 2>/dev/null || true &
done
wait
sleep 1

# Scenario 5: Multiple Connection Attempts (brute-force pattern)
echo "🔨 Scenario 5: Simulating connection burst..."
for i in {1..10}; do
    timeout 0.2 nc -zv localhost 22 2>/dev/null || true &
done
wait
sleep 1

# Scenario 6: UDP Traffic (NTP, SNMP-like)
echo "📊 Scenario 6: Generating UDP traffic..."
# NTP query
timeout 2 ntpdate -q pool.ntp.org >/dev/null 2>&1 || true
sleep 1

# Scenario 7: ICMP Traffic
echo "🏓 Scenario 7: Generating ICMP traffic..."
ping -c 5 8.8.8.8 >/dev/null 2>&1 &
ping -c 5 1.1.1.1 >/dev/null 2>&1 &
wait
sleep 1

echo ""
echo "✅ Traffic generation complete!"
echo "📦 This generated:"
echo "   - HTTP/HTTPS requests (TCP handshakes, data transfer)"
echo "   - SSH connection attempts (authentication traffic)"
echo "   - DNS queries (various domains)"
echo "   - Port scan pattern (sequential port probing)"
echo "   - Connection bursts (rapid connection attempts)"
echo "   - UDP traffic (NTP)"
echo "   - ICMP traffic (ping)"
echo ""
echo "💡 This traffic exercises:"
echo "   ✓ TCP analyzers (handshake, RTT, retrans, window)"
echo "   ✓ DNS analyzer"
echo "   ✓ Protocol distribution"
echo "   ✓ Service classification"
echo "   ✓ Security detectors (port scan, brute-force)"
