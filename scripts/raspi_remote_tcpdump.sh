#!/usr/bin/env bash
set -euo pipefail

# Run this script on the Raspberry Pi.
# Usage:
#   sudo ./raspi_remote_tcpdump.sh <output.pcap> [duration_sec] [interface] [bpf_filter]

OUT_FILE="${1:-/tmp/capture_$(date +%Y%m%d_%H%M%S).pcap}"
DURATION="${2:-180}"
IFACE="${3:-any}"
FILTER="${4:-}"

echo "[remote] starting tcpdump: iface=${IFACE} duration=${DURATION}s out=${OUT_FILE}"

if [[ -n "${FILTER}" ]]; then
  timeout "${DURATION}" tcpdump -i "${IFACE}" -s 0 -U -w "${OUT_FILE}" "${FILTER}"
else
  timeout "${DURATION}" tcpdump -i "${IFACE}" -s 0 -U -w "${OUT_FILE}"
fi

echo "[remote] capture done: ${OUT_FILE}"
