#!/usr/bin/env bash
set -euo pipefail

# Local orchestration script:
# 1) Upload remote capture helper to Raspberry Pi
# 2) Run tcpdump remotely via SSH
# 3) Download PCAP
# 4) Run tshark quick stats
# 5) Run pcap_analyzer
#
# Example:
#   scripts/capture_from_raspberry.sh \
#     --host 192.168.25.15 --user omegabk --key ~/.ssh/id_ed25519_raspberry \
#     --duration 120 --iface any --filter "tcp or udp" --name lab1

HOST=""
USER_NAME=""
SSH_KEY="${HOME}/.ssh/id_ed25519_raspberry"
DURATION="180"
IFACE="any"
FILTER=""
NAME="raspi_capture"
OUT_DIR="pcap-dir"
TSHARK_STATS="yes"
RUN_ANALYZER="yes"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) HOST="$2"; shift 2 ;;
    --user) USER_NAME="$2"; shift 2 ;;
    --key) SSH_KEY="$2"; shift 2 ;;
    --duration) DURATION="$2"; shift 2 ;;
    --iface) IFACE="$2"; shift 2 ;;
    --filter) FILTER="$2"; shift 2 ;;
    --name) NAME="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --no-tshark) TSHARK_STATS="no"; shift ;;
    --no-analyzer) RUN_ANALYZER="no"; shift ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "${HOST}" || -z "${USER_NAME}" ]]; then
  echo "Usage: $0 --host <ip> --user <user> [--key <path>] [--duration <sec>] [--iface <iface>] [--filter <bpf>] [--name <label>] [--out-dir <dir>] [--no-tshark] [--no-analyzer]" >&2
  exit 2
fi

if ! command -v ssh >/dev/null || ! command -v scp >/dev/null; then
  echo "ssh/scp are required." >&2
  exit 1
fi

mkdir -p "${OUT_DIR}"
TS="$(date +%Y%m%d_%H%M%S)"
REMOTE_HELPER="/tmp/raspi_remote_tcpdump.sh"
REMOTE_PCAP="/tmp/${NAME}_${TS}.pcap"
LOCAL_PCAP="${OUT_DIR}/${NAME}_${TS}.pcap"

echo "[1/5] Upload helper script to Raspberry"
scp -i "${SSH_KEY}" -o StrictHostKeyChecking=no scripts/raspi_remote_tcpdump.sh "${USER_NAME}@${HOST}:${REMOTE_HELPER}"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${USER_NAME}@${HOST}" "chmod +x ${REMOTE_HELPER}"

echo "[2/5] Capture remotely with tcpdump"
if [[ -n "${FILTER}" ]]; then
  ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${USER_NAME}@${HOST}" \
    "sudo ${REMOTE_HELPER} ${REMOTE_PCAP} ${DURATION} ${IFACE} '${FILTER}'"
else
  ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${USER_NAME}@${HOST}" \
    "sudo ${REMOTE_HELPER} ${REMOTE_PCAP} ${DURATION} ${IFACE}"
fi

echo "[3/5] Download PCAP"
scp -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${USER_NAME}@${HOST}:${REMOTE_PCAP}" "${LOCAL_PCAP}"
ssh -i "${SSH_KEY}" -o StrictHostKeyChecking=no "${USER_NAME}@${HOST}" "sudo rm -f ${REMOTE_PCAP} ${REMOTE_HELPER}"

if [[ ! -s "${LOCAL_PCAP}" ]]; then
  echo "Downloaded PCAP is empty: ${LOCAL_PCAP}" >&2
  exit 1
fi

if [[ "${TSHARK_STATS}" == "yes" ]]; then
  if command -v tshark >/dev/null; then
    echo "[4/5] tshark quick analysis"
    tshark -r "${LOCAL_PCAP}" -q -z io,stat,1 -z conv,tcp -z conv,udp | tee "${LOCAL_PCAP%.pcap}.tshark.txt"
  else
    echo "[4/5] tshark not found locally, skipping quick analysis"
  fi
else
  echo "[4/5] tshark step skipped"
fi

if [[ "${RUN_ANALYZER}" == "yes" ]]; then
  echo "[5/5] pcap_analyzer run"
  if [[ -x ".venv/bin/pcap_analyzer" ]]; then
    .venv/bin/pcap_analyzer analyze "${LOCAL_PCAP}" -o "$(basename "${LOCAL_PCAP%.pcap}")"
  else
    pcap_analyzer analyze "${LOCAL_PCAP}" -o "$(basename "${LOCAL_PCAP%.pcap}")"
  fi
else
  echo "[5/5] analyzer step skipped"
fi

echo "Done: ${LOCAL_PCAP}"
