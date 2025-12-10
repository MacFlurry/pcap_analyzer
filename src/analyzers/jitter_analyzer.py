"""
Jitter Analyzer - RFC 3393 IPDV (Inter-Packet Delay Variation)

Analyzes jitter (delay variation) in packet flows, which is critical
for real-time applications like VoIP, video streaming, and gaming.

RFC 3393 defines jitter as:
  IPDV = |delay[i] - delay[i-1]|

Where delay[i] is the inter-arrival time between packets i and i-1.

High jitter indicators:
- Mean jitter > 30ms: Noticeable in VoIP
- Max jitter > 100ms: Significant quality degradation
- P95 jitter > 50ms: Frequent disruptions

References:
- RFC 3393: IP Packet Delay Variation Metric for IPPM
- ITU-T G.114: One-way transmission time
- RFC 3550: RTP (Real-time Transport Protocol)
"""

import statistics
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from scapy.all import IP, TCP, UDP, IPv6

# RFC 3393 jitter thresholds (in seconds)
JITTER_THRESHOLD_LOW = 0.030  # <30ms: Excellent
JITTER_THRESHOLD_MEDIUM = 0.050  # 30-50ms: Acceptable
JITTER_THRESHOLD_HIGH = 0.100  # >100ms: Poor


class JitterAnalyzer:
    """
    Analyzes Inter-Packet Delay Variation (IPDV) per RFC 3393.

    Tracks:
    - Per-flow jitter statistics
    - Global jitter across all flows
    - High jitter flow identification
    - Jitter percentiles (p50, p95, p99)
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset all counters and state."""
        self.flow_packets = defaultdict(list)  # Flow -> list of (timestamp, packet_num)
        self.flow_jitters = defaultdict(list)  # Flow -> list of jitter values
        self.all_jitters = []  # Global jitter values

    def analyze(self, packets: List) -> Dict[str, Any]:
        """
        Analyze jitter across all flows.

        Args:
            packets: List of scapy packets with timestamps

        Returns:
            Dictionary with jitter statistics
        """
        self.reset()

        # Group packets by flow and sort by timestamp
        for idx, packet in enumerate(packets):
            flow_key = self._get_flow_key(packet)
            if flow_key:
                timestamp = self._get_timestamp(packet)
                self.flow_packets[flow_key].append((timestamp, idx))

        # Calculate jitter for each flow
        for flow_key, timestamps in self.flow_packets.items():
            # Sort by timestamp (handle out-of-order packets)
            timestamps.sort(key=lambda x: x[0])

            # Calculate inter-packet delays
            delays = []
            for i in range(1, len(timestamps)):
                delay = timestamps[i][0] - timestamps[i - 1][0]
                delays.append(delay)

            # Calculate jitter (IPDV) = |delay[i] - delay[i-1]|
            jitters = []
            for i in range(1, len(delays)):
                jitter = abs(delays[i] - delays[i - 1])
                jitters.append(jitter)
                self.all_jitters.append(jitter)

            self.flow_jitters[flow_key] = jitters

        return self.get_results()

    def _get_flow_key(self, packet) -> Tuple:
        """Get flow identifier from packet."""
        if IP in packet and (TCP in packet or UDP in packet):
            ip = packet[IP]
            if TCP in packet:
                tcp_udp = packet[TCP]
                proto = "TCP"
            else:
                tcp_udp = packet[UDP]
                proto = "UDP"

            # 5-tuple: src_ip, src_port, dst_ip, dst_port, proto
            return (ip.src, tcp_udp.sport, ip.dst, tcp_udp.dport, proto)

        elif IPv6 in packet and (TCP in packet or UDP in packet):
            ip = packet[IPv6]
            if TCP in packet:
                tcp_udp = packet[TCP]
                proto = "TCP"
            else:
                tcp_udp = packet[UDP]
                proto = "UDP"

            return (ip.src, tcp_udp.sport, ip.dst, tcp_udp.dport, proto)

        return None

    def _get_timestamp(self, packet) -> float:
        """Get timestamp from packet."""
        return float(packet.time) if hasattr(packet, "time") else 0.0

    def _format_flow_key(self, flow_key: Tuple) -> str:
        """Format flow key as readable string."""
        src_ip, src_port, dst_ip, dst_port, proto = flow_key
        return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})"

    def get_results(self) -> Dict[str, Any]:
        """
        Get jitter analysis results.

        Returns:
            Dictionary with jitter statistics
        """
        flows_with_jitter = {}
        high_jitter_flows = []

        # Calculate per-flow statistics
        for flow_key, jitters in self.flow_jitters.items():
            if len(jitters) == 0:
                continue  # Need at least 3 packets for jitter calculation

            # Calculate statistics
            mean_jitter = statistics.mean(jitters)
            median_jitter = statistics.median(jitters)
            max_jitter = max(jitters)
            min_jitter = min(jitters)

            # Standard deviation (if enough samples)
            if len(jitters) > 1:
                stdev_jitter = statistics.stdev(jitters)
            else:
                stdev_jitter = 0.0

            # Percentiles
            sorted_jitters = sorted(jitters)
            p95_jitter = sorted_jitters[int(len(sorted_jitters) * 0.95)] if len(sorted_jitters) > 1 else max_jitter
            p99_jitter = sorted_jitters[int(len(sorted_jitters) * 0.99)] if len(sorted_jitters) > 1 else max_jitter

            flow_stats = {
                "packet_count": len(self.flow_packets[flow_key]),
                "jitter_samples": len(jitters),
                "mean_jitter": mean_jitter,
                "median_jitter": median_jitter,
                "p50_jitter": median_jitter,
                "p95_jitter": p95_jitter,
                "p99_jitter": p99_jitter,
                "min_jitter": min_jitter,
                "max_jitter": max_jitter,
                "stdev_jitter": stdev_jitter,
            }

            flow_key_str = self._format_flow_key(flow_key)
            flows_with_jitter[flow_key_str] = flow_stats

            # Identify high jitter flows
            if mean_jitter > JITTER_THRESHOLD_HIGH or p95_jitter > JITTER_THRESHOLD_HIGH:
                high_jitter_flows.append(
                    {
                        "flow": flow_key_str,
                        "mean_jitter": mean_jitter,
                        "max_jitter": max_jitter,
                        "p95_jitter": p95_jitter,
                        "severity": self._classify_jitter_severity(mean_jitter),
                    }
                )

        # Global statistics
        global_stats = {}
        if len(self.all_jitters) > 0:
            global_stats = {
                "total_jitter_measurements": len(self.all_jitters),
                "mean_jitter": statistics.mean(self.all_jitters),
                "median_jitter": statistics.median(self.all_jitters),
                "max_jitter": max(self.all_jitters),
                "min_jitter": min(self.all_jitters),
            }

            if len(self.all_jitters) > 1:
                global_stats["stdev_jitter"] = statistics.stdev(self.all_jitters)
                sorted_all = sorted(self.all_jitters)
                global_stats["p95_jitter"] = sorted_all[int(len(sorted_all) * 0.95)]
                global_stats["p99_jitter"] = sorted_all[int(len(sorted_all) * 0.99)]

        return {
            "total_flows": len(self.flow_packets),
            "flows_with_jitter": flows_with_jitter,
            "high_jitter_flows": high_jitter_flows,
            "global_statistics": global_stats,
        }

    def _classify_jitter_severity(self, mean_jitter: float) -> str:
        """Classify jitter severity based on RFC 3393 thresholds."""
        if mean_jitter < JITTER_THRESHOLD_LOW:
            return "low"
        elif mean_jitter < JITTER_THRESHOLD_MEDIUM:
            return "medium"
        elif mean_jitter < JITTER_THRESHOLD_HIGH:
            return "high"
        else:
            return "critical"
