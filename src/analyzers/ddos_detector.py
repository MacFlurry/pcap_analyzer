"""
DDoS Detector - Identifies Distributed Denial of Service attacks

Detects various DDoS attack patterns:
- SYN flood (massive SYN packets without completing handshake)
- UDP flood (high volume UDP traffic to overwhelm target)
- ICMP flood (ping flood attacks)
- HTTP flood (application layer DDoS)
- Amplification attacks (DNS, NTP, SSDP)

Indicators:
- Abnormally high packet rate from single or multiple sources
- High ratio of SYN to SYN-ACK packets
- Incomplete TCP handshakes
- Traffic volume spikes
- Many sources targeting single victim
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, DefaultDict, Dict, List, Optional, Set, Tuple

from scapy.all import ICMP, IP, TCP, UDP, IPv6, Packet

from .base_analyzer import BaseAnalyzer


@dataclass
class DDoSEvent:
    """Represents a detected DDoS attack"""

    attack_type: str  # "syn_flood", "udp_flood", "icmp_flood", "amplification"
    target_ip: str
    target_port: Optional[int]
    start_time: float
    end_time: float
    source_count: int  # Number of unique sources
    packet_count: int
    bytes_total: int
    packets_per_second: float
    severity: str  # "low", "medium", "high", "critical"
    top_sources: list[str]  # Top attacking IPs


class DDoSDetector(BaseAnalyzer):
    """
    Detects Distributed Denial of Service (DDoS) attacks.

    Detection criteria:
    - SYN flood: 100+ SYN packets/sec to same target, <10% SYN-ACK response
    - UDP flood: 500+ UDP packets/sec to same target
    - ICMP flood: 100+ ICMP packets/sec to same target
    - Amplification: Small request, large response (ratio >10:1)
    """

    def __init__(
        self,
        syn_flood_threshold: int = 100,  # SYN packets/sec
        udp_flood_threshold: int = 500,  # UDP packets/sec
        icmp_flood_threshold: int = 100,  # ICMP packets/sec
        time_window: float = 10.0,  # Analysis window in seconds
        syn_ack_ratio_threshold: float = 0.1,  # Max SYN-ACK ratio for SYN flood
        include_localhost: bool = False,
    ):
        """
        Initialize DDoS detector.

        Args:
            syn_flood_threshold: Min SYN packets/sec to flag SYN flood
            udp_flood_threshold: Min UDP packets/sec to flag UDP flood
            icmp_flood_threshold: Min ICMP packets/sec to flag ICMP flood
            time_window: Time window for rate calculation
            syn_ack_ratio_threshold: Max ratio of SYN-ACK to SYN for flood detection
            include_localhost: Include localhost traffic (default: False)
        """
        super().__init__()
        self.syn_flood_threshold = syn_flood_threshold
        self.udp_flood_threshold = udp_flood_threshold
        self.icmp_flood_threshold = icmp_flood_threshold
        self.time_window = time_window
        self.syn_ack_ratio_threshold = syn_ack_ratio_threshold
        self.include_localhost = include_localhost

        # Track packets by target IP and time windows
        # {(target_ip, time_slot): {packet_type: count, sources: set()}}
        self.traffic_windows: DefaultDict[tuple, dict] = defaultdict(
            lambda: {
                "syn": 0,
                "syn_ack": 0,
                "udp": 0,
                "icmp": 0,
                "bytes": 0,
                "sources": set(),
                "start_time": 0,
                "packets": [],
            }
        )

        # Track SYN/SYN-ACK for specific flows
        self.syn_tracker: DefaultDict[tuple, dict] = defaultdict(
            lambda: {"syn_count": 0, "syn_ack_count": 0, "sources": set()}
        )

        # Detected DDoS events
        self.ddos_events: list[DDoSEvent] = []

    @staticmethod
    def _is_localhost(ip: str) -> bool:
        """Check if an IP address is localhost."""
        if ip in ["::1", "::ffff:127.0.0.1"]:
            return True
        if ip.startswith("127."):
            return True
        return False

    def _get_time_slot(self, timestamp: float) -> int:
        """Get time slot for timestamp based on time window."""
        return int(timestamp / self.time_window)

    def process_packet(self, packet: Packet, packet_num: int) -> None:
        """Process a single packet for DDoS detection."""
        timestamp = float(packet.time)
        time_slot = self._get_time_slot(timestamp)

        # Extract IPs
        src_ip = None
        dst_ip = None

        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            return

        # Filter localhost unless explicitly included
        if not self.include_localhost:
            if self._is_localhost(src_ip) or self._is_localhost(dst_ip):
                return

        packet_size = len(packet)

        # Track TCP SYN/SYN-ACK patterns
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            dst_port = tcp.dport
            flags = tcp.flags

            window_key = (dst_ip, time_slot)

            # SYN flag (connection attempt)
            if flags & 0x02:  # SYN
                if not (flags & 0x10):  # Pure SYN (not SYN-ACK)
                    self.traffic_windows[window_key]["syn"] += 1
                    self.traffic_windows[window_key]["sources"].add(src_ip)
                    self.traffic_windows[window_key]["bytes"] += packet_size
                    if self.traffic_windows[window_key]["start_time"] == 0:
                        self.traffic_windows[window_key]["start_time"] = timestamp

                    # Track per target-port
                    flow_key = (dst_ip, dst_port)
                    self.syn_tracker[flow_key]["syn_count"] += 1
                    self.syn_tracker[flow_key]["sources"].add(src_ip)

                elif flags & 0x10:  # SYN-ACK (server response)
                    self.traffic_windows[window_key]["syn_ack"] += 1

                    # Track SYN-ACK responses
                    flow_key = (src_ip, tcp.sport)  # Source is now the server
                    self.syn_tracker[flow_key]["syn_ack_count"] += 1

        # Track UDP traffic
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            dst_port = udp.dport

            window_key = (dst_ip, time_slot)
            self.traffic_windows[window_key]["udp"] += 1
            self.traffic_windows[window_key]["sources"].add(src_ip)
            self.traffic_windows[window_key]["bytes"] += packet_size
            if self.traffic_windows[window_key]["start_time"] == 0:
                self.traffic_windows[window_key]["start_time"] = timestamp

        # Track ICMP traffic
        elif packet.haslayer(ICMP):
            window_key = (dst_ip, time_slot)
            self.traffic_windows[window_key]["icmp"] += 1
            self.traffic_windows[window_key]["sources"].add(src_ip)
            self.traffic_windows[window_key]["bytes"] += packet_size
            if self.traffic_windows[window_key]["start_time"] == 0:
                self.traffic_windows[window_key]["start_time"] = timestamp

    def finalize(self) -> dict[str, Any]:
        """
        Analyze traffic patterns and detect DDoS attacks.

        Returns:
            Dictionary with detected DDoS events
        """
        # Analyze SYN flood patterns
        self._detect_syn_flood()

        # Analyze UDP flood patterns
        self._detect_udp_flood()

        # Analyze ICMP flood patterns
        self._detect_icmp_flood()

        return self.get_results()

    def _detect_syn_flood(self) -> None:
        """Detect SYN flood attacks."""
        for flow_key, stats in self.syn_tracker.items():
            target_ip, target_port = flow_key
            syn_count = stats["syn_count"]
            syn_ack_count = stats["syn_ack_count"]
            sources = stats["sources"]

            # Find time window for this flow
            start_time = None
            end_time = None
            total_bytes = 0

            for window_key, window_data in self.traffic_windows.items():
                if window_key[0] == target_ip:
                    if start_time is None or window_data["start_time"] < start_time:
                        start_time = window_data["start_time"]
                    end_time = max(end_time or 0, window_data["start_time"] + self.time_window)
                    total_bytes += window_data["bytes"]

            if start_time is None:
                continue

            duration = end_time - start_time if end_time else self.time_window
            if duration == 0:
                duration = 0.001

            packets_per_sec = syn_count / duration

            # Check for SYN flood indicators
            syn_ack_ratio = syn_ack_count / syn_count if syn_count > 0 else 1.0

            if packets_per_sec >= self.syn_flood_threshold and syn_ack_ratio <= self.syn_ack_ratio_threshold:
                # Determine severity
                severity = self._calculate_severity(packets_per_sec, len(sources), syn_count, attack_type="syn_flood")

                event = DDoSEvent(
                    attack_type="syn_flood",
                    target_ip=target_ip,
                    target_port=target_port,
                    start_time=start_time,
                    end_time=end_time,
                    source_count=len(sources),
                    packet_count=syn_count,
                    bytes_total=total_bytes,
                    packets_per_second=packets_per_sec,
                    severity=severity,
                    top_sources=sorted(sources, key=lambda x: x)[:10],
                )
                self.ddos_events.append(event)

    def _detect_udp_flood(self) -> None:
        """Detect UDP flood attacks."""
        # Group by target IP
        target_stats = defaultdict(
            lambda: {"udp_count": 0, "sources": set(), "bytes": 0, "start_time": None, "end_time": None}
        )

        for window_key, window_data in self.traffic_windows.items():
            target_ip, time_slot = window_key
            udp_count = window_data["udp"]

            if udp_count > 0:
                target_stats[target_ip]["udp_count"] += udp_count
                target_stats[target_ip]["sources"].update(window_data["sources"])
                target_stats[target_ip]["bytes"] += window_data["bytes"]

                start = window_data["start_time"]
                if target_stats[target_ip]["start_time"] is None or start < target_stats[target_ip]["start_time"]:
                    target_stats[target_ip]["start_time"] = start

                target_stats[target_ip]["end_time"] = max(
                    target_stats[target_ip]["end_time"] or 0, start + self.time_window
                )

        # Check for UDP floods
        for target_ip, stats in target_stats.items():
            udp_count = stats["udp_count"]
            start_time = stats["start_time"]
            end_time = stats["end_time"]

            if start_time is None:
                continue

            duration = end_time - start_time if end_time else self.time_window
            if duration == 0:
                duration = 0.001

            packets_per_sec = udp_count / duration

            if packets_per_sec >= self.udp_flood_threshold:
                severity = self._calculate_severity(
                    packets_per_sec, len(stats["sources"]), udp_count, attack_type="udp_flood"
                )

                event = DDoSEvent(
                    attack_type="udp_flood",
                    target_ip=target_ip,
                    target_port=None,
                    start_time=start_time,
                    end_time=end_time,
                    source_count=len(stats["sources"]),
                    packet_count=udp_count,
                    bytes_total=stats["bytes"],
                    packets_per_second=packets_per_sec,
                    severity=severity,
                    top_sources=sorted(stats["sources"], key=lambda x: x)[:10],
                )
                self.ddos_events.append(event)

    def _detect_icmp_flood(self) -> None:
        """Detect ICMP flood attacks (ping flood)."""
        # Group by target IP
        target_stats = defaultdict(
            lambda: {"icmp_count": 0, "sources": set(), "bytes": 0, "start_time": None, "end_time": None}
        )

        for window_key, window_data in self.traffic_windows.items():
            target_ip, time_slot = window_key
            icmp_count = window_data["icmp"]

            if icmp_count > 0:
                target_stats[target_ip]["icmp_count"] += icmp_count
                target_stats[target_ip]["sources"].update(window_data["sources"])
                target_stats[target_ip]["bytes"] += window_data["bytes"]

                start = window_data["start_time"]
                if target_stats[target_ip]["start_time"] is None or start < target_stats[target_ip]["start_time"]:
                    target_stats[target_ip]["start_time"] = start

                target_stats[target_ip]["end_time"] = max(
                    target_stats[target_ip]["end_time"] or 0, start + self.time_window
                )

        # Check for ICMP floods
        for target_ip, stats in target_stats.items():
            icmp_count = stats["icmp_count"]
            start_time = stats["start_time"]
            end_time = stats["end_time"]

            if start_time is None:
                continue

            duration = end_time - start_time if end_time else self.time_window
            if duration == 0:
                duration = 0.001

            packets_per_sec = icmp_count / duration

            if packets_per_sec >= self.icmp_flood_threshold:
                severity = self._calculate_severity(
                    packets_per_sec, len(stats["sources"]), icmp_count, attack_type="icmp_flood"
                )

                event = DDoSEvent(
                    attack_type="icmp_flood",
                    target_ip=target_ip,
                    target_port=None,
                    start_time=start_time,
                    end_time=end_time,
                    source_count=len(stats["sources"]),
                    packet_count=icmp_count,
                    bytes_total=stats["bytes"],
                    packets_per_second=packets_per_sec,
                    severity=severity,
                    top_sources=sorted(stats["sources"], key=lambda x: x)[:10],
                )
                self.ddos_events.append(event)

    def _calculate_severity(
        self, packets_per_sec: float, source_count: int, total_packets: int, attack_type: str
    ) -> str:
        """Calculate attack severity based on multiple factors."""
        severity = "low"

        # Base severity on packet rate
        if attack_type == "syn_flood":
            if packets_per_sec > 1000:
                severity = "critical"
            elif packets_per_sec > 500:
                severity = "high"
            elif packets_per_sec > 200:
                severity = "medium"
        elif attack_type == "udp_flood":
            if packets_per_sec > 5000:
                severity = "critical"
            elif packets_per_sec > 2000:
                severity = "high"
            elif packets_per_sec > 1000:
                severity = "medium"
        elif attack_type == "icmp_flood":
            if packets_per_sec > 500:
                severity = "critical"
            elif packets_per_sec > 200:
                severity = "high"
            elif packets_per_sec > 100:
                severity = "medium"

        # Increase severity for distributed attacks
        if source_count > 100:
            if severity in ["low", "medium"]:
                severity = "high"
            elif severity == "high":
                severity = "critical"
        elif source_count > 50:
            if severity == "low":
                severity = "medium"

        # Very high packet counts are critical
        if total_packets > 10000:
            severity = "critical"

        return severity

    def get_results(self) -> dict[str, Any]:
        """Get detection results."""
        # Sort by severity and timestamp
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_events = sorted(self.ddos_events, key=lambda e: (severity_order[e.severity], e.start_time))

        # Count by severity and attack type
        severity_counts = defaultdict(int)
        attack_type_counts = defaultdict(int)
        target_counts = defaultdict(int)

        for event in sorted_events:
            severity_counts[event.severity] += 1
            attack_type_counts[event.attack_type] += 1
            target_counts[event.target_ip] += 1

        # Format events for output
        formatted_events = []
        for event in sorted_events[:20]:  # Top 20
            formatted_events.append(
                {
                    "attack_type": event.attack_type,
                    "target_ip": event.target_ip,
                    "target_port": event.target_port,
                    "severity": event.severity,
                    "start_time": event.start_time,
                    "duration": event.end_time - event.start_time,
                    "source_count": event.source_count,
                    "packet_count": event.packet_count,
                    "bytes_total": event.bytes_total,
                    "packets_per_second": event.packets_per_second,
                    "top_sources": event.top_sources[:5],
                }
            )

        return {
            "total_attacks_detected": len(self.ddos_events),
            "severity_breakdown": dict(severity_counts),
            "attack_type_breakdown": dict(attack_type_counts),
            "target_breakdown": dict(sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:10]),
            "ddos_events": formatted_events,
            "detection_thresholds": {
                "syn_flood_threshold": self.syn_flood_threshold,
                "udp_flood_threshold": self.udp_flood_threshold,
                "icmp_flood_threshold": self.icmp_flood_threshold,
                "time_window": self.time_window,
                "syn_ack_ratio_threshold": self.syn_ack_ratio_threshold,
            },
        }

    def get_summary(self) -> str:
        """Get one-line summary of DDoS detection."""
        results = self.get_results()
        total = results["total_attacks_detected"]

        if total == 0:
            return "✓ Aucune attaque DDoS détectée."

        severity = results["severity_breakdown"]
        critical = severity.get("critical", 0)
        high = severity.get("high", 0)

        attack_types = results["attack_type_breakdown"]
        type_str = ", ".join([f"{count} {atype}" for atype, count in attack_types.items()])

        summary = f"🔴 {total} attaque(s) DDoS détectée(s): {type_str}"
        if critical > 0 or high > 0:
            summary += f" ({critical} critique(s), {high} élevée(s))"

        return summary
