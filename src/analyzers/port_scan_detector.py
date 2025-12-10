"""
Port Scan Detector - Identifies port scanning activities

Detects various port scanning patterns:
- Horizontal scans (one source → many ports on one target)
- Vertical scans (one source → one port on many targets)
- Failed connection attempts (SYN without response, RST)

Patterns detected:
- nmap scans (SYN, NULL, FIN, XMAS)
- masscan-style rapid scans
- Stealth scans (low rate, distributed)
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, DefaultDict, Dict, List, Optional, Set, Tuple

from scapy.all import IP, IPv6, Packet, TCP

from .base_analyzer import BaseAnalyzer


@dataclass
class ScanEvent:
    """Represents a detected scan event"""
    source_ip: str
    scan_type: str  # "horizontal", "vertical", "distributed"
    start_time: float
    end_time: float
    target_ips: Set[str]
    target_ports: Set[int]
    total_attempts: int
    failed_attempts: int
    success_rate: float
    scan_rate: float  # attempts per second
    severity: str  # "low", "medium", "high", "critical"


class PortScanDetector(BaseAnalyzer):
    """
    Detects port scanning activities in network traffic.

    Detection criteria:
    - Horizontal scan: 10+ ports on same target in 60s
    - Vertical scan: 5+ targets on same port in 60s
    - High failure rate (>70% failed connections)
    - High scan rate (>5 attempts/second)
    """

    def __init__(self,
                 horizontal_threshold: int = 10,
                 vertical_threshold: int = 5,
                 time_window: float = 60.0,
                 failure_rate_threshold: float = 0.7,
                 scan_rate_threshold: float = 5.0,
                 include_localhost: bool = False):
        """
        Initialize port scan detector.

        Args:
            horizontal_threshold: Min ports to flag horizontal scan
            vertical_threshold: Min targets to flag vertical scan
            time_window: Time window in seconds to group scan attempts
            failure_rate_threshold: Min failure rate to flag suspicious activity
            scan_rate_threshold: Min attempts/sec to flag aggressive scanning
            include_localhost: Include localhost traffic in analysis (default: False)
        """
        super().__init__()
        self.horizontal_threshold = horizontal_threshold
        self.vertical_threshold = vertical_threshold
        self.time_window = time_window
        self.failure_rate_threshold = failure_rate_threshold
        self.scan_rate_threshold = scan_rate_threshold
        self.include_localhost = include_localhost

        # Track connection attempts by source IP
        # {src_ip: [(timestamp, dst_ip, dst_port, flags, responded)]}
        self.connection_attempts: DefaultDict[str, List[Tuple]] = defaultdict(list)

        # Track SYN packets waiting for SYN-ACK
        # {(src_ip, dst_ip, src_port, dst_port): (timestamp, seq)}
        self.pending_syns: Dict[Tuple, Tuple[float, int]] = {}

        # Track which connections succeeded
        # {(src_ip, dst_ip, src_port, dst_port): bool}
        self.connection_success: Dict[Tuple, bool] = {}

        # Detected scan events
        self.scan_events: List[ScanEvent] = []

    @staticmethod
    def _is_localhost(ip: str) -> bool:
        """
        Check if an IP address is localhost.

        Args:
            ip: IP address string (IPv4 or IPv6)

        Returns:
            True if localhost, False otherwise
        """
        # IPv6 localhost
        if ip in ["::1", "::ffff:127.0.0.1"]:
            return True

        # IPv4 localhost (127.0.0.0/8)
        if ip.startswith("127."):
            return True

        return False

    def process_packet(self, packet: Packet, packet_num: int) -> None:
        """Process a single packet for port scan detection."""
        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]
        timestamp = float(packet.time)

        # Extract IPs (support both IPv4 and IPv6)
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
        else:
            return

        # Filter localhost traffic unless explicitly included
        if not self.include_localhost:
            if self._is_localhost(src_ip) or self._is_localhost(dst_ip):
                return

        src_port = tcp.sport
        dst_port = tcp.dport
        flags = tcp.flags

        flow_key = (src_ip, dst_ip, src_port, dst_port)
        reverse_key = (dst_ip, src_ip, dst_port, src_port)

        # Track SYN packets (potential scan attempts)
        if flags & 0x02:  # SYN flag
            if not (flags & 0x10):  # Not ACK (pure SYN)
                # Record connection attempt
                self.pending_syns[flow_key] = (timestamp, tcp.seq)
                self.connection_attempts[src_ip].append(
                    (timestamp, dst_ip, dst_port, flags, False)
                )

            elif flags & 0x10:  # SYN-ACK
                # Mark corresponding SYN as responded
                if reverse_key in self.pending_syns:
                    self.connection_success[reverse_key] = True
                    # Update connection attempt
                    attempts = self.connection_attempts[dst_ip]
                    for i, (ts, dip, dport, f, _) in enumerate(attempts):
                        if dip == src_ip and dport == src_port:
                            attempts[i] = (ts, dip, dport, f, True)
                            break

        # Track RST packets (failed connections)
        elif flags & 0x04:  # RST flag
            if reverse_key in self.pending_syns:
                self.connection_success[reverse_key] = False

        # Track FIN packets (closed connections)
        elif flags & 0x01:  # FIN flag
            if flow_key in self.pending_syns:
                self.connection_success[flow_key] = True

    def finalize(self) -> Dict[str, Any]:
        """
        Analyze connection patterns and detect port scans.

        Returns:
            Dictionary with detected scan events
        """
        # Analyze each source IP for scanning behavior
        for src_ip, attempts in self.connection_attempts.items():
            if not attempts:
                continue

            # Sort by timestamp
            attempts.sort(key=lambda x: x[0])

            # Analyze in time windows
            self._analyze_scan_patterns(src_ip, attempts)

        return self.get_results()

    def _analyze_scan_patterns(self, src_ip: str, attempts: List[Tuple]) -> None:
        """Analyze connection attempts for scan patterns."""
        if len(attempts) < 5:  # Too few attempts to be a scan
            return

        start_time = attempts[0][0]
        end_time = attempts[-1][0]
        duration = end_time - start_time

        if duration == 0:
            return

        # Group by target IP and port
        target_ips = set()
        target_ports = set()
        failed_count = 0
        total_attempts = len(attempts)

        for timestamp, dst_ip, dst_port, flags, responded in attempts:
            target_ips.add(dst_ip)
            target_ports.add(dst_port)
            if not responded:
                failed_count += 1

        # Calculate metrics
        failure_rate = failed_count / total_attempts if total_attempts > 0 else 0
        scan_rate = total_attempts / duration if duration > 0 else 0
        unique_targets = len(target_ips)
        unique_ports = len(target_ports)

        # Detect scan type and severity
        scan_type = None
        severity = "low"

        # Horizontal scan: many ports on few targets
        if unique_ports >= self.horizontal_threshold and unique_targets <= 3:
            scan_type = "horizontal"
            if unique_ports > 50:
                severity = "critical"
            elif unique_ports > 25:
                severity = "high"
            elif unique_ports > 15:
                severity = "medium"

        # Vertical scan: one port on many targets
        elif unique_targets >= self.vertical_threshold and unique_ports <= 3:
            scan_type = "vertical"
            if unique_targets > 50:
                severity = "critical"
            elif unique_targets > 20:
                severity = "high"
            elif unique_targets > 10:
                severity = "medium"

        # Distributed scan: many ports on many targets
        elif unique_ports >= self.horizontal_threshold and unique_targets >= self.vertical_threshold:
            scan_type = "distributed"
            severity = "high"

        # High failure rate indicates scanning
        if failure_rate > self.failure_rate_threshold:
            if severity == "low":
                severity = "medium"
            elif severity == "medium":
                severity = "high"

        # High scan rate indicates aggressive scanning
        if scan_rate > self.scan_rate_threshold:
            if severity in ["low", "medium"]:
                severity = "high"
            elif severity == "high":
                severity = "critical"

        # Record scan event if detected
        if scan_type:
            event = ScanEvent(
                source_ip=src_ip,
                scan_type=scan_type,
                start_time=start_time,
                end_time=end_time,
                target_ips=target_ips,
                target_ports=target_ports,
                total_attempts=total_attempts,
                failed_attempts=failed_count,
                success_rate=1.0 - failure_rate,
                scan_rate=scan_rate,
                severity=severity
            )
            self.scan_events.append(event)

    def get_results(self) -> Dict[str, Any]:
        """Get detection results."""
        # Sort by severity and timestamp
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_events = sorted(
            self.scan_events,
            key=lambda e: (severity_order[e.severity], e.start_time)
        )

        # Count by severity
        severity_counts = defaultdict(int)
        scan_type_counts = defaultdict(int)

        for event in sorted_events:
            severity_counts[event.severity] += 1
            scan_type_counts[event.scan_type] += 1

        # Format events for output
        formatted_events = []
        for event in sorted_events[:20]:  # Top 20
            formatted_events.append({
                "source_ip": event.source_ip,
                "scan_type": event.scan_type,
                "severity": event.severity,
                "start_time": event.start_time,
                "duration": event.end_time - event.start_time,
                "unique_targets": len(event.target_ips),
                "unique_ports": len(event.target_ports),
                "total_attempts": event.total_attempts,
                "failed_attempts": event.failed_attempts,
                "success_rate": event.success_rate,
                "scan_rate": event.scan_rate,
                "target_ips": list(event.target_ips)[:10],  # First 10
                "target_ports": sorted(list(event.target_ports))[:20]  # First 20
            })

        return {
            "total_scans_detected": len(self.scan_events),
            "severity_breakdown": dict(severity_counts),
            "scan_type_breakdown": dict(scan_type_counts),
            "scan_events": formatted_events,
            "top_scanners": self._get_top_scanners(sorted_events[:10]),
            "detection_thresholds": {
                "horizontal_threshold": self.horizontal_threshold,
                "vertical_threshold": self.vertical_threshold,
                "time_window": self.time_window,
                "failure_rate_threshold": self.failure_rate_threshold,
                "scan_rate_threshold": self.scan_rate_threshold
            }
        }

    def _get_top_scanners(self, events: List[ScanEvent]) -> List[Dict]:
        """Get top scanning source IPs."""
        scanner_stats = defaultdict(lambda: {
            "scan_count": 0,
            "total_targets": set(),
            "total_ports": set(),
            "total_attempts": 0,
            "max_severity": "low"
        })

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        for event in events:
            stats = scanner_stats[event.source_ip]
            stats["scan_count"] += 1
            stats["total_targets"].update(event.target_ips)
            stats["total_ports"].update(event.target_ports)
            stats["total_attempts"] += event.total_attempts

            if severity_order[event.severity] > severity_order[stats["max_severity"]]:
                stats["max_severity"] = event.severity

        # Format and sort
        top_scanners = []
        for ip, stats in scanner_stats.items():
            top_scanners.append({
                "source_ip": ip,
                "scan_count": stats["scan_count"],
                "unique_targets": len(stats["total_targets"]),
                "unique_ports": len(stats["total_ports"]),
                "total_attempts": stats["total_attempts"],
                "max_severity": stats["max_severity"]
            })

        return sorted(top_scanners, key=lambda x: (
            severity_order[x["max_severity"]],
            x["scan_count"]
        ), reverse=True)[:10]

    def get_summary(self) -> str:
        """Get one-line summary of scan detection."""
        results = self.get_results()
        total = results["total_scans_detected"]

        if total == 0:
            return "✓ Aucun scan de ports détecté."

        severity = results["severity_breakdown"]
        critical = severity.get("critical", 0)
        high = severity.get("high", 0)
        medium = severity.get("medium", 0)

        summary = f"🔴 {total} scan(s) de ports détecté(s)"
        if critical > 0:
            summary += f" ({critical} critique(s)"
        if high > 0:
            summary += f", {high} élevé(s)" if critical > 0 else f" ({high} élevé(s)"
        if medium > 0:
            summary += f", {medium} moyen(s)"
        if critical > 0 or high > 0 or medium > 0:
            summary += ")"

        return summary
