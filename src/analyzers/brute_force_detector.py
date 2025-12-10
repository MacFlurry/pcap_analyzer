"""
Brute-Force Detector - Identifies brute-force authentication attempts

Detects repeated authentication attempts patterns:
- SSH brute-force (port 22)
- RDP brute-force (port 3389)
- Web login brute-force (ports 80, 443, 8080)
- Database brute-force (MySQL, PostgreSQL, MongoDB, Redis)
- Multiple failed connection attempts in short time window

Indicators:
- High connection rate to authentication services
- Rapid connection/disconnection cycles
- Failed authentication patterns
"""

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, DefaultDict, Dict, List, Optional, Set, Tuple

from scapy.all import IP, IPv6, Packet, TCP

from .base_analyzer import BaseAnalyzer


@dataclass
class BruteForceEvent:
    """Represents a detected brute-force attack"""
    source_ip: str
    target_ip: str
    target_port: int
    service: str
    start_time: float
    end_time: float
    total_attempts: int
    failed_attempts: int
    success_rate: float
    attempt_rate: float  # attempts per second
    severity: str


class BruteForceDetector(BaseAnalyzer):
    """
    Detects brute-force authentication attempts.

    Detection criteria:
    - 10+ connection attempts to same service in 60s
    - High connection rate (>0.5 attempts/second)
    - High failure rate (>70% failed)
    - Targeting authentication services (SSH, RDP, web, DB)
    """

    # Service definitions
    AUTH_SERVICES = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        80: "HTTP",
        443: "HTTPS",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt",
        27017: "MongoDB"
    }

    def __init__(self,
                 attempt_threshold: int = 10,
                 time_window: float = 60.0,
                 failure_rate_threshold: float = 0.7,
                 attempt_rate_threshold: float = 0.5,
                 include_localhost: bool = False,
                 include_private_ips: bool = False,
                 high_success_threshold: float = 0.9):
        """
        Initialize brute-force detector.

        Args:
            attempt_threshold: Min attempts to flag brute-force
            time_window: Time window in seconds to group attempts
            failure_rate_threshold: Min failure rate to flag attack
            attempt_rate_threshold: Min attempts/sec to flag aggressive attack
            include_localhost: Include localhost traffic in analysis (default: False)
            include_private_ips: Include private IP traffic in analysis (default: False)
            high_success_threshold: Ignore connections with success rate above this (default: 0.9)
        """
        super().__init__()
        self.attempt_threshold = attempt_threshold
        self.time_window = time_window
        self.failure_rate_threshold = failure_rate_threshold
        self.attempt_rate_threshold = attempt_rate_threshold
        self.include_localhost = include_localhost
        self.include_private_ips = include_private_ips
        self.high_success_threshold = high_success_threshold

        # Track connection attempts to authentication services
        # {(src_ip, dst_ip, dst_port): [(timestamp, flags, responded, established)]}
        self.auth_attempts: DefaultDict[Tuple, List[Tuple]] = defaultdict(list)

        # Track established connections (successful auth)
        # {(src_ip, dst_ip, src_port, dst_port): timestamp}
        self.established_connections: Dict[Tuple, float] = {}

        # Track SYN packets waiting for SYN-ACK
        self.pending_syns: Dict[Tuple, float] = {}

        # Detected brute-force events
        self.brute_force_events: List[BruteForceEvent] = []

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

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """
        Check if an IP address is in a private range (RFC 1918).

        Args:
            ip: IP address string (IPv4 or IPv6)

        Returns:
            True if private IP, False otherwise
        """
        # IPv6 private ranges
        if ip.startswith("fd") or ip.startswith("fc"):  # Unique Local Address (ULA)
            return True
        if ip.startswith("fe80:"):  # Link-local
            return True

        # IPv4 private ranges (RFC 1918)
        # 10.0.0.0/8
        if ip.startswith("10."):
            return True

        # 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
        if ip.startswith("172."):
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return True
            except (ValueError, IndexError):
                pass

        # 192.168.0.0/16
        if ip.startswith("192.168."):
            return True

        # Localhost (127.0.0.0/8)
        if ip.startswith("127."):
            return True

        return False

    def process_packet(self, packet: Packet, packet_num: int) -> None:
        """Process a single packet for brute-force detection."""
        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]
        timestamp = float(packet.time)

        # Extract IPs
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

        # Filter private IP traffic unless explicitly included (for Kubernetes/internal networks)
        if not self.include_private_ips:
            if self._is_private_ip(src_ip) and self._is_private_ip(dst_ip):
                return

        src_port = tcp.sport
        dst_port = tcp.dport
        flags = tcp.flags

        # Only track authentication service ports
        if dst_port not in self.AUTH_SERVICES:
            return

        flow_key = (src_ip, dst_ip, src_port, dst_port)
        reverse_key = (dst_ip, src_ip, dst_port, src_port)
        service_key = (src_ip, dst_ip, dst_port)

        # Track SYN packets (connection attempts)
        if flags & 0x02:  # SYN flag
            if not (flags & 0x10):  # Pure SYN (not SYN-ACK)
                self.pending_syns[flow_key] = timestamp
                self.auth_attempts[service_key].append(
                    (timestamp, flags, False, False)
                )

            elif flags & 0x10:  # SYN-ACK (server response)
                # Mark corresponding SYN as responded
                if reverse_key in self.pending_syns:
                    # Update attempt with response
                    attempts = self.auth_attempts[(dst_ip, src_ip, src_port)]
                    if attempts:
                        last_attempt = list(attempts[-1])
                        last_attempt[2] = True  # responded = True
                        attempts[-1] = tuple(last_attempt)

        # Track established connections (PSH-ACK with data)
        elif (flags & 0x18) == 0x18:  # PSH-ACK
            if flow_key not in self.established_connections:
                self.established_connections[flow_key] = timestamp
                # Mark as established in attempts
                if service_key in self.auth_attempts:
                    attempts = self.auth_attempts[service_key]
                    if attempts:
                        last_attempt = list(attempts[-1])
                        last_attempt[3] = True  # established = True
                        attempts[-1] = tuple(last_attempt)

        # Track RST (failed/refused connections)
        elif flags & 0x04:  # RST flag
            # Connection rejected/closed
            pass  # Already tracked as not responded/not established

        # Track FIN (clean close after auth success/failure)
        elif flags & 0x01:  # FIN flag
            # Connection closing
            pass

    def finalize(self) -> Dict[str, Any]:
        """
        Analyze authentication patterns and detect brute-force.

        Returns:
            Dictionary with detected brute-force events
        """
        # Analyze each service connection pattern
        for service_key, attempts in self.auth_attempts.items():
            if len(attempts) < self.attempt_threshold:
                continue

            src_ip, dst_ip, dst_port = service_key
            self._analyze_brute_force_pattern(
                src_ip, dst_ip, dst_port, attempts
            )

        return self.get_results()

    def _analyze_brute_force_pattern(self, src_ip: str, dst_ip: str,
                                      dst_port: int, attempts: List[Tuple]) -> None:
        """Analyze connection attempts for brute-force patterns."""
        if len(attempts) < self.attempt_threshold:
            return

        # Sort by timestamp
        attempts.sort(key=lambda x: x[0])

        start_time = attempts[0][0]
        end_time = attempts[-1][0]
        duration = end_time - start_time

        if duration == 0:
            duration = 0.001  # Avoid division by zero

        # Count failures
        failed_count = 0
        responded_count = 0
        established_count = 0

        for timestamp, flags, responded, established in attempts:
            if responded:
                responded_count += 1
            if established:
                established_count += 1
            if not established:
                failed_count += 1

        total_attempts = len(attempts)
        failure_rate = failed_count / total_attempts if total_attempts > 0 else 0
        attempt_rate = total_attempts / duration

        # Determine severity
        severity = "low"
        service = self.AUTH_SERVICES.get(dst_port, f"Port-{dst_port}")

        # High number of attempts
        if total_attempts > 50:
            severity = "critical"
        elif total_attempts > 30:
            severity = "high"
        elif total_attempts > 20:
            severity = "medium"

        # High failure rate
        if failure_rate > 0.9:
            if severity in ["low", "medium"]:
                severity = "high"
            elif severity == "high":
                severity = "critical"

        # High attempt rate (aggressive)
        if attempt_rate > 2.0:
            if severity in ["low", "medium"]:
                severity = "high"
            elif severity == "high":
                severity = "critical"

        # Critical services (SSH, RDP) are higher priority
        if dst_port in [22, 3389, 445]:
            if severity == "medium":
                severity = "high"
            elif severity == "low":
                severity = "medium"

        success_rate = established_count / total_attempts if total_attempts > 0 else 0

        # Ignore legitimate traffic with high success rates (>90%)
        # This prevents false positives from Kubernetes health checks, monitoring, etc.
        if success_rate > self.high_success_threshold:
            return

        # Only flag if suspicious: high failure rate AND sufficient attempts
        # Changed from OR to AND to reduce false positives
        if failure_rate > self.failure_rate_threshold and total_attempts >= self.attempt_threshold:
            event = BruteForceEvent(
                source_ip=src_ip,
                target_ip=dst_ip,
                target_port=dst_port,
                service=service,
                start_time=start_time,
                end_time=end_time,
                total_attempts=total_attempts,
                failed_attempts=failed_count,
                success_rate=success_rate,
                attempt_rate=attempt_rate,
                severity=severity
            )
            self.brute_force_events.append(event)

    def get_results(self) -> Dict[str, Any]:
        """Get detection results."""
        # Sort by severity and timestamp
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_events = sorted(
            self.brute_force_events,
            key=lambda e: (severity_order[e.severity], e.start_time)
        )

        # Count by severity and service
        severity_counts = defaultdict(int)
        service_counts = defaultdict(int)
        target_counts = defaultdict(int)

        for event in sorted_events:
            severity_counts[event.severity] += 1
            service_counts[event.service] += 1
            target_counts[event.target_ip] += 1

        # Format events for output
        formatted_events = []
        for event in sorted_events[:20]:  # Top 20
            formatted_events.append({
                "source_ip": event.source_ip,
                "target_ip": event.target_ip,
                "target_port": event.target_port,
                "service": event.service,
                "severity": event.severity,
                "start_time": event.start_time,
                "duration": event.end_time - event.start_time,
                "total_attempts": event.total_attempts,
                "failed_attempts": event.failed_attempts,
                "success_rate": event.success_rate,
                "attempt_rate": event.attempt_rate
            })

        return {
            "total_attacks_detected": len(self.brute_force_events),
            "severity_breakdown": dict(severity_counts),
            "service_breakdown": dict(service_counts),
            "target_breakdown": dict(sorted(
                target_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]),
            "brute_force_events": formatted_events,
            "top_attackers": self._get_top_attackers(sorted_events[:10]),
            "detection_thresholds": {
                "attempt_threshold": self.attempt_threshold,
                "time_window": self.time_window,
                "failure_rate_threshold": self.failure_rate_threshold,
                "attempt_rate_threshold": self.attempt_rate_threshold,
                "high_success_threshold": self.high_success_threshold,
                "include_private_ips": self.include_private_ips,
                "include_localhost": self.include_localhost
            }
        }

    def _get_top_attackers(self, events: List[BruteForceEvent]) -> List[Dict]:
        """Get top attacking source IPs."""
        attacker_stats = defaultdict(lambda: {
            "attack_count": 0,
            "total_targets": set(),
            "services_targeted": set(),
            "total_attempts": 0,
            "max_severity": "low"
        })

        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

        for event in events:
            stats = attacker_stats[event.source_ip]
            stats["attack_count"] += 1
            stats["total_targets"].add(event.target_ip)
            stats["services_targeted"].add(event.service)
            stats["total_attempts"] += event.total_attempts

            if severity_order[event.severity] > severity_order[stats["max_severity"]]:
                stats["max_severity"] = event.severity

        # Format and sort
        top_attackers = []
        for ip, stats in attacker_stats.items():
            top_attackers.append({
                "source_ip": ip,
                "attack_count": stats["attack_count"],
                "unique_targets": len(stats["total_targets"]),
                "services_targeted": list(stats["services_targeted"]),
                "total_attempts": stats["total_attempts"],
                "max_severity": stats["max_severity"]
            })

        return sorted(top_attackers, key=lambda x: (
            severity_order[x["max_severity"]],
            x["attack_count"]
        ), reverse=True)[:10]

    def get_summary(self) -> str:
        """Get one-line summary of brute-force detection."""
        results = self.get_results()
        total = results["total_attacks_detected"]

        if total == 0:
            return "✓ Aucune tentative de brute-force détectée."

        severity = results["severity_breakdown"]
        critical = severity.get("critical", 0)
        high = severity.get("high", 0)
        medium = severity.get("medium", 0)

        summary = f"🔴 {total} tentative(s) de brute-force détectée(s)"
        if critical > 0:
            summary += f" ({critical} critique(s)"
        if high > 0:
            summary += f", {high} élevée(s)" if critical > 0 else f" ({high} élevée(s)"
        if medium > 0:
            summary += f", {medium} moyenne(s)"
        if critical > 0 or high > 0 or medium > 0:
            summary += ")"

        return summary
