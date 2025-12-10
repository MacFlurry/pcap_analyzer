#!/usr/bin/env python3
"""
C2 Beaconing Detector

Detects Command & Control (C2) beaconing patterns by analyzing:
1. Periodic communications (regular intervals)
2. Consistent payload sizes (beacon signatures)
3. Low-volume but frequent connections
4. Single destination repeated connections
5. Unusual timing patterns (regular check-ins)

C2 beacons are characterized by:
- Regular time intervals (heartbeat)
- Small, consistent packet sizes
- One-way or minimal bidirectional traffic
- Often to single suspicious destination

Author: PCAP Analyzer Team
Sprint: 11 (Advanced Threat Detection)
"""

from typing import Dict, Any, List, Tuple
from collections import defaultdict
from scapy.all import IP, TCP, UDP
from .base_analyzer import BaseAnalyzer
import statistics


class C2BeaconingDetector(BaseAnalyzer):
    """
    Detects C2 beaconing by analyzing timing patterns, payload consistency,
    and connection characteristics.
    """

    def __init__(self,
                 min_beacons: int = 10,
                 interval_tolerance: float = 0.3,
                 payload_size_tolerance: float = 0.2,
                 include_localhost: bool = False):
        """
        Initialize C2 Beaconing Detector.

        Args:
            min_beacons: Minimum number of beacons to consider pattern (default: 10)
            interval_tolerance: Tolerance for interval regularity (0.3 = 30% variance)
            payload_size_tolerance: Tolerance for payload size consistency (0.2 = 20%)
            include_localhost: Include localhost traffic in analysis (default: False)
        """
        super().__init__()
        self.min_beacons = min_beacons
        self.interval_tolerance = interval_tolerance
        self.payload_size_tolerance = payload_size_tolerance
        self.include_localhost = include_localhost

        # Track connections: (src_ip, dst_ip, dst_port) -> list of (timestamp, size)
        self.connections: Dict[Tuple[str, str, int], List[Tuple[float, int]]] = defaultdict(list)

        # Detected beaconing patterns
        self.beaconing_events: List[Dict[str, Any]] = []

    def process_packet(self, packet: Any, packet_num: int) -> None:
        """
        Process individual packet (not used - we use batch analyze instead).

        Args:
            packet: Scapy packet to process
            packet_num: Packet number in capture
        """
        pass  # Batch processing in analyze() method

    def analyze(self, packets: list) -> Dict[str, Any]:
        """
        Analyze packets for C2 beaconing patterns.

        Args:
            packets: List of scapy packets to analyze

        Returns:
            Dictionary containing beaconing analysis results
        """
        if not packets:
            return self._generate_results()

        # Collect connection data
        for pkt in packets:
            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            timestamp = float(pkt.time)

            # Skip localhost if configured
            if not self.include_localhost:
                if self._is_localhost(src_ip) or self._is_localhost(dst_ip):
                    continue

            # Track TCP and UDP connections
            if pkt.haslayer(TCP):
                dst_port = pkt[TCP].dport
                payload_size = len(bytes(pkt))
                conn_key = (src_ip, dst_ip, dst_port)
                self.connections[conn_key].append((timestamp, payload_size))

            elif pkt.haslayer(UDP):
                dst_port = pkt[UDP].dport
                payload_size = len(bytes(pkt))
                conn_key = (src_ip, dst_ip, dst_port)
                self.connections[conn_key].append((timestamp, payload_size))

        # Analyze connections for beaconing patterns
        for conn_key, packets_data in self.connections.items():
            if len(packets_data) >= self.min_beacons:
                self._analyze_connection_for_beaconing(conn_key, packets_data)

        return self._generate_results()

    def _analyze_connection_for_beaconing(
        self,
        conn_key: Tuple[str, str, int],
        packets_data: List[Tuple[float, int]]
    ):
        """
        Analyze a single connection for beaconing characteristics.

        Args:
            conn_key: (source_ip, dest_ip, dest_port)
            packets_data: List of (timestamp, payload_size) tuples
        """
        src_ip, dst_ip, dst_port = conn_key

        # Sort by timestamp
        packets_data.sort(key=lambda x: x[0])

        # Calculate intervals between packets
        intervals = []
        for i in range(1, len(packets_data)):
            interval = packets_data[i][0] - packets_data[i-1][0]
            intervals.append(interval)

        if not intervals:
            return

        # Check for regular intervals (beaconing characteristic)
        mean_interval = statistics.mean(intervals)

        # Skip very short intervals (< 1 second) - likely bulk traffic
        if mean_interval < 1.0:
            return

        # Calculate coefficient of variation (CV = std_dev / mean)
        if len(intervals) >= 2:
            std_dev = statistics.stdev(intervals)
            cv = std_dev / mean_interval if mean_interval > 0 else float('inf')
        else:
            cv = 0.0

        # Regular intervals have low CV (< tolerance)
        is_regular_interval = cv <= self.interval_tolerance

        # Check for consistent payload sizes
        payload_sizes = [size for _, size in packets_data]
        mean_size = statistics.mean(payload_sizes)

        if len(payload_sizes) >= 2:
            size_std_dev = statistics.stdev(payload_sizes)
            size_cv = size_std_dev / mean_size if mean_size > 0 else float('inf')
        else:
            size_cv = 0.0

        is_consistent_size = size_cv <= self.payload_size_tolerance

        # Beaconing indicators:
        # 1. Regular intervals (low CV)
        # 2. Consistent payload sizes
        # 3. Minimum number of packets
        # 4. Not too frequent (> 1 second intervals)
        beacon_score = 0
        indicators = []

        if is_regular_interval:
            beacon_score += 40
            indicators.append(f"regular_intervals (CV: {cv:.2f}, mean: {mean_interval:.2f}s)")

        if is_consistent_size:
            beacon_score += 30
            indicators.append(f"consistent_size (CV: {size_cv:.2f}, mean: {mean_size} bytes)")

        if len(packets_data) >= 20:
            beacon_score += 20
            indicators.append(f"high_packet_count ({len(packets_data)} packets)")

        # Check if destination is external
        if not self._is_internal(dst_ip):
            beacon_score += 10
            indicators.append("external_destination")

        # If score is high enough, consider it beaconing
        if beacon_score >= 60:
            # Determine severity based on characteristics
            severity = self._calculate_severity(
                beacon_score,
                mean_interval,
                len(packets_data),
                dst_ip
            )

            self.beaconing_events.append({
                'type': 'c2_beaconing',
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'destination_port': dst_port,
                'beacon_count': len(packets_data),
                'mean_interval_seconds': round(mean_interval, 2),
                'interval_regularity_cv': round(cv, 3),
                'mean_payload_size': int(mean_size),
                'payload_consistency_cv': round(size_cv, 3),
                'beacon_score': beacon_score,
                'indicators': indicators,
                'severity': severity,
                'description': f"Potential C2 beaconing detected: {len(packets_data)} beacons every {mean_interval:.1f}s to {dst_ip}:{dst_port}",
                'duration_seconds': packets_data[-1][0] - packets_data[0][0]
            })

    def _calculate_severity(
        self,
        beacon_score: int,
        interval: float,
        count: int,
        dst_ip: str
    ) -> str:
        """
        Calculate severity based on beaconing characteristics.

        Args:
            beacon_score: Calculated beacon score
            interval: Mean interval between beacons
            count: Number of beacons
            dst_ip: Destination IP

        Returns:
            Severity level: critical, high, medium, or low
        """
        # Higher score = higher severity
        if beacon_score >= 90:
            return 'critical'
        elif beacon_score >= 80:
            return 'high'
        elif beacon_score >= 70:
            return 'medium'
        else:
            return 'low'

    def _is_internal(self, ip: str) -> bool:
        """Check if IP is from internal network."""
        if ip.startswith('192.168.') or ip.startswith('10.'):
            return True

        # 172.16.0.0 to 172.31.255.255
        if ip.startswith('172.'):
            try:
                second_octet = int(ip.split('.')[1])
                if 16 <= second_octet <= 31:
                    return True
            except (IndexError, ValueError):
                pass

        return False

    def _is_localhost(self, ip: str) -> bool:
        """Check if IP is localhost."""
        return ip == '127.0.0.1' or ip == '::1' or ip.startswith('127.')

    def _generate_results(self) -> Dict[str, Any]:
        """Generate analysis results dictionary."""
        # Count by severity
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for event in self.beaconing_events:
            severity = event.get('severity', 'low')
            severity_count[severity] += 1

        return {
            'total_beaconing_detected': len(self.beaconing_events),
            'severity_breakdown': severity_count,
            'beaconing_events': sorted(
                self.beaconing_events,
                key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x.get('severity', 'low')]
            ),
            'total_connections_analyzed': len(self.connections),
        }

    def finalize(self):
        """Finalize analysis and cleanup resources."""
        self.connections.clear()
        self.beaconing_events.clear()
