#!/usr/bin/env python3
"""
Lateral Movement Detector

Detects lateral movement attempts within a network by analyzing:
1. SMB/CIFS activity (ports 445, 139)
2. RDP connections between internal hosts (port 3389)
3. WMI/PowerShell remoting (ports 5985, 5986)
4. RPC/DCOM activity (ports 135, 593)
5. Multiple internal connections from single source
6. Administrative protocol usage patterns

Lateral movement indicators:
- Internal host connecting to multiple internal hosts
- Administrative protocol usage (SMB, RDP, WMI)
- Rapid connection attempts to many targets
- Use of administrative shares (ADMIN$, C$, IPC$)

Author: PCAP Analyzer Team
Sprint: 11 (Advanced Threat Detection)
"""

from typing import Dict, Any, List, Set, Tuple
from collections import defaultdict
from scapy.all import IP, TCP
from .base_analyzer import BaseAnalyzer


class LateralMovementDetector(BaseAnalyzer):
    """
    Detects lateral movement by analyzing internal network connections
    to administrative services and protocols.
    """

    # Administrative ports commonly used for lateral movement
    LATERAL_MOVEMENT_PORTS = {
        135: 'RPC',
        139: 'NetBIOS/SMB',
        445: 'SMB/CIFS',
        593: 'RPC over HTTP',
        3389: 'RDP',
        5985: 'WinRM HTTP',
        5986: 'WinRM HTTPS',
        22: 'SSH',
    }

    def __init__(self,
                 target_threshold: int = 3,
                 time_window: float = 300.0,
                 include_localhost: bool = False):
        """
        Initialize Lateral Movement Detector.

        Args:
            target_threshold: Number of targets to consider lateral movement (default: 3)
            time_window: Time window in seconds for rapid movement detection (default: 300s)
            include_localhost: Include localhost traffic in analysis (default: False)
        """
        super().__init__()
        self.target_threshold = target_threshold
        self.time_window = time_window
        self.include_localhost = include_localhost

        # Track connections: src_ip -> {dst_ip: {ports, timestamps}}
        self.internal_connections: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(
            lambda: defaultdict(lambda: {'ports': set(), 'timestamps': [], 'protocols': set()})
        )

        # Track administrative protocol usage
        self.admin_protocol_usage: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        # Detected lateral movement events
        self.lateral_movement_events: List[Dict[str, Any]] = []

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
        Analyze packets for lateral movement patterns.

        Args:
            packets: List of scapy packets to analyze

        Returns:
            Dictionary containing lateral movement analysis results
        """
        if not packets:
            return self._generate_results()

        # Collect connection data
        for pkt in packets:
            if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
                continue

            ip_layer = pkt[IP]
            tcp_layer = pkt[TCP]

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            dst_port = tcp_layer.dport
            timestamp = float(pkt.time)

            # Skip localhost if configured
            if not self.include_localhost:
                if self._is_localhost(src_ip) or self._is_localhost(dst_ip):
                    continue

            # Only track internal-to-internal connections
            if not (self._is_internal(src_ip) and self._is_internal(dst_ip)):
                continue

            # Skip if source and dest are the same
            if src_ip == dst_ip:
                continue

            # Track connection
            conn_data = self.internal_connections[src_ip][dst_ip]
            conn_data['ports'].add(dst_port)
            conn_data['timestamps'].append(timestamp)

            # Track protocol if it's an administrative port
            if dst_port in self.LATERAL_MOVEMENT_PORTS:
                protocol = self.LATERAL_MOVEMENT_PORTS[dst_port]
                conn_data['protocols'].add(protocol)

                self.admin_protocol_usage[src_ip].append({
                    'destination': dst_ip,
                    'port': dst_port,
                    'protocol': protocol,
                    'timestamp': timestamp
                })

        # Analyze for lateral movement patterns
        self._detect_multi_target_connections()
        self._detect_admin_protocol_spread()
        self._detect_rapid_movement()

        return self._generate_results()

    def _detect_multi_target_connections(self):
        """
        Detect sources connecting to multiple internal targets.
        Classic lateral movement indicator.
        """
        for src_ip, targets in self.internal_connections.items():
            target_count = len(targets)

            # If a host connects to many others, it might be lateral movement
            if target_count >= self.target_threshold:
                # Collect details
                admin_targets = []
                admin_protocols = set()

                for dst_ip, conn_data in targets.items():
                    # Check if any administrative protocols were used
                    if conn_data['protocols']:
                        admin_targets.append(dst_ip)
                        admin_protocols.update(conn_data['protocols'])

                # If administrative protocols were used, this is more suspicious
                if admin_targets:
                    severity = self._calculate_severity_multi_target(
                        len(admin_targets),
                        admin_protocols
                    )

                    self.lateral_movement_events.append({
                        'type': 'multi_target_admin',
                        'source_ip': src_ip,
                        'target_count': len(admin_targets),
                        'targets': admin_targets[:10],  # Limit to 10 for readability
                        'protocols_used': sorted(list(admin_protocols)),
                        'severity': severity,
                        'description': f"Internal host connected to {len(admin_targets)} targets using administrative protocols: {', '.join(admin_protocols)}"
                    })

    def _detect_admin_protocol_spread(self):
        """
        Detect use of administrative protocols to multiple targets.
        """
        for src_ip, admin_usage in self.admin_protocol_usage.items():
            if len(admin_usage) < 5:  # Less than 5 admin connections
                continue

            # Group by protocol
            protocol_targets: Dict[str, Set[str]] = defaultdict(set)
            for usage in admin_usage:
                protocol_targets[usage['protocol']].add(usage['destination'])

            # Check each protocol
            for protocol, targets in protocol_targets.items():
                if len(targets) >= self.target_threshold:
                    severity = self._calculate_severity_protocol_spread(
                        protocol,
                        len(targets)
                    )

                    self.lateral_movement_events.append({
                        'type': 'admin_protocol_spread',
                        'source_ip': src_ip,
                        'protocol': protocol,
                        'target_count': len(targets),
                        'targets': list(targets)[:10],
                        'severity': severity,
                        'description': f"Administrative protocol {protocol} used to connect to {len(targets)} internal hosts"
                    })

    def _detect_rapid_movement(self):
        """
        Detect rapid connections to multiple targets within time window.
        Indicator of automated lateral movement/worm behavior.
        """
        for src_ip, targets in self.internal_connections.items():
            # Collect all timestamps with administrative protocols
            admin_timestamps: List[Tuple[float, str, str]] = []

            for dst_ip, conn_data in targets.items():
                if conn_data['protocols']:
                    for ts in conn_data['timestamps']:
                        for protocol in conn_data['protocols']:
                            admin_timestamps.append((ts, dst_ip, protocol))

            if len(admin_timestamps) < self.target_threshold:
                continue

            # Sort by timestamp
            admin_timestamps.sort(key=lambda x: x[0])

            # Check for rapid movement in time windows
            for i in range(len(admin_timestamps)):
                start_time = admin_timestamps[i][0]
                end_time = start_time + self.time_window

                # Count unique targets in this window
                targets_in_window = set()
                protocols_in_window = set()

                for ts, dst_ip, protocol in admin_timestamps[i:]:
                    if ts <= end_time:
                        targets_in_window.add(dst_ip)
                        protocols_in_window.add(protocol)
                    else:
                        break

                # If many targets hit rapidly, it's suspicious
                if len(targets_in_window) >= self.target_threshold:
                    self.lateral_movement_events.append({
                        'type': 'rapid_movement',
                        'source_ip': src_ip,
                        'target_count': len(targets_in_window),
                        'targets': list(targets_in_window),
                        'protocols_used': list(protocols_in_window),
                        'time_window_seconds': self.time_window,
                        'severity': 'high',
                        'description': f"Rapid lateral movement: {len(targets_in_window)} targets in {self.time_window}s"
                    })
                    break  # Only report once per source

    def _calculate_severity_multi_target(
        self,
        target_count: int,
        protocols: Set[str]
    ) -> str:
        """Calculate severity for multi-target connections."""
        # More targets = higher severity
        # Certain protocols = higher severity
        high_risk_protocols = {'RDP', 'WinRM HTTP', 'WinRM HTTPS'}

        if target_count >= 10:
            return 'critical'
        elif target_count >= 7:
            return 'high'
        elif target_count >= 5:
            return 'medium'
        elif any(p in high_risk_protocols for p in protocols):
            return 'high'
        else:
            return 'medium'

    def _calculate_severity_protocol_spread(
        self,
        protocol: str,
        target_count: int
    ) -> str:
        """Calculate severity for protocol spread."""
        high_risk_protocols = {'RDP', 'WinRM HTTP', 'WinRM HTTPS'}

        if protocol in high_risk_protocols:
            if target_count >= 5:
                return 'critical'
            else:
                return 'high'
        else:
            if target_count >= 10:
                return 'high'
            else:
                return 'medium'

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
        for event in self.lateral_movement_events:
            severity = event.get('severity', 'low')
            severity_count[severity] += 1

        # Count by type
        type_count = defaultdict(int)
        for event in self.lateral_movement_events:
            type_count[event['type']] += 1

        return {
            'total_lateral_movement_detected': len(self.lateral_movement_events),
            'severity_breakdown': severity_count,
            'type_breakdown': dict(type_count),
            'lateral_movement_events': sorted(
                self.lateral_movement_events,
                key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x.get('severity', 'low')]
            ),
            'total_sources_analyzed': len(self.internal_connections),
        }

    def finalize(self):
        """Finalize analysis and cleanup resources."""
        self.internal_connections.clear()
        self.admin_protocol_usage.clear()
        self.lateral_movement_events.clear()
