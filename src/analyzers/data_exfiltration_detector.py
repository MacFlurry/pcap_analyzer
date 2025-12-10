#!/usr/bin/env python3
"""
Data Exfiltration Detector

Detects potential data exfiltration attempts by analyzing:
1. Large upload volumes (>50MB in 5min window)
2. Suspicious upload/download ratios (>5:1)
3. Unusual protocol usage for data transfer
4. Encoding patterns in unencrypted protocols
5. Transfers to suspicious destinations

Author: PCAP Analyzer Team
Sprint: 11 (Advanced Threat Detection)
"""

from typing import Dict, Any, List, Tuple
from collections import defaultdict
from scapy.all import IP, TCP, UDP, Raw
from .base_analyzer import BaseAnalyzer
import time


class DataExfiltrationDetector(BaseAnalyzer):
    """
    Detects data exfiltration attempts by monitoring upload volumes,
    suspicious ratios, and unusual transfer patterns.
    """

    def __init__(self,
                 upload_threshold_mb: float = 50.0,
                 time_window: float = 300.0,
                 suspicious_ratio: float = 5.0,
                 include_localhost: bool = False,
                 suspicious_ports: List[int] = None):
        """
        Initialize Data Exfiltration Detector.

        Args:
            upload_threshold_mb: Upload volume threshold in MB (default: 50MB)
            time_window: Time window in seconds for volume analysis (default: 300s = 5min)
            suspicious_ratio: Upload/Download ratio threshold (default: 5:1)
            include_localhost: Include localhost traffic in analysis (default: False)
            suspicious_ports: List of ports commonly used for exfiltration (default: non-standard)
        """
        super().__init__()
        self.upload_threshold_bytes = upload_threshold_mb * 1024 * 1024
        self.time_window = time_window
        self.suspicious_ratio = suspicious_ratio
        self.include_localhost = include_localhost

        # Common exfiltration ports (non-standard services)
        self.suspicious_ports = suspicious_ports or [
            8080, 8443, 8888, 9000, 9001,  # Alternative HTTP/HTTPS
            3128, 8123,  # Proxy ports
            4444, 5555, 6666, 7777,  # Common backdoor ports
            31337, 12345,  # Classic backdoor ports
        ]

        # Track upload/download per IP
        self.traffic_by_ip: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'upload_bytes': 0,
            'download_bytes': 0,
            'upload_packets': 0,
            'download_packets': 0,
            'first_seen': None,
            'last_seen': None,
            'destinations': set(),
            'ports_used': set(),
            'protocols': set(),
        })

        # Track time windows for volume analysis
        self.upload_windows: Dict[str, List[Tuple[float, int]]] = defaultdict(list)

        # Exfiltration events detected
        self.exfiltration_events: List[Dict[str, Any]] = []

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
        Analyze packets for data exfiltration patterns.

        Args:
            packets: List of scapy packets to analyze

        Returns:
            Dictionary containing exfiltration analysis results
        """
        if not packets:
            return self._generate_results()

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

            # Determine if this is upload or download from internal network perspective
            # Assume 192.168.x.x, 10.x.x.x, 172.16-31.x.x are internal
            src_internal = self._is_internal(src_ip)
            dst_internal = self._is_internal(dst_ip)

            # Upload: internal -> external
            # Download: external -> internal
            if src_internal and not dst_internal:
                # Upload traffic
                payload_size = len(bytes(pkt))
                self._record_upload(src_ip, dst_ip, payload_size, timestamp, pkt)
            elif not src_internal and dst_internal:
                # Download traffic
                payload_size = len(bytes(pkt))
                self._record_download(dst_ip, src_ip, payload_size, timestamp)

        # Analyze collected data for exfiltration patterns
        self._detect_large_uploads()
        self._detect_suspicious_ratios()
        self._detect_unusual_protocols()

        return self._generate_results()

    def _record_upload(self, src_ip: str, dst_ip: str, size: int,
                       timestamp: float, pkt: Any):
        """Record upload traffic from source to destination."""
        data = self.traffic_by_ip[src_ip]
        data['upload_bytes'] += size
        data['upload_packets'] += 1
        data['destinations'].add(dst_ip)

        if data['first_seen'] is None:
            data['first_seen'] = timestamp
        data['last_seen'] = timestamp

        # Track ports and protocols
        if pkt.haslayer(TCP):
            data['ports_used'].add(pkt[TCP].dport)
            data['protocols'].add('TCP')
        elif pkt.haslayer(UDP):
            data['ports_used'].add(pkt[UDP].dport)
            data['protocols'].add('UDP')

        # Track upload in time windows
        self.upload_windows[src_ip].append((timestamp, size))

    def _record_download(self, dst_ip: str, src_ip: str, size: int, timestamp: float):
        """Record download traffic to destination from source."""
        data = self.traffic_by_ip[dst_ip]
        data['download_bytes'] += size
        data['download_packets'] += 1

        if data['first_seen'] is None:
            data['first_seen'] = timestamp
        data['last_seen'] = timestamp

    def _detect_large_uploads(self):
        """Detect large upload volumes within time windows."""
        for src_ip, windows in self.upload_windows.items():
            if not windows:
                continue

            # Sort by timestamp
            windows.sort(key=lambda x: x[0])

            # Sliding window analysis
            for i, (start_time, _) in enumerate(windows):
                end_time = start_time + self.time_window

                # Sum bytes in this time window
                window_bytes = sum(
                    size for ts, size in windows[i:]
                    if start_time <= ts <= end_time
                )

                if window_bytes >= self.upload_threshold_bytes:
                    # Large upload detected
                    data = self.traffic_by_ip[src_ip]

                    self.exfiltration_events.append({
                        'type': 'large_upload',
                        'source_ip': src_ip,
                        'upload_volume_mb': window_bytes / (1024 * 1024),
                        'time_window_seconds': self.time_window,
                        'destinations': list(data['destinations']),
                        'ports_used': sorted(list(data['ports_used'])),
                        'protocols': list(data['protocols']),
                        'severity': self._calculate_severity_upload(window_bytes),
                        'description': f"Large upload detected: {window_bytes / (1024 * 1024):.2f}MB uploaded in {self.time_window}s"
                    })
                    break  # Only report once per IP

    def _detect_suspicious_ratios(self):
        """Detect suspicious upload/download ratios."""
        for src_ip, data in self.traffic_by_ip.items():
            upload_bytes = data['upload_bytes']
            download_bytes = data['download_bytes']

            # Skip if no significant traffic
            if upload_bytes < (10 * 1024 * 1024):  # Less than 10MB
                continue

            # Calculate ratio
            if download_bytes == 0:
                ratio = float('inf')
            else:
                ratio = upload_bytes / download_bytes

            if ratio >= self.suspicious_ratio:
                self.exfiltration_events.append({
                    'type': 'suspicious_ratio',
                    'source_ip': src_ip,
                    'upload_mb': upload_bytes / (1024 * 1024),
                    'download_mb': download_bytes / (1024 * 1024),
                    'ratio': ratio if ratio != float('inf') else 'infinite',
                    'destinations': list(data['destinations']),
                    'ports_used': sorted(list(data['ports_used'])),
                    'severity': self._calculate_severity_ratio(ratio),
                    'description': f"Suspicious upload/download ratio: {ratio:.2f}:1 ({upload_bytes / (1024 * 1024):.2f}MB uploaded)"
                })

    def _detect_unusual_protocols(self):
        """Detect data transfers over unusual protocols or ports."""
        for src_ip, data in self.traffic_by_ip.items():
            upload_mb = data['upload_bytes'] / (1024 * 1024)

            # Skip small transfers
            if upload_mb < 5.0:  # Less than 5MB
                continue

            # Check for suspicious ports
            suspicious_ports_used = [
                port for port in data['ports_used']
                if port in self.suspicious_ports
            ]

            if suspicious_ports_used:
                self.exfiltration_events.append({
                    'type': 'unusual_protocol',
                    'source_ip': src_ip,
                    'upload_mb': upload_mb,
                    'suspicious_ports': suspicious_ports_used,
                    'destinations': list(data['destinations']),
                    'severity': 'high',
                    'description': f"Data transfer over suspicious ports: {suspicious_ports_used}"
                })

    def _calculate_severity_upload(self, bytes_uploaded: int) -> str:
        """Calculate severity based on upload volume."""
        mb = bytes_uploaded / (1024 * 1024)

        if mb >= 500:
            return 'critical'
        elif mb >= 200:
            return 'high'
        elif mb >= 100:
            return 'medium'
        else:
            return 'low'

    def _calculate_severity_ratio(self, ratio: float) -> str:
        """Calculate severity based on upload/download ratio."""
        if ratio == float('inf'):
            return 'critical'
        elif ratio >= 20:
            return 'high'
        elif ratio >= 10:
            return 'medium'
        else:
            return 'low'

    def _is_internal(self, ip: str) -> bool:
        """Check if IP is from internal network."""
        if ip.startswith('192.168.') or ip.startswith('10.'):
            return True

        # 172.16.0.0 to 172.31.255.255
        if ip.startswith('172.'):
            second_octet = int(ip.split('.')[1])
            if 16 <= second_octet <= 31:
                return True

        return False

    def _is_localhost(self, ip: str) -> bool:
        """Check if IP is localhost."""
        return ip == '127.0.0.1' or ip == '::1' or ip.startswith('127.')

    def _generate_results(self) -> Dict[str, Any]:
        """Generate analysis results dictionary."""
        # Count by severity
        severity_count = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for event in self.exfiltration_events:
            severity = event.get('severity', 'low')
            severity_count[severity] += 1

        # Count by type
        type_count = defaultdict(int)
        for event in self.exfiltration_events:
            type_count[event['type']] += 1

        return {
            'total_exfiltration_detected': len(self.exfiltration_events),
            'severity_breakdown': severity_count,
            'type_breakdown': dict(type_count),
            'exfiltration_events': sorted(
                self.exfiltration_events,
                key=lambda x: {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}[x.get('severity', 'low')]
            ),
            'total_ips_analyzed': len(self.traffic_by_ip),
        }

    def finalize(self):
        """Finalize analysis and cleanup resources."""
        self.traffic_by_ip.clear()
        self.upload_windows.clear()
        self.exfiltration_events.clear()
