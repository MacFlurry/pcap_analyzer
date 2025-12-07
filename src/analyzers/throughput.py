"""
Analyseur de Throughput (débit)
Calcule le débit par flux et détecte les goulots d'étranglement
"""

from scapy.all import IP, TCP, UDP
from collections import defaultdict
from typing import Dict, Any, Union

# Import PacketMetadata for hybrid mode support (3-5x faster)
try:
    from ..parsers.fast_parser import PacketMetadata
except ImportError:
    PacketMetadata = None


class ThroughputAnalyzer:
    """Analyse le débit par flux TCP/UDP"""

    def __init__(self):
        # Key: flow_key (bidirectional)
        self.flows = defaultdict(lambda: {
            'bytes': 0,
            'packets': 0,
            'first_timestamp': None,
            'last_timestamp': None,
            'protocol': 'TCP',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None
        })
        
        # Statistiques globales
        self.total_bytes = 0
        self.total_packets = 0
        self.first_packet_time = None
        self.last_packet_time = None

    def _get_flow_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
        """Génère une clé de flux bidirectionnelle normalisée"""
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port} <-> {dst_ip}:{dst_port}"
        else:
            return f"{dst_ip}:{dst_port} <-> {src_ip}:{src_port}"

    def process_packet(self, packet: Union['Packet', 'PacketMetadata'], packet_num: int):
        """
        Process a single packet (supports both Scapy Packet and PacketMetadata).

        PERFORMANCE: PacketMetadata is 3-5x faster than Scapy Packet parsing.

        Args:
            packet: Scapy Packet or lightweight PacketMetadata
            packet_num: Packet sequence number in capture
        """
        # FAST PATH: Handle PacketMetadata (dpkt-extracted, 3-5x faster)
        if PacketMetadata and isinstance(packet, PacketMetadata):
            self._process_metadata(packet, packet_num)
            return

        # LEGACY PATH: Handle Scapy Packet (for backward compatibility)
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        timestamp = float(packet.time)
        length = len(packet)
        
        # Stats globales
        self.total_bytes += length
        self.total_packets += 1
        
        if self.first_packet_time is None:
            self.first_packet_time = timestamp
        self.last_packet_time = timestamp
        
        # Identification du flux
        src_ip = ip.src
        dst_ip = ip.dst
        src_port = None
        dst_port = None
        protocol = 'Other'
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            protocol = 'TCP'
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            protocol = 'UDP'
        else:
            # Pour les autres protocoles, on utilise juste les IPs
            flow_key = f"{src_ip} <-> {dst_ip}"
            flow = self.flows[flow_key]
            flow['bytes'] += length
            flow['packets'] += 1
            flow['protocol'] = protocol
            flow['src_ip'] = src_ip
            flow['dst_ip'] = dst_ip
            if flow['first_timestamp'] is None:
                flow['first_timestamp'] = timestamp
            flow['last_timestamp'] = timestamp
            return
        
        # Flux TCP/UDP
        flow_key = self._get_flow_key(src_ip, src_port, dst_ip, dst_port)
        flow = self.flows[flow_key]
        
        flow['bytes'] += length
        flow['packets'] += 1
        flow['protocol'] = protocol
        flow['src_ip'] = src_ip
        flow['dst_ip'] = dst_ip
        flow['src_port'] = src_port
        flow['dst_port'] = dst_port
        
        if flow['first_timestamp'] is None:
            flow['first_timestamp'] = timestamp
        flow['last_timestamp'] = timestamp

    def _calculate_throughput(self, bytes_count: int, first_ts: float, last_ts: float) -> Dict[str, float]:
        """
        Calcule le débit en différentes unités.

        FIX: Improved handling of edge cases:
        - Single packet flows (first_ts == last_ts)
        - Missing timestamps
        - Proper bit/byte conversion (using decimal 1000 for network metrics)
        """
        # Handle missing timestamps
        if not first_ts or not last_ts:
            return {
                'duration_seconds': 0,
                'bytes_per_second': 0,
                'kbps': 0,
                'mbps': 0
            }

        duration = last_ts - first_ts

        # For single packet or very short flows, use minimal duration
        # to avoid division by zero while still indicating data was transferred
        if duration <= 0:
            # Assume minimum measurable duration (1ms) for throughput calculation
            # This prevents division by zero for single-packet flows
            duration = 0.001

        bps = bytes_count / duration

        # Network throughput uses decimal (SI) units: 1 kbit = 1000 bits
        return {
            'duration_seconds': last_ts - first_ts,  # Real duration (may be 0)
            'bytes_per_second': bps,
            'kbps': (bps * 8) / 1000,  # kilobits per second (decimal)
            'mbps': (bps * 8) / 1_000_000  # megabits per second (decimal)
        }

    def _process_metadata(self, metadata: 'PacketMetadata', packet_num: int) -> None:
        """
        PERFORMANCE OPTIMIZED: Process lightweight PacketMetadata (3-5x faster than Scapy).

        This method replicates throughput calculation logic but uses direct attribute access
        from dpkt-extracted metadata.

        Args:
            metadata: Lightweight packet metadata from dpkt
            packet_num: Packet sequence number in capture
        """
        timestamp = metadata.timestamp
        length = metadata.packet_length

        # Stats globales
        self.total_bytes += length
        self.total_packets += 1

        if self.first_packet_time is None:
            self.first_packet_time = timestamp
        self.last_packet_time = timestamp

        # Identification du flux
        src_ip = metadata.src_ip
        dst_ip = metadata.dst_ip
        src_port = metadata.src_port
        dst_port = metadata.dst_port
        protocol = metadata.protocol

        # Pour TCP/UDP avec ports
        if protocol in ('TCP', 'UDP') and src_port is not None and dst_port is not None:
            flow_key = self._get_flow_key(src_ip, src_port, dst_ip, dst_port)
            flow = self.flows[flow_key]

            flow['bytes'] += length
            flow['packets'] += 1
            flow['protocol'] = protocol
            flow['src_ip'] = src_ip
            flow['dst_ip'] = dst_ip
            flow['src_port'] = src_port
            flow['dst_port'] = dst_port

            if flow['first_timestamp'] is None:
                flow['first_timestamp'] = timestamp
            flow['last_timestamp'] = timestamp
        else:
            # Pour les autres protocoles (ICMP, Other), utiliser juste les IPs
            flow_key = f"{src_ip} <-> {dst_ip}"
            flow = self.flows[flow_key]
            flow['bytes'] += length
            flow['packets'] += 1
            flow['protocol'] = protocol
            flow['src_ip'] = src_ip
            flow['dst_ip'] = dst_ip
            if flow['first_timestamp'] is None:
                flow['first_timestamp'] = timestamp
            flow['last_timestamp'] = timestamp

    def finalize(self) -> Dict[str, Any]:
        """Finalize analysis and return results"""
        return self.get_results()

    def _generate_report(self) -> Dict[str, Any]:
        """Generate report for hybrid mode compatibility"""
        return self.get_results()

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse de débit"""
        results = self.get_results()

        global_tp = results['global_throughput']
        total_flows = results['total_flows']
        slow_flows = results['slow_flows']

        summary = f"📈 Analyse du débit (Throughput):\n"
        summary += f"  - Débit global: {global_tp['throughput_mbps']:.2f} Mbps\n"
        summary += f"  - Durée totale: {global_tp['duration_seconds']:.2f}s\n"
        summary += f"  - Flux analysés: {total_flows}\n"

        if slow_flows:
            summary += f"  - Flux lents détectés: {len(slow_flows)}\n"
            summary += f"\n⚠️  {len(slow_flows)} flux avec débit < 1 Mbps détectés."
        else:
            summary += "\n✓ Aucun flux lent détecté."

        return summary

    def get_results(self) -> Dict[str, Any]:
        """Retourne les résultats de l'analyse"""

        # Throughput global
        global_throughput = self._calculate_throughput(
            self.total_bytes,
            self.first_packet_time,
            self.last_packet_time
        )
        
        # Throughput par flux
        flow_stats = []
        for flow_key, flow in self.flows.items():
            throughput = self._calculate_throughput(
                flow['bytes'],
                flow['first_timestamp'],
                flow['last_timestamp']
            )
            
            flow_stats.append({
                'flow_key': flow_key,
                'protocol': flow['protocol'],
                'bytes': flow['bytes'],
                'packets': flow['packets'],
                'duration_seconds': throughput['duration_seconds'],
                'throughput_mbps': throughput['mbps'],
                'throughput_kbps': throughput['kbps'],
                'avg_packet_size': flow['bytes'] / flow['packets'] if flow['packets'] > 0 else 0,
                'src_ip': flow['src_ip'],
                'dst_ip': flow['dst_ip'],
                'src_port': flow['src_port'],
                'dst_port': flow['dst_port']
            })
        
        # Trier par débit décroissant
        flow_stats.sort(key=lambda x: x['throughput_mbps'], reverse=True)
        
        # Identifier les flux à faible débit (potentiels goulots)
        # Un flux est considéré "lent" s'il a une durée > 1s et un débit < 1 Mbps
        slow_flows = [
            f for f in flow_stats 
            if f['duration_seconds'] > 1.0 and f['throughput_mbps'] < 1.0 and f['bytes'] > 10000
        ]
        
        return {
            'global_throughput': {
                'total_bytes': self.total_bytes,
                'total_packets': self.total_packets,
                'duration_seconds': global_throughput['duration_seconds'],
                'throughput_mbps': global_throughput['mbps'],
                'throughput_kbps': global_throughput['kbps']
            },
            'top_flows': flow_stats[:20],  # Top 20 flows by throughput
            'slow_flows': slow_flows[:10],  # Top 10 slow flows
            'total_flows': len(self.flows)
        }
