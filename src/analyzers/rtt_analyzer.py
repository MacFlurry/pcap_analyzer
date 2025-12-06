"""
Analyseur de RTT (Round Trip Time)
"""

from scapy.all import Packet, TCP, IP
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict
import statistics


@dataclass
class RTTMeasurement:
    """Mesure individuelle de RTT"""
    timestamp: float
    rtt: float
    flow_key: str
    seq_num: int
    ack_num: int
    data_packet_num: int
    ack_packet_num: int


@dataclass
class FlowRTTStats:
    """Statistiques RTT pour un flux"""
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    measurements_count: int
    min_rtt: float
    max_rtt: float
    mean_rtt: float
    median_rtt: float
    stdev_rtt: Optional[float]
    rtt_spikes: int  # Nombre de pics au-dessus du seuil


class RTTAnalyzer:
    """Analyseur de Round Trip Time"""

    def __init__(self, rtt_warning: float = 0.1, rtt_critical: float = 0.5,
                 latency_filter: Optional[float] = None):
        """
        Initialise l'analyseur de RTT

        Args:
            rtt_warning: Seuil d'alerte RTT en secondes
            rtt_critical: Seuil critique RTT en secondes
            latency_filter: Si défini, ne garde que les mesures RTT >= ce seuil
        """
        self.rtt_warning = rtt_warning
        self.rtt_critical = rtt_critical
        self.latency_filter = latency_filter

        self.measurements: List[RTTMeasurement] = []
        self.flow_stats: Dict[str, FlowRTTStats] = {}

        # Tracking interne : {flow_key: {seq: (packet_num, timestamp, payload_len)}}
        self._unacked_segments: Dict[str, Dict[int, Tuple[int, float, int]]] = defaultdict(dict)

        # Memory optimization: periodic cleanup
        self._packet_counter = 0
        self._cleanup_interval = 5000
        self._segment_timeout = 60.0  # Remove segments unacked for 60s

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyse le RTT des flux TCP

        Args:
            packets: Liste des paquets Scapy

        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        for i, packet in enumerate(packets):
            self.process_packet(packet, i)

        return self.finalize()

    def process_packet(self, packet: Packet, packet_num: int) -> None:
        """Traite un paquet individuel"""
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return

        tcp = packet[TCP]
        timestamp = float(packet.time)

        # Memory optimization: periodic cleanup
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_stale_segments(timestamp)

        # Segment avec données
        if len(tcp.payload) > 0:
            flow_key = self._get_flow_key(packet)
            seq = tcp.seq
            payload_len = len(tcp.payload)

            # Enregistre le segment en attente d'ACK
            if seq not in self._unacked_segments[flow_key]:
                self._unacked_segments[flow_key][seq] = (packet_num, timestamp, payload_len)

        # ACK reçu
        if tcp.flags & 0x10 and tcp.ack > 0:
            reverse_flow = self._get_reverse_flow_key(packet)
            ack = tcp.ack

            # Cherche les segments correspondants
            for seq, (data_pkt_num, data_time, payload_len) in list(
                self._unacked_segments[reverse_flow].items()
            ):
                # Si l'ACK couvre ce segment
                if ack >= seq + payload_len:
                    rtt = timestamp - data_time

                    # Applique le filtre de latence si défini
                    if self.latency_filter is None or rtt >= self.latency_filter:
                        measurement = RTTMeasurement(
                            timestamp=timestamp,
                            rtt=rtt,
                            flow_key=reverse_flow,
                            seq_num=seq,
                            ack_num=ack,
                            data_packet_num=data_pkt_num,
                            ack_packet_num=packet_num
                        )
                        self.measurements.append(measurement)

                    # Supprime le segment ACKé
                    del self._unacked_segments[reverse_flow][seq]

    def finalize(self) -> Dict[str, Any]:
        """Finalise l'analyse et génère le rapport"""
        # Cleanup unacked segments older than 60s to prevent memory leaks
        self._cleanup_stale_segments()

        # Calcule les statistiques par flux
        self._calculate_flow_statistics()

        return self._generate_report()

    def _cleanup_stale_segments(self) -> None:
        """Clean up unacked segments older than 60s to prevent memory leaks"""
        if not self.measurements:
            return

        # Use the last measurement timestamp as reference
        current_time = self.measurements[-1].timestamp if self.measurements else 0
        timeout_threshold = 60.0  # 60 seconds

        for flow_key in list(self._unacked_segments.keys()):
            segments_to_remove = []
            for seq, (packet_num, timestamp, payload_len) in list(self._unacked_segments[flow_key].items()):
                # Remove segments older than 60s
                if current_time - timestamp > timeout_threshold:
                    segments_to_remove.append(seq)

            # Remove stale segments
            for seq in segments_to_remove:
                del self._unacked_segments[flow_key][seq]

            # Clean up empty flow entries
            if not self._unacked_segments[flow_key]:
                del self._unacked_segments[flow_key]

    def _get_flow_key(self, packet: Packet) -> str:
        """Génère une clé de flux unidirectionnelle"""
        ip = packet[IP]
        tcp = packet[TCP]
        return f"{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}"

    def _get_reverse_flow_key(self, packet: Packet) -> str:
        """Génère la clé de flux inverse"""
        ip = packet[IP]
        tcp = packet[TCP]
        return f"{ip.dst}:{tcp.dport}->{ip.src}:{tcp.sport}"

    def _calculate_flow_statistics(self) -> None:
        """Calcule les statistiques RTT par flux"""
        flow_measurements: Dict[str, List[float]] = defaultdict(list)

        # Regroupe les mesures par flux
        for measurement in self.measurements:
            flow_measurements[measurement.flow_key].append(measurement.rtt)

        # Calcule les stats pour chaque flux
        for flow_key, rtts in flow_measurements.items():
            if not rtts:
                continue

            parts = flow_key.split('->')
            src_part, dst_part = parts[0].split(':'), parts[1].split(':')

            rtt_spikes = sum(1 for rtt in rtts if rtt > self.rtt_warning)

            stats = FlowRTTStats(
                flow_key=flow_key,
                src_ip=src_part[0],
                dst_ip=dst_part[0],
                src_port=int(src_part[1]),
                dst_port=int(dst_part[1]),
                measurements_count=len(rtts),
                min_rtt=min(rtts),
                max_rtt=max(rtts),
                mean_rtt=statistics.mean(rtts),
                median_rtt=statistics.median(rtts),
                stdev_rtt=statistics.stdev(rtts) if len(rtts) > 1 else None,
                rtt_spikes=rtt_spikes
            )

            self.flow_stats[flow_key] = stats

    def _generate_report(self) -> Dict[str, Any]:
        """Génère le rapport d'analyse RTT"""
        all_rtts = [m.rtt for m in self.measurements]

        global_stats = {}
        if all_rtts:
            global_stats = {
                'min_rtt': min(all_rtts),
                'max_rtt': max(all_rtts),
                'mean_rtt': statistics.mean(all_rtts),
                'median_rtt': statistics.median(all_rtts),
            }

            if len(all_rtts) > 1:
                global_stats['stdev_rtt'] = statistics.stdev(all_rtts)

        # Identifie les flux avec RTT élevé
        flows_with_high_rtt = [
            f for f in self.flow_stats.values()
            if f.mean_rtt > self.rtt_warning or f.max_rtt > self.rtt_critical
        ]

        # Mesures avec RTT critique
        critical_measurements = [
            m for m in self.measurements
            if m.rtt > self.rtt_critical
        ]

        return {
            'total_measurements': len(self.measurements),
            'total_flows': len(self.flow_stats),
            'global_statistics': global_stats,
            'thresholds': {
                'warning_seconds': self.rtt_warning,
                'critical_seconds': self.rtt_critical
            },
            'flows_with_high_rtt': len(flows_with_high_rtt),
            'critical_measurements': len(critical_measurements),
            'flow_statistics': [asdict(f) for f in self.flow_stats.values()],
            'measurements': [asdict(m) for m in self.measurements],
            'critical_rtt_details': [asdict(m) for m in critical_measurements]
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse RTT"""
        if not self.measurements:
            return "📊 Aucune mesure RTT disponible."

        all_rtts = [m.rtt for m in self.measurements]
        mean_rtt = statistics.mean(all_rtts)
        max_rtt = max(all_rtts)

        flows_with_issues = [
            f for f in self.flow_stats.values()
            if f.mean_rtt > self.rtt_warning or f.max_rtt > self.rtt_critical
        ]

        summary = f"📊 Analyse RTT:\n"
        summary += f"  - Mesures totales: {len(self.measurements)}\n"
        summary += f"  - RTT moyen global: {mean_rtt * 1000:.2f}ms\n"
        summary += f"  - RTT max global: {max_rtt * 1000:.2f}ms\n"

        if flows_with_issues:
            summary += f"\n🔴 {len(flows_with_issues)} flux avec RTT élevé:\n"

            for flow in sorted(flows_with_issues, key=lambda f: f.mean_rtt, reverse=True)[:10]:
                summary += f"\n  {flow.flow_key}\n"
                summary += f"    - RTT moyen: {flow.mean_rtt * 1000:.2f}ms\n"
                summary += f"    - RTT min/max: {flow.min_rtt * 1000:.2f}/{flow.max_rtt * 1000:.2f}ms\n"
                summary += f"    - Pics RTT: {flow.rtt_spikes}\n"
        else:
            summary += f"\n✓ Tous les flux ont un RTT acceptable.\n"

        return summary

    def get_rtt_time_series(self, flow_key: Optional[str] = None) -> List[Tuple[float, float]]:
        """
        Retourne la série temporelle des RTT

        Args:
            flow_key: Clé de flux (si None, retourne tous les flux)

        Returns:
            Liste de tuples (timestamp, rtt)
        """
        if flow_key:
            measurements = [m for m in self.measurements if m.flow_key == flow_key]
        else:
            measurements = self.measurements

        return [(m.timestamp, m.rtt) for m in measurements]
