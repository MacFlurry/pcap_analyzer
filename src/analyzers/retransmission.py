"""
Analyseur de retransmissions et anomalies TCP
"""

from scapy.all import Packet, TCP, IP
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class TCPRetransmission:
    """Représente une retransmission TCP"""
    packet_num: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq_num: int
    original_packet_num: int
    delay: float


@dataclass
class TCPAnomaly:
    """Représente une anomalie TCP (DUP ACK, Out-of-Order, etc.)"""
    anomaly_type: str  # 'dup_ack', 'out_of_order', 'zero_window', etc.
    packet_num: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    details: str


@dataclass
class FlowStats:
    """Statistiques d'un flux TCP"""
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    total_packets: int
    retransmissions: int
    dup_acks: int
    out_of_order: int
    zero_windows: int
    severity: str  # 'low', 'medium', 'critical'


class RetransmissionAnalyzer:
    """Analyseur de retransmissions et anomalies TCP"""

    def __init__(self, retrans_low: int = 5, retrans_medium: int = 15,
                 retrans_critical: int = 30):
        """
        Initialise l'analyseur de retransmissions

        Args:
            retrans_low: Seuil bas de retransmissions par flux
            retrans_medium: Seuil moyen de retransmissions par flux
            retrans_critical: Seuil critique de retransmissions par flux
        """
        self.retrans_low = retrans_low
        self.retrans_medium = retrans_medium
        self.retrans_critical = retrans_critical

        self.retransmissions: List[TCPRetransmission] = []
        self.anomalies: List[TCPAnomaly] = []
        self.flow_stats: Dict[str, FlowStats] = {}

        # Tracking interne
        self._seen_segments: Dict[str, Dict[int, Tuple[int, float]]] = defaultdict(dict)
        self._flow_counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._expected_ack: Dict[str, int] = {}
        self._expected_seq: Dict[str, int] = {}

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyse les retransmissions et anomalies TCP

        Args:
            packets: Liste des paquets Scapy

        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        for i, packet in enumerate(packets):
            if not packet.haslayer(TCP) or not packet.haslayer(IP):
                continue

            self._analyze_packet(i, packet)

        self._calculate_flow_severity()

        return self._generate_report()

    def _analyze_packet(self, packet_num: int, packet: Packet) -> None:
        """Analyse un paquet TCP individuel"""
        tcp = packet[TCP]
        ip = packet[IP]
        timestamp = float(packet.time)

        flow_key = self._get_flow_key(packet)
        self._flow_counters[flow_key]['total'] += 1

        # Détection de retransmissions
        if len(tcp.payload) > 0 or tcp.flags & 0x02:  # Données ou SYN
            seq = tcp.seq
            payload_len = len(tcp.payload)

            # Vérifie si ce segment a déjà été vu
            if seq in self._seen_segments[flow_key]:
                original_num, original_time = self._seen_segments[flow_key][seq]
                delay = timestamp - original_time

                retrans = TCPRetransmission(
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    seq_num=seq,
                    original_packet_num=original_num,
                    delay=delay
                )
                self.retransmissions.append(retrans)
                self._flow_counters[flow_key]['retransmissions'] += 1
            else:
                self._seen_segments[flow_key][seq] = (packet_num, timestamp)

        # Détection de DUP ACK
        if tcp.flags & 0x10:  # ACK flag
            ack = tcp.ack
            reverse_flow = self._get_reverse_flow_key(packet)

            if reverse_flow in self._expected_ack:
                if ack == self._expected_ack[reverse_flow]:
                    # Même ACK répété = DUP ACK
                    anomaly = TCPAnomaly(
                        anomaly_type='dup_ack',
                        packet_num=packet_num,
                        timestamp=timestamp,
                        src_ip=ip.src,
                        dst_ip=ip.dst,
                        src_port=tcp.sport,
                        dst_port=tcp.dport,
                        details=f"Duplicate ACK for seq {ack}"
                    )
                    self.anomalies.append(anomaly)
                    self._flow_counters[flow_key]['dup_acks'] += 1

            self._expected_ack[reverse_flow] = ack

        # Détection Out-of-Order
        if len(tcp.payload) > 0:
            seq = tcp.seq
            expected = self._expected_seq.get(flow_key, seq)

            if seq < expected:
                # Paquet reçu avec un numéro de séquence inférieur à celui attendu
                anomaly = TCPAnomaly(
                    anomaly_type='out_of_order',
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    details=f"Expected seq {expected}, got {seq}"
                )
                self.anomalies.append(anomaly)
                self._flow_counters[flow_key]['out_of_order'] += 1
            else:
                self._expected_seq[flow_key] = seq + len(tcp.payload)

        # Détection Zero Window
        if tcp.window == 0:
            anomaly = TCPAnomaly(
                anomaly_type='zero_window',
                packet_num=packet_num,
                timestamp=timestamp,
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                details="TCP window size is 0"
            )
            self.anomalies.append(anomaly)
            self._flow_counters[flow_key]['zero_windows'] += 1

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

    def _calculate_flow_severity(self) -> None:
        """Calcule la sévérité pour chaque flux"""
        for flow_key, counters in self._flow_counters.items():
            parts = flow_key.split('->')
            src_part, dst_part = parts[0].split(':'), parts[1].split(':')

            retrans_count = counters['retransmissions']

            if retrans_count >= self.retrans_critical:
                severity = 'critical'
            elif retrans_count >= self.retrans_medium:
                severity = 'medium'
            elif retrans_count >= self.retrans_low:
                severity = 'low'
            else:
                severity = 'none'

            stats = FlowStats(
                flow_key=flow_key,
                src_ip=src_part[0],
                dst_ip=dst_part[0],
                src_port=int(src_part[1]),
                dst_port=int(dst_part[1]),
                total_packets=counters['total'],
                retransmissions=counters['retransmissions'],
                dup_acks=counters['dup_acks'],
                out_of_order=counters['out_of_order'],
                zero_windows=counters['zero_windows'],
                severity=severity
            )

            self.flow_stats[flow_key] = stats

    def _generate_report(self) -> Dict[str, Any]:
        """Génère le rapport d'analyse"""
        total_retrans = len(self.retransmissions)
        flows_with_issues = [f for f in self.flow_stats.values() if f.severity != 'none']

        # Compte les anomalies par type
        anomaly_counts = defaultdict(int)
        for anomaly in self.anomalies:
            anomaly_counts[anomaly.anomaly_type] += 1

        # Statistiques de sévérité
        severity_counts = defaultdict(int)
        for flow in self.flow_stats.values():
            severity_counts[flow.severity] += 1

        return {
            'total_flows': len(self.flow_stats),
            'flows_with_issues': len(flows_with_issues),
            'total_retransmissions': total_retrans,
            'total_anomalies': len(self.anomalies),
            'anomaly_types': dict(anomaly_counts),
            'severity_distribution': dict(severity_counts),
            'thresholds': {
                'low': self.retrans_low,
                'medium': self.retrans_medium,
                'critical': self.retrans_critical
            },
            'retransmissions': [asdict(r) for r in self.retransmissions],
            'anomalies': [asdict(a) for a in self.anomalies],
            'flow_statistics': [asdict(f) for f in self.flow_stats.values()]
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse"""
        total_retrans = len(self.retransmissions)
        flows_with_issues = [f for f in self.flow_stats.values() if f.severity != 'none']

        summary = f"📊 Analyse des retransmissions et anomalies TCP:\n"
        summary += f"  - Flux analysés: {len(self.flow_stats)}\n"
        summary += f"  - Retransmissions totales: {total_retrans}\n"
        summary += f"  - Anomalies totales: {len(self.anomalies)}\n"

        if flows_with_issues:
            summary += f"\n🔴 {len(flows_with_issues)} flux avec problèmes:\n"

            for flow in sorted(flows_with_issues, key=lambda f: f.retransmissions, reverse=True)[:10]:
                summary += f"\n  {flow.flow_key}\n"
                summary += f"    - Sévérité: {flow.severity.upper()}\n"
                summary += f"    - Retransmissions: {flow.retransmissions}\n"
                summary += f"    - DUP ACK: {flow.dup_acks}\n"
                summary += f"    - Out-of-Order: {flow.out_of_order}\n"
                summary += f"    - Zero Window: {flow.zero_windows}\n"

        return summary
