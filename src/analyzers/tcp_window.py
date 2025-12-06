"""
Analyseur de fenêtres TCP et saturation applicative
"""

from scapy.all import Packet, TCP, IP
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class WindowEvent:
    """Événement lié à la fenêtre TCP"""
    event_type: str  # 'zero_window', 'low_window', 'window_full', 'window_update'
    packet_num: int
    timestamp: float
    flow_key: str
    window_size: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    duration: float = 0.0  # Durée de l'événement (pour zero_window)


@dataclass
class FlowWindowStats:
    """Statistiques de fenêtre pour un flux"""
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    min_window: int
    max_window: int
    mean_window: float
    zero_window_count: int
    low_window_count: int
    zero_window_total_duration: float
    suspected_bottleneck: str  # 'receiver', 'application', 'none'


class TCPWindowAnalyzer:
    """Analyseur de fenêtres TCP optimisé"""

    def __init__(self, low_window_threshold: int = 8192, zero_window_duration: float = 0.1):
        """
        Initialise l'analyseur de fenêtres TCP

        Args:
            low_window_threshold: Seuil de fenêtre basse en octets
            zero_window_duration: Durée minimale de zero window pour alerter (secondes)
        """
        self.low_window_threshold = low_window_threshold
        self.zero_window_duration_threshold = zero_window_duration

        self.window_events: List[WindowEvent] = []
        self.flow_stats: Dict[str, FlowWindowStats] = {}

        # Tracking interne optimisé
        self._flow_scales: Dict[str, int] = {}  # Cache des facteurs d'échelle
        self._zero_window_start: Dict[str, Tuple[int, float, WindowEvent]] = {}
        
        # Agrégation des stats pour éviter de stocker toutes les fenêtres (mémoire & CPU)
        # Structure: {
        #   'count': int, 'sum': float, 'min': int, 'max': int,
        #   'stable_count': int, 'stable_sum': float, 'stable_min': int, 'stable_max': int,
        #   'low_window_count': int, 'zero_window_count': int, 'zero_duration': float
        # }
        self._flow_aggregates: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            'count': 0, 'sum': 0.0, 'min': float('inf'), 'max': 0,
            'stable_count': 0, 'stable_sum': 0.0, 'stable_min': float('inf'), 'stable_max': 0,
            'low_window_count': 0, 'zero_window_count': 0, 'zero_duration': 0.0
        })

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyse les fenêtres TCP

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

        self._last_packet_time = float(packet.time)
        self._analyze_packet(packet_num, packet)

    def finalize(self) -> Dict[str, Any]:
        """Finalise l'analyse et génère le rapport"""
        # Termine les zero windows en cours
        if hasattr(self, '_last_packet_time'):
            last_time = self._last_packet_time
            for flow_key, (start_pkt, start_time, event) in self._zero_window_start.items():
                duration = last_time - start_time
                event.duration = duration
                self._flow_aggregates[flow_key]['zero_duration'] += duration

        # Calcule les statistiques par flux
        self._calculate_flow_statistics()

        return self._generate_report()

    def _analyze_packet(self, packet_num: int, packet: Packet) -> None:
        """Analyse un paquet TCP individuel"""
        tcp = packet[TCP]
        ip = packet[IP]
        timestamp = float(packet.time)

        flow_key = self._get_flow_key(packet)
        
        # Gestion optimisée du Window Scale
        window_scale = self._get_window_scale(tcp, flow_key)
        window_size = tcp.window
        actual_window = window_size * window_scale

        # Mise à jour des agrégats
        stats = self._flow_aggregates[flow_key]
        stats['count'] += 1
        stats['sum'] += actual_window
        if actual_window < stats['min']: stats['min'] = actual_window
        if actual_window > stats['max']: stats['max'] = actual_window

        # Stats "stables" (après 20 paquets)
        is_stable = stats['count'] > 20
        if is_stable:
            stats['stable_count'] += 1
            stats['stable_sum'] += actual_window
            if actual_window < stats['stable_min']: stats['stable_min'] = actual_window
            if actual_window > stats['stable_max']: stats['stable_max'] = actual_window

        # Détection Zero Window
        if actual_window == 0:
            stats['zero_window_count'] += 1

            # Démarre le tracking de la durée si pas déjà en cours
            if flow_key not in self._zero_window_start:
                event = WindowEvent(
                    event_type='zero_window',
                    packet_num=packet_num,
                    timestamp=timestamp,
                    flow_key=flow_key,
                    window_size=actual_window,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport
                )
                self.window_events.append(event)
                self._zero_window_start[flow_key] = (packet_num, timestamp, event)

        else:
            # Fin d'un zero window
            if flow_key in self._zero_window_start:
                start_pkt, start_time, event = self._zero_window_start[flow_key]
                duration = timestamp - start_time
                
                # Mise à jour directe de l'événement et des stats
                event.duration = duration
                stats['zero_duration'] += duration
                
                del self._zero_window_start[flow_key]

                # Window Update après zero window significatif
                if duration >= self.zero_window_duration_threshold:
                    event = WindowEvent(
                        event_type='window_update',
                        packet_num=packet_num,
                        timestamp=timestamp,
                        flow_key=flow_key,
                        window_size=actual_window,
                        src_ip=ip.src,
                        dst_ip=ip.dst,
                        src_port=tcp.sport,
                        dst_port=tcp.dport,
                        duration=duration
                    )
                    self.window_events.append(event)

        # Détection Low Window (uniquement comptage, pas d'événement pour éviter le spam)
        if 0 < actual_window < self.low_window_threshold:
            if is_stable:
                stats['low_window_count'] += 1
            
            # On ne génère plus d'événement 'low_window' pour chaque paquet
            # car cela ralentit énormément l'analyse et surcharge la mémoire

    def _get_flow_key(self, packet: Packet) -> str:
        """Génère une clé de flux unidirectionnelle"""
        ip = packet[IP]
        tcp = packet[TCP]
        return f"{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}"

    def _get_window_scale(self, tcp: TCP, flow_key: str) -> int:
        """
        Récupère le facteur d'échelle de la fenêtre TCP avec mise en cache

        RFC 7323: Window Scale option MUST be checked in both SYN and SYN-ACK packets
        for proper negotiation. The scale factor is only valid if both sides agree.
        """
        # Vérifie le cache
        if flow_key in self._flow_scales:
            return self._flow_scales[flow_key]

        # RFC 7323: Check for WScale option in SYN or SYN-ACK packets
        # Both SYN (0x02) and SYN-ACK (0x12) can carry WScale option
        if tcp.flags & 0x02:  # Flag SYN set (includes both SYN and SYN-ACK)
            scale = 1
            if tcp.options:
                for option in tcp.options:
                    if option[0] == 'WScale':
                        # RFC 7323: Scale factor = 2^shift_count
                        scale = 2 ** option[1]
                        break
            self._flow_scales[flow_key] = scale
            return scale

        # Par défaut 1 si on n'a pas vu le SYN
        return 1

    def _calculate_flow_statistics(self) -> None:
        """Calcule les statistiques de fenêtre par flux à partir des agrégats"""
        for flow_key, stats in self._flow_aggregates.items():
            parts = flow_key.split('->')
            src_part, dst_part = parts[0].split(':'), parts[1].split(':')

            zero_duration = stats['zero_duration']
            zero_count = stats['zero_window_count']
            
            # Calcul du pourcentage de fenêtres basses sur la partie stable
            low_window_percentage = 0
            if stats['stable_count'] > 0:
                low_window_percentage = (stats['low_window_count'] / stats['stable_count']) * 100

            # Détermination du goulot d'étranglement
            suspected = 'none'
            
            # On ignore les flux trop courts
            if stats['count'] >= 30:
                if zero_count > 5 or zero_duration > 1.0:
                    suspected = 'application'
                elif low_window_percentage > 30 and (zero_count > 0 or zero_duration > 0):
                    suspected = 'receiver'

            # Valeurs min/max/moy
            # Si on a des données stables, on les privilégie pour le min
            min_win = stats['stable_min'] if stats['stable_count'] > 0 else stats['min']
            if min_win == float('inf'): min_win = 0
            
            mean_win = stats['sum'] / stats['count'] if stats['count'] > 0 else 0

            flow_stats = FlowWindowStats(
                flow_key=flow_key,
                src_ip=src_part[0],
                dst_ip=dst_part[0],
                src_port=int(src_part[1]),
                dst_port=int(dst_part[1]),
                min_window=int(min_win),
                max_window=int(stats['max']),
                mean_window=mean_win,
                zero_window_count=zero_count,
                low_window_count=stats['low_window_count'],
                zero_window_total_duration=zero_duration,
                suspected_bottleneck=suspected
            )

            self.flow_stats[flow_key] = flow_stats

    def _generate_report(self) -> Dict[str, Any]:
        """Génère le rapport d'analyse des fenêtres TCP"""
        flows_with_issues = [
            f for f in self.flow_stats.values()
            if f.suspected_bottleneck != 'none'
        ]

        zero_window_events = [
            e for e in self.window_events
            if e.event_type == 'zero_window' and e.duration >= self.zero_window_duration_threshold
        ]

        # Statistiques de goulots d'étranglement
        bottleneck_counts = defaultdict(int)
        for flow in self.flow_stats.values():
            bottleneck_counts[flow.suspected_bottleneck] += 1

        return {
            'total_flows': len(self.flow_stats),
            'flows_with_issues': len(flows_with_issues),
            'total_window_events': len(self.window_events),
            'significant_zero_windows': len(zero_window_events),
            'thresholds': {
                'low_window_bytes': self.low_window_threshold,
                'zero_window_duration_seconds': self.zero_window_duration_threshold
            },
            'bottleneck_distribution': dict(bottleneck_counts),
            'window_events': [asdict(e) for e in self.window_events],
            'flow_statistics': [asdict(f) for f in self.flow_stats.values()],
            'critical_zero_windows': [asdict(e) for e in zero_window_events]
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse des fenêtres TCP"""
        flows_with_issues = [
            f for f in self.flow_stats.values()
            if f.suspected_bottleneck != 'none'
        ]

        zero_windows = sum(f.zero_window_count for f in self.flow_stats.values())

        summary = f"📊 Analyse des fenêtres TCP:\n"
        summary += f"  - Flux analysés: {len(self.flow_stats)}\n"
        summary += f"  - Événements Zero Window: {zero_windows}\n"

        if flows_with_issues:
            summary += f"\n🔴 {len(flows_with_issues)} flux avec problèmes de fenêtre:\n"

            for flow in sorted(flows_with_issues,
                             key=lambda f: f.zero_window_total_duration, reverse=True)[:10]:
                summary += f"\n  {flow.flow_key}\n"
                summary += f"    - Goulot suspecté: {flow.suspected_bottleneck}\n"
                summary += f"    - Zero Windows: {flow.zero_window_count}\n"
                summary += f"    - Durée totale ZW: {flow.zero_window_total_duration:.3f}s\n"
                summary += f"    - Fenêtre min/moy/max: {flow.min_window}/{int(flow.mean_window)}/{flow.max_window} bytes\n"
        else:
            summary += f"\n✓ Aucun problème de fenêtre TCP détecté.\n"

        return summary
