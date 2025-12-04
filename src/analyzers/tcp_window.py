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
    """Analyseur de fenêtres TCP"""

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

        # Tracking interne
        self._flow_windows: Dict[str, List[int]] = defaultdict(list)
        self._zero_window_start: Dict[str, Tuple[int, float]] = {}
        self._event_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyse les fenêtres TCP

        Args:
            packets: Liste des paquets Scapy

        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        for i, packet in enumerate(packets):
            if not packet.haslayer(TCP) or not packet.haslayer(IP):
                continue

            self._analyze_packet(i, packet)

        # Termine les zero windows en cours
        for flow_key, (start_pkt, start_time) in self._zero_window_start.items():
            # Utilise le dernier timestamp connu
            if packets:
                last_time = float(packets[-1].time)
                duration = last_time - start_time
                # Met à jour la durée du dernier événement zero window
                for event in reversed(self.window_events):
                    if event.flow_key == flow_key and event.event_type == 'zero_window':
                        event.duration = duration
                        break

        # Calcule les statistiques par flux
        self._calculate_flow_statistics()

        return self._generate_report()

    def _analyze_packet(self, packet_num: int, packet: Packet) -> None:
        """Analyse un paquet TCP individuel"""
        tcp = packet[TCP]
        ip = packet[IP]
        timestamp = float(packet.time)

        flow_key = self._get_flow_key(packet)
        window_size = tcp.window
        window_scale = self._get_window_scale(tcp)
        actual_window = window_size * window_scale

        # Enregistre la taille de fenêtre
        self._flow_windows[flow_key].append(actual_window)

        # Détection Zero Window
        if actual_window == 0:
            self._event_counts[flow_key]['zero_window'] += 1

            # Démarre le tracking de la durée si pas déjà en cours
            if flow_key not in self._zero_window_start:
                self._zero_window_start[flow_key] = (packet_num, timestamp)

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

        else:
            # Fin d'un zero window
            if flow_key in self._zero_window_start:
                start_pkt, start_time = self._zero_window_start[flow_key]
                duration = timestamp - start_time

                # Met à jour la durée du dernier événement zero window
                for event in reversed(self.window_events):
                    if (event.flow_key == flow_key and
                        event.event_type == 'zero_window' and
                        event.packet_num == start_pkt):
                        event.duration = duration
                        break

                del self._zero_window_start[flow_key]

                # Window Update après zero window
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

        # Détection Low Window
        if 0 < actual_window < self.low_window_threshold:
            self._event_counts[flow_key]['low_window'] += 1

            event = WindowEvent(
                event_type='low_window',
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

    def _get_flow_key(self, packet: Packet) -> str:
        """Génère une clé de flux unidirectionnelle"""
        ip = packet[IP]
        tcp = packet[TCP]
        return f"{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}"

    def _get_window_scale(self, tcp: TCP) -> int:
        """
        Récupère le facteur d'échelle de la fenêtre TCP

        Args:
            tcp: Couche TCP du paquet

        Returns:
            Facteur d'échelle (1 si non trouvé)
        """
        # Cherche l'option Window Scale (kind=3)
        if tcp.options:
            for option in tcp.options:
                if option[0] == 'WScale':
                    return 2 ** option[1]
        return 1

    def _calculate_flow_statistics(self) -> None:
        """Calcule les statistiques de fenêtre par flux"""
        for flow_key, windows in self._flow_windows.items():
            if not windows:
                continue

            parts = flow_key.split('->')
            src_part, dst_part = parts[0].split(':'), parts[1].split(':')

            # Calcule la durée totale des zero windows
            zero_window_duration = sum(
                event.duration for event in self.window_events
                if event.flow_key == flow_key and event.event_type == 'zero_window'
            )

            # Détermine le goulot d'étranglement suspecté
            zero_count = self._event_counts[flow_key]['zero_window']
            low_count = self._event_counts[flow_key]['low_window']

            # Amélioration : Ignore les premières fenêtres (handshake + slow start)
            # On skip les 10 premiers paquets pour éviter les faux positifs
            windows_stable = windows[10:] if len(windows) > 10 else windows

            # Pour les flux très courts (< 20 paquets), on ne signale pas de problème
            # car il n'y a pas assez de données pour être pertinent
            if len(windows) < 20:
                suspected = 'none'
            else:
                # Calcule le % de fenêtres basses (hors handshake)
                if windows_stable:
                    low_window_percentage = (
                        sum(1 for w in windows_stable if 0 < w < self.low_window_threshold) /
                        len(windows_stable) * 100
                    )
                else:
                    low_window_percentage = 0

                # Détection améliorée : un problème n'est signalé que si :
                # 1. Zero windows significatifs (> 5 ou durée > 1s)
                # 2. OU fenêtres basses persistantes (> 20% du temps hors handshake)
                if zero_count > 5 or zero_window_duration > 1.0:
                    suspected = 'application'
                elif low_window_percentage > 20:  # Plus de 20% du temps avec fenêtre basse
                    suspected = 'receiver'
                else:
                    suspected = 'none'

            stats = FlowWindowStats(
                flow_key=flow_key,
                src_ip=src_part[0],
                dst_ip=dst_part[0],
                src_port=int(src_part[1]),
                dst_port=int(dst_part[1]),
                min_window=min(windows_stable) if windows_stable else min(windows),
                max_window=max(windows),
                mean_window=sum(windows) / len(windows),
                zero_window_count=zero_count,
                low_window_count=low_count,
                zero_window_total_duration=zero_window_duration,
                suspected_bottleneck=suspected
            )

            self.flow_stats[flow_key] = stats

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
