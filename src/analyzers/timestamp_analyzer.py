"""
Analyseur de timestamps - Détection des ruptures de flux et délais anormaux
"""

from scapy.all import rdpcap, Packet
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
import statistics


@dataclass
class TimestampGap:
    """Représente un gap temporel anormal entre deux paquets"""
    packet_num_before: int
    packet_num_after: int
    timestamp_before: float
    timestamp_after: float
    gap_duration: float
    src_ip: str
    dst_ip: str
    protocol: str
    is_abnormal: bool = True


class TimestampAnalyzer:
    """Analyseur de timestamps pour détecter les délais anormaux"""

    def __init__(self, gap_threshold: float = 1.0):
        """
        Initialise l'analyseur de timestamps

        Args:
            gap_threshold: Seuil de détection des gaps en secondes
        """
        self.gap_threshold = gap_threshold
        self.gaps: List[TimestampGap] = []
        # Memory optimization: limit stored intervals using sliding window
        self.packet_intervals: List[float] = []
        self._max_intervals = 100000  # Limit to prevent memory exhaustion
        self.total_packets = 0
        self.capture_duration = 0.0
        self.first_timestamp = None
        self.last_timestamp = None
        self._packet_count = 0

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyse les timestamps des paquets

        Args:
            packets: Liste des paquets Scapy

        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        self.total_packets = len(packets)

        if self.total_packets < 2:
            return self._generate_report()

        # Analyse séquentielle des timestamps
        for i, packet in enumerate(packets):
            self.process_packet(packet, i)

        return self.finalize()

    def process_packet(self, packet: Packet, packet_num: int) -> None:
        """Traite un paquet individuel"""
        if not hasattr(packet, 'time'):
            return

        self._packet_count += 1
        current_time = float(packet.time)

        # Premier paquet
        if self.first_timestamp is None:
            self.first_timestamp = current_time

        self.last_timestamp = current_time

        # Calcul de l'intervalle avec le paquet précédent
        # Note: On stocke prev_time dans l'instance maintenant
        if hasattr(self, '_prev_time') and self._prev_time is not None:
            interval = current_time - self._prev_time

            # Memory optimization: use sliding window to limit memory usage
            if len(self.packet_intervals) < self._max_intervals:
                self.packet_intervals.append(interval)
            else:
                # Keep only the most recent intervals (sliding window)
                self.packet_intervals = self.packet_intervals[-self._max_intervals+1:] + [interval]

            # Détection de gap anormal
            if interval > self.gap_threshold:
                gap = TimestampGap(
                    packet_num_before=packet_num - 1,
                    packet_num_after=packet_num,
                    timestamp_before=self._prev_time,
                    timestamp_after=current_time,
                    gap_duration=interval,
                    src_ip=self._get_src_ip(packet),
                    dst_ip=self._get_dst_ip(packet),
                    protocol=self._get_protocol(packet),
                    is_abnormal=True
                )
                self.gaps.append(gap)

        self._prev_time = current_time

    def finalize(self) -> Dict[str, Any]:
        """Finalise l'analyse et génère le rapport"""
        # Met à jour total_packets avec le compteur streaming
        if self._packet_count > 0:
            self.total_packets = self._packet_count
            
        if self.first_timestamp and self.last_timestamp:
            self.capture_duration = self.last_timestamp - self.first_timestamp

        return self._generate_report()

    def _get_src_ip(self, packet: Packet) -> str:
        """Extrait l'IP source du paquet"""
        if packet.haslayer('IP'):
            return packet['IP'].src
        elif packet.haslayer('IPv6'):
            return packet['IPv6'].src
        return "N/A"

    def _get_dst_ip(self, packet: Packet) -> str:
        """Extrait l'IP destination du paquet"""
        if packet.haslayer('IP'):
            return packet['IP'].dst
        elif packet.haslayer('IPv6'):
            return packet['IPv6'].dst
        return "N/A"

    def _get_protocol(self, packet: Packet) -> str:
        """Détermine le protocole du paquet"""
        if packet.haslayer('TCP'):
            return 'TCP'
        elif packet.haslayer('UDP'):
            return 'UDP'
        elif packet.haslayer('ICMP'):
            return 'ICMP'
        elif packet.haslayer('IPv6'):
            return 'IPv6'
        elif packet.haslayer('IP'):
            return 'IP'
        return 'Other'

    def _detect_periodic_pattern(self) -> bool:
        """
        Détecte si les gaps forment un pattern périodique (polling, heartbeat, etc.)

        Returns:
            True si les gaps semblent être un comportement applicatif régulier
        """
        if len(self.gaps) < 3:
            return False

        # Extraire les durées des gaps
        gap_durations = [gap.gap_duration for gap in self.gaps]

        # Calculer la moyenne et l'écart-type
        mean_gap = statistics.mean(gap_durations)

        if len(gap_durations) < 2:
            return False

        stdev_gap = statistics.stdev(gap_durations)

        # Si l'écart-type est < 10% de la moyenne, c'est probablement périodique
        # (variance très faible = comportement régulier)
        coefficient_of_variation = (stdev_gap / mean_gap) if mean_gap > 0 else float('inf')

        return coefficient_of_variation < 0.10

    def _mark_periodic_gaps(self) -> None:
        """
        Marque les gaps qui correspondent au pattern périodique comme non anormaux
        """
        if len(self.gaps) < 3:
            return

        gap_durations = [gap.gap_duration for gap in self.gaps]
        mean_gap = statistics.mean(gap_durations)

        # Marquer les gaps qui sont proches de la moyenne comme "non anormaux"
        for gap in self.gaps:
            deviation = abs(gap.gap_duration - mean_gap) / mean_gap if mean_gap > 0 else 0
            if deviation <= 0.20:
                gap.is_abnormal = False

    def _generate_report(self) -> Dict[str, Any]:
        """Génère le rapport d'analyse des timestamps"""
        stats = {}

        if self.packet_intervals:
            stats = {
                'min_interval': min(self.packet_intervals),
                'max_interval': max(self.packet_intervals),
                'mean_interval': statistics.mean(self.packet_intervals),
                'median_interval': statistics.median(self.packet_intervals),
            }

            if len(self.packet_intervals) > 1:
                stats['stdev_interval'] = statistics.stdev(self.packet_intervals)

        # Détection de pattern périodique dans les gaps
        periodic_pattern_detected = self._detect_periodic_pattern()
        
        non_periodic_gaps = len(self.gaps)
        if periodic_pattern_detected:
            self._mark_periodic_gaps()
            non_periodic_gaps = sum(1 for gap in self.gaps if gap.is_abnormal)

        return {
            'total_packets': self.total_packets,
            'capture_duration_seconds': self.capture_duration,
            'first_timestamp': self.first_timestamp,
            'last_timestamp': self.last_timestamp,
            'gap_threshold_seconds': self.gap_threshold,
            'gaps_detected': len(self.gaps),
            'gaps': [asdict(gap) for gap in self.gaps],
            'interval_statistics': stats,
            'packets_per_second': self.total_packets / self.capture_duration if self.capture_duration > 0 else 0,
            'periodic_pattern_detected': periodic_pattern_detected,
            'non_periodic_gaps': non_periodic_gaps
        }

    def get_gaps_summary(self) -> str:
        """Retourne un résumé textuel des gaps détectés"""
        # Filtrer pour ne garder que les gaps anormaux
        abnormal_gaps = [gap for gap in self.gaps if getattr(gap, 'is_abnormal', True)]
        
        if not abnormal_gaps:
            if self.gaps:
                return f"ℹ️ {len(self.gaps)} gap(s) périodique(s) détecté(s) (comportement normal)."
            return "Aucun gap temporel anormal détecté."

        summary = f"🔴 {len(abnormal_gaps)} gap(s) temporel(s) anormal(aux) détecté(s)"
        if len(self.gaps) > len(abnormal_gaps):
            summary += f" (sur {len(self.gaps)} total):\n"
        else:
            summary += ":\n"

        for i, gap in enumerate(abnormal_gaps, 1):
            summary += f"\n  Gap #{i}:\n"
            summary += f"    - Entre paquets {gap.packet_num_before} et {gap.packet_num_after}\n"
            summary += f"    - Durée: {gap.gap_duration:.3f}s\n"
            summary += f"    - Direction: {gap.src_ip} → {gap.dst_ip}\n"
            summary += f"    - Protocole: {gap.protocol}\n"

        return summary

    def filter_by_latency(self, min_latency: float) -> List[Tuple[int, int, float]]:
        """
        Filtre les gaps par latence minimale

        Args:
            min_latency: Latence minimale en secondes

        Returns:
            Liste de tuples (packet_before, packet_after, latency)
        """
        return [
            (gap.packet_num_before, gap.packet_num_after, gap.gap_duration)
            for gap in self.gaps
            if gap.gap_duration >= min_latency
        ]
