"""
Analyseur de Bursts (rafales) de paquets.
Détecte les pics de trafic qui peuvent causer des congestions.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

# Import PacketMetadata for hybrid mode support (3-5x faster)
try:
    from ..parsers.fast_parser import PacketMetadata
except ImportError:
    PacketMetadata = None


@dataclass
class BurstEvent:
    """Représente un burst détecté."""

    start_time: float
    end_time: float
    packet_count: int
    byte_count: int
    packets_per_second: float
    bytes_per_second: float
    peak_ratio: float  # Ratio par rapport à la moyenne
    top_sources: list[dict[str, Any]] = field(default_factory=list)
    top_destinations: list[dict[str, Any]] = field(default_factory=list)
    protocol_breakdown: dict[str, int] = field(default_factory=dict)

    def duration_ms(self) -> float:
        """Durée du burst en millisecondes."""
        return (self.end_time - self.start_time) * 1000

    def start_iso(self) -> str:
        """Timestamp de début en format ISO."""
        return datetime.fromtimestamp(self.start_time).strftime("%H:%M:%S.%f")[:-3]

    def end_iso(self) -> str:
        """Timestamp de fin en format ISO."""
        return datetime.fromtimestamp(self.end_time).strftime("%H:%M:%S.%f")[:-3]


@dataclass
class IntervalStats:
    """Statistiques pour un intervalle de temps."""

    start_time: float
    packets: int = 0
    bytes: int = 0
    sources: dict[str, int] = field(default_factory=dict)
    destinations: dict[str, int] = field(default_factory=dict)
    protocols: dict[str, int] = field(default_factory=dict)


class BurstAnalyzer:
    """
    Analyseur de bursts (rafales) de paquets.

    Détecte les intervalles où le trafic dépasse significativement la moyenne,
    ce qui peut indiquer:
    - Congestion réseau
    - Applications mal optimisées (envoi en bloc)
    - Démarrage de transferts massifs
    - Attaques potentielles (DDoS, scans)
    """

    def __init__(
        self,
        interval_ms: int = 100,
        burst_threshold_multiplier: float = 3.0,
        min_packets_for_burst: int = 50,
        merge_gap_ms: int = 200,
    ):
        """
        Initialise l'analyseur.

        Args:
            interval_ms: Taille de l'intervalle d'analyse en millisecondes
            burst_threshold_multiplier: Facteur multiplicateur pour détecter un burst
                                       (3.0 = 3x la moyenne)
            min_packets_for_burst: Nombre minimum de paquets pour considérer un burst
            merge_gap_ms: Écart maximum pour fusionner des bursts consécutifs
        """
        self.interval_ms = interval_ms
        self.interval_sec = interval_ms / 1000.0
        self.burst_threshold_multiplier = burst_threshold_multiplier
        self.min_packets_for_burst = min_packets_for_burst
        self.merge_gap_ms = merge_gap_ms

        # Stockage par intervalle: timestamp_bucket -> IntervalStats
        self.intervals: dict[int, IntervalStats] = {}

        # Stats globales
        self.total_packets = 0
        self.total_bytes = 0
        self.first_packet_time: Optional[float] = None
        self.last_packet_time: Optional[float] = None

        # Bursts détectés
        self.bursts: list[BurstEvent] = []

        # Memory optimization: limit intervals with sliding window
        self.max_intervals = 100000  # Limit to prevent memory exhaustion
        self._packet_counter = 0
        self._cleanup_interval = 10000  # Cleanup every 10k packets

    def _get_interval_bucket(self, timestamp: float) -> int:
        """Calcule le bucket d'intervalle pour un timestamp."""
        return int(timestamp / self.interval_sec)

    def _get_protocol(self, packet: Packet) -> str:
        """Détermine le protocole du paquet."""
        if packet.haslayer(TCP):
            return "TCP"
        elif packet.haslayer(UDP):
            return "UDP"
        elif packet.haslayer(IP):
            return "IP"
        return "Other"

    def process_packet(self, packet: Union[Packet, "PacketMetadata"], packet_num: int = 0) -> None:
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
        packet_len = len(packet)

        # Stats globales
        self.total_packets += 1
        self.total_bytes += packet_len

        if self.first_packet_time is None:
            self.first_packet_time = timestamp
        self.last_packet_time = timestamp

        # Memory optimization: periodic cleanup of old intervals
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_old_intervals()

        # Bucket d'intervalle
        bucket = self._get_interval_bucket(timestamp)

        if bucket not in self.intervals:
            self.intervals[bucket] = IntervalStats(start_time=bucket * self.interval_sec)

        interval = self.intervals[bucket]
        interval.packets += 1
        interval.bytes += packet_len

        # Sources et destinations
        src_ip = ip.src
        dst_ip = ip.dst
        interval.sources[src_ip] = interval.sources.get(src_ip, 0) + 1
        interval.destinations[dst_ip] = interval.destinations.get(dst_ip, 0) + 1

        # Protocole
        proto = self._get_protocol(packet)
        interval.protocols[proto] = interval.protocols.get(proto, 0) + 1

    def _process_metadata(self, metadata: "PacketMetadata", packet_num: int) -> None:
        """
        PERFORMANCE OPTIMIZED: Process lightweight PacketMetadata (3-5x faster than Scapy).

        This method replicates burst detection logic but uses direct attribute access
        from dpkt-extracted metadata.

        Args:
            metadata: Lightweight packet metadata from dpkt
            packet_num: Packet sequence number in capture
        """
        timestamp = metadata.timestamp
        packet_len = metadata.packet_length

        # Stats globales
        self.total_packets += 1
        self.total_bytes += packet_len

        if self.first_packet_time is None:
            self.first_packet_time = timestamp
        self.last_packet_time = timestamp

        # Memory optimization: periodic cleanup of old intervals
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_old_intervals()

        # Bucket d'intervalle
        bucket = self._get_interval_bucket(timestamp)

        if bucket not in self.intervals:
            self.intervals[bucket] = IntervalStats(start_time=bucket * self.interval_sec)

        interval = self.intervals[bucket]
        interval.packets += 1
        interval.bytes += packet_len

        # Sources et destinations
        src_ip = metadata.src_ip
        dst_ip = metadata.dst_ip
        interval.sources[src_ip] = interval.sources.get(src_ip, 0) + 1
        interval.destinations[dst_ip] = interval.destinations.get(dst_ip, 0) + 1

        # Protocole (already extracted by dpkt)
        proto = metadata.protocol
        interval.protocols[proto] = interval.protocols.get(proto, 0) + 1

    def _cleanup_old_intervals(self) -> None:
        """Remove oldest intervals when exceeding max_intervals limit."""
        if len(self.intervals) <= self.max_intervals:
            return

        # Sort buckets by key (time order) and keep the most recent ones
        sorted_buckets = sorted(self.intervals.keys())
        buckets_to_remove = sorted_buckets[: -self.max_intervals]

        # Remove oldest intervals
        for bucket in buckets_to_remove:
            del self.intervals[bucket]

    def finalize(self) -> None:
        """Finalise l'analyse et détecte les bursts."""
        if not self.intervals:
            return

        # Calculer la moyenne
        total_intervals = len(self.intervals)
        if total_intervals == 0:
            return

        avg_packets = self.total_packets / total_intervals
        avg_bytes = self.total_bytes / total_intervals

        # Seuil pour burst
        packet_threshold = max(avg_packets * self.burst_threshold_multiplier, self.min_packets_for_burst)

        # Détecter les intervalles en burst
        burst_intervals = []
        for bucket, interval in sorted(self.intervals.items()):
            if interval.packets >= packet_threshold:
                burst_intervals.append((bucket, interval))

        # Fusionner les bursts consécutifs
        if not burst_intervals:
            return

        merged_bursts = []
        current_burst_start = burst_intervals[0]
        current_burst_end = burst_intervals[0]
        current_intervals = [burst_intervals[0]]

        for i in range(1, len(burst_intervals)):
            bucket, interval = burst_intervals[i]
            prev_bucket = current_burst_end[0]

            # Vérifier si on doit fusionner
            gap_buckets = bucket - prev_bucket
            gap_ms = gap_buckets * self.interval_ms

            if gap_ms <= self.merge_gap_ms:
                # Fusionner
                current_burst_end = (bucket, interval)
                current_intervals.append((bucket, interval))
            else:
                # Nouveau burst
                merged_bursts.append(current_intervals)
                current_burst_start = (bucket, interval)
                current_burst_end = (bucket, interval)
                current_intervals = [(bucket, interval)]

        # Ajouter le dernier burst
        merged_bursts.append(current_intervals)

        # Créer les événements de burst
        for burst_intervals_group in merged_bursts:
            self._create_burst_event(burst_intervals_group, avg_packets, avg_bytes)

    def _create_burst_event(self, intervals: list[tuple], avg_packets: float, avg_bytes: float) -> None:
        """Crée un événement de burst à partir d'intervalles."""
        if not intervals:
            return

        first_bucket, first_interval = intervals[0]
        last_bucket, last_interval = intervals[-1]

        start_time = first_interval.start_time
        end_time = last_bucket * self.interval_sec + self.interval_sec

        # Agréger les stats
        total_packets = 0
        total_bytes = 0
        sources: dict[str, int] = defaultdict(int)
        destinations: dict[str, int] = defaultdict(int)
        protocols: dict[str, int] = defaultdict(int)

        for bucket, interval in intervals:
            total_packets += interval.packets
            total_bytes += interval.bytes

            for src, count in interval.sources.items():
                sources[src] += count
            for dst, count in interval.destinations.items():
                destinations[dst] += count
            for proto, count in interval.protocols.items():
                protocols[proto] += count

        duration = end_time - start_time
        if duration <= 0:
            duration = self.interval_sec

        # Top sources/destinations
        top_sources = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:5]
        top_destinations = sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:5]

        # Calculer le ratio par rapport à la moyenne
        packets_in_burst_intervals = total_packets / len(intervals) if intervals else 0
        peak_ratio = packets_in_burst_intervals / avg_packets if avg_packets > 0 else 0

        burst = BurstEvent(
            start_time=start_time,
            end_time=end_time,
            packet_count=total_packets,
            byte_count=total_bytes,
            packets_per_second=total_packets / duration,
            bytes_per_second=total_bytes / duration,
            peak_ratio=peak_ratio,
            top_sources=[{"ip": ip, "packets": count} for ip, count in top_sources],
            top_destinations=[{"ip": ip, "packets": count} for ip, count in top_destinations],
            protocol_breakdown=dict(protocols),
        )

        self.bursts.append(burst)

    def _generate_report(self) -> dict[str, Any]:
        """Generate report for hybrid mode compatibility."""
        return self.get_results()

    def get_results(self) -> dict[str, Any]:
        """Retourne les résultats complets de l'analyse."""
        if self.first_packet_time is None or self.last_packet_time is None:
            capture_duration = 0
        else:
            capture_duration = self.last_packet_time - self.first_packet_time

        # Stats sur les intervalles
        interval_packets = [i.packets for i in self.intervals.values()]
        interval_bytes = [i.bytes for i in self.intervals.values()]

        if interval_packets:
            avg_packets_per_interval = sum(interval_packets) / len(interval_packets)
            max_packets_per_interval = max(interval_packets)
            min_packets_per_interval = min(interval_packets)

            # Écart-type
            variance = sum((p - avg_packets_per_interval) ** 2 for p in interval_packets) / len(interval_packets)
            std_dev = variance**0.5
        else:
            avg_packets_per_interval = 0
            max_packets_per_interval = 0
            min_packets_per_interval = 0
            std_dev = 0

        # Calculer le coefficient de variation (mesure de régularité)
        cv = (std_dev / avg_packets_per_interval * 100) if avg_packets_per_interval > 0 else 0

        return {
            "summary": {
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "capture_duration_seconds": round(capture_duration, 2),
                "interval_ms": self.interval_ms,
                "total_intervals": len(self.intervals),
                "burst_threshold_multiplier": self.burst_threshold_multiplier,
                "bursts_detected": len(self.bursts),
                "packets_in_bursts": sum(b.packet_count for b in self.bursts),
                "bytes_in_bursts": sum(b.byte_count for b in self.bursts),
            },
            "interval_stats": {
                "avg_packets_per_interval": round(avg_packets_per_interval, 2),
                "max_packets_per_interval": max_packets_per_interval,
                "min_packets_per_interval": min_packets_per_interval,
                "std_deviation": round(std_dev, 2),
                "coefficient_of_variation": round(cv, 1),
                "traffic_regularity": "Régulier" if cv < 50 else ("Variable" if cv < 100 else "Très irrégulier"),
            },
            "bursts": [
                {
                    "start_time": b.start_time,
                    "end_time": b.end_time,
                    "start_iso": b.start_iso(),
                    "end_iso": b.end_iso(),
                    "duration_ms": round(b.duration_ms(), 1),
                    "packet_count": b.packet_count,
                    "byte_count": b.byte_count,
                    "packets_per_second": round(b.packets_per_second, 0),
                    "bytes_per_second": round(b.bytes_per_second, 0),
                    "mbps": round(b.bytes_per_second * 8 / 1_000_000, 2),
                    "peak_ratio": round(b.peak_ratio, 1),
                    "top_sources": b.top_sources,
                    "top_destinations": b.top_destinations,
                    "protocol_breakdown": b.protocol_breakdown,
                }
                for b in self.bursts[:50]  # Limiter à 50 bursts
            ],
            "worst_burst": self._get_worst_burst() if self.bursts else None,
        }

    def _get_worst_burst(self) -> Optional[dict[str, Any]]:
        """Retourne le burst le plus intense."""
        if not self.bursts:
            return None

        worst = max(self.bursts, key=lambda b: b.peak_ratio)
        return {
            "start_iso": worst.start_iso(),
            "duration_ms": round(worst.duration_ms(), 1),
            "packet_count": worst.packet_count,
            "packets_per_second": round(worst.packets_per_second, 0),
            "peak_ratio": round(worst.peak_ratio, 1),
            "top_source": worst.top_sources[0] if worst.top_sources else None,
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse."""
        results = self.get_results()
        summary = results["summary"]
        interval_stats = results["interval_stats"]

        lines = [
            "=== Analyse des Bursts de Paquets ===",
            f"Intervalle d'analyse: {summary['interval_ms']}ms",
            f"Intervalles analysés: {summary['total_intervals']}",
            f"Seuil de burst: {summary['burst_threshold_multiplier']}x la moyenne",
            "",
            f"Régularité du trafic: {interval_stats['traffic_regularity']} (CV: {interval_stats['coefficient_of_variation']}%)",
            f"Paquets/intervalle: moy={interval_stats['avg_packets_per_interval']}, "
            f"min={interval_stats['min_packets_per_interval']}, "
            f"max={interval_stats['max_packets_per_interval']}",
            "",
            f"Bursts détectés: {summary['bursts_detected']}",
        ]

        if results["worst_burst"]:
            wb = results["worst_burst"]
            lines.append(
                f"Pire burst: {wb['start_iso']} - {wb['packet_count']} paquets "
                f"({wb['packets_per_second']} pkt/s, {wb['peak_ratio']}x la moyenne)"
            )
            if wb["top_source"]:
                lines.append(f"  Source principale: {wb['top_source']['ip']} ({wb['top_source']['packets']} paquets)")

        return "\n".join(lines)
