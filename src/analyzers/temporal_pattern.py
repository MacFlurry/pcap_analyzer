"""
Analyseur de patterns temporels.
Détecte les variations de trafic dans le temps, périodicités et anomalies.
"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple, Union

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

# Import PacketMetadata for hybrid mode support (3-5x faster)
try:
    from ..parsers.fast_parser import PacketMetadata
except ImportError:
    PacketMetadata = None


@dataclass
class TimeSlot:
    """Statistiques pour un créneau temporel."""

    timestamp: float
    packets: int = 0
    bytes: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    unique_sources: set = field(default_factory=set)
    unique_destinations: set = field(default_factory=set)

    def __post_init__(self):
        if not isinstance(self.unique_sources, set):
            self.unique_sources = set()
        if not isinstance(self.unique_destinations, set):
            self.unique_destinations = set()


@dataclass
class PeriodicPattern:
    """Pattern périodique détecté."""

    interval_seconds: float
    confidence: float
    occurrences: int
    source_ip: Optional[str] = None
    description: str = ""


class TemporalPatternAnalyzer:
    """
    Analyseur de patterns temporels dans le trafic réseau.

    Détecte:
    - Distribution horaire du trafic
    - Pics et creux d'activité
    - Patterns périodiques (heartbeat, polling, cron)
    - Anomalies temporelles
    """

    def __init__(
        self,
        slot_duration_seconds: int = 60,
        periodicity_min_interval: float = 1.0,
        periodicity_max_interval: float = 300.0,
        periodicity_tolerance: float = 0.1,
    ):
        """
        Initialise l'analyseur.

        Args:
            slot_duration_seconds: Durée d'un créneau en secondes (défaut: 1 min)
            periodicity_min_interval: Intervalle minimum pour détecter périodicité
            periodicity_max_interval: Intervalle maximum pour détecter périodicité
            periodicity_tolerance: Tolérance pour matcher des intervalles (10%)
        """
        self.slot_duration = slot_duration_seconds
        self.periodicity_min_interval = periodicity_min_interval
        self.periodicity_max_interval = periodicity_max_interval
        self.periodicity_tolerance = periodicity_tolerance

        # Stockage par créneau
        self.time_slots: Dict[int, TimeSlot] = {}

        # Pour détection de périodicité par source
        self.packet_times_by_source: Dict[str, List[float]] = defaultdict(list)

        # Stats globales
        self.total_packets = 0
        self.total_bytes = 0
        self.first_packet_time: Optional[float] = None
        self.last_packet_time: Optional[float] = None

        # Memory optimization: limit stored data
        self.max_packets_per_source = 1000
        self.max_sources = 500  # Limit total sources tracked for periodicity
        self._packet_counter = 0
        self._cleanup_interval = 10000  # Cleanup every 10k packets

    def _get_slot_key(self, timestamp: float) -> int:
        """Calcule la clé du créneau pour un timestamp."""
        return int(timestamp / self.slot_duration)

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

        # Créneau temporel
        slot_key = self._get_slot_key(timestamp)

        if slot_key not in self.time_slots:
            self.time_slots[slot_key] = TimeSlot(timestamp=slot_key * self.slot_duration)

        slot = self.time_slots[slot_key]
        slot.packets += 1
        slot.bytes += packet_len
        slot.unique_sources.add(ip.src)
        slot.unique_destinations.add(ip.dst)

        if packet.haslayer(TCP):
            slot.tcp_packets += 1
        elif packet.haslayer(UDP):
            slot.udp_packets += 1

        # Memory optimization: periodic cleanup of sources
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_excess_sources()

        # Stocker timestamps pour détection de périodicité
        src_ip = ip.src
        if len(self.packet_times_by_source[src_ip]) < self.max_packets_per_source:
            self.packet_times_by_source[src_ip].append(timestamp)

    def _process_metadata(self, metadata: "PacketMetadata", packet_num: int) -> None:
        """
        PERFORMANCE OPTIMIZED: Process lightweight PacketMetadata (3-5x faster than Scapy).

        This method replicates temporal pattern analysis logic but uses direct attribute access
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

        # Créneau temporel
        slot_key = self._get_slot_key(timestamp)

        if slot_key not in self.time_slots:
            self.time_slots[slot_key] = TimeSlot(timestamp=slot_key * self.slot_duration)

        slot = self.time_slots[slot_key]
        slot.packets += 1
        slot.bytes += packet_len
        slot.unique_sources.add(metadata.src_ip)
        slot.unique_destinations.add(metadata.dst_ip)

        # Protocol detection (already extracted by dpkt)
        if metadata.protocol == "TCP":
            slot.tcp_packets += 1
        elif metadata.protocol == "UDP":
            slot.udp_packets += 1

        # Memory optimization: periodic cleanup of sources
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_excess_sources()

        # Stocker timestamps pour détection de périodicité
        src_ip = metadata.src_ip
        if len(self.packet_times_by_source[src_ip]) < self.max_packets_per_source:
            self.packet_times_by_source[src_ip].append(timestamp)

    def _cleanup_excess_sources(self) -> None:
        """Remove least active sources when exceeding max_sources limit."""
        if len(self.packet_times_by_source) <= self.max_sources:
            return

        # Sort sources by packet count (activity level)
        sources_by_activity = sorted(self.packet_times_by_source.items(), key=lambda x: len(x[1]), reverse=True)

        # Keep only the most active sources
        self.packet_times_by_source = defaultdict(list, sources_by_activity[: self.max_sources])

    def finalize(self) -> None:
        """Finalise l'analyse."""
        pass

    def _detect_periodicity(self, timestamps: List[float], min_occurrences: int = 5) -> List[PeriodicPattern]:
        """
        Détecte des patterns périodiques dans une liste de timestamps.
        """
        if len(timestamps) < min_occurrences:
            return []

        # Calculer les intervalles entre paquets consécutifs
        intervals = []
        sorted_ts = sorted(timestamps)
        for i in range(1, len(sorted_ts)):
            interval = sorted_ts[i] - sorted_ts[i - 1]
            if self.periodicity_min_interval <= interval <= self.periodicity_max_interval:
                intervals.append(interval)

        if len(intervals) < min_occurrences:
            return []

        # Grouper les intervalles similaires
        interval_groups: Dict[float, int] = defaultdict(int)

        for interval in intervals:
            # Arrondir à la seconde près pour grouper
            rounded = round(interval)
            if rounded > 0:
                interval_groups[rounded] += 1

        # Trouver les intervalles fréquents
        patterns = []
        for interval, count in interval_groups.items():
            if count >= min_occurrences:
                # Calculer la confiance (ratio d'intervalles matchant)
                confidence = count / len(intervals)
                if confidence >= 0.3:  # Au moins 30% des intervalles
                    patterns.append(
                        PeriodicPattern(
                            interval_seconds=interval,
                            confidence=confidence,
                            occurrences=count,
                            description=self._describe_interval(interval),
                        )
                    )

        return sorted(patterns, key=lambda p: p.occurrences, reverse=True)

    def _describe_interval(self, seconds: float) -> str:
        """Décrit un intervalle en termes compréhensibles."""
        if seconds < 1:
            return f"{seconds*1000:.0f}ms"
        elif seconds == 1:
            return "1 seconde (heartbeat?)"
        elif seconds == 5:
            return "5 secondes (polling rapide?)"
        elif seconds == 10:
            return "10 secondes"
        elif seconds == 30:
            return "30 secondes (health check?)"
        elif seconds == 60:
            return "1 minute (cron?)"
        elif seconds == 300:
            return "5 minutes (monitoring?)"
        elif seconds < 60:
            return f"{seconds:.0f} secondes"
        else:
            minutes = seconds / 60
            return f"{minutes:.1f} minutes"

    def _get_hourly_distribution(self) -> Dict[int, Dict[str, Any]]:
        """Calcule la distribution par heure de la journée."""
        hourly: Dict[int, Dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0, "slots": 0})

        for slot_key, slot in self.time_slots.items():
            dt = datetime.fromtimestamp(slot.timestamp)
            hour = dt.hour
            hourly[hour]["packets"] += slot.packets
            hourly[hour]["bytes"] += slot.bytes
            hourly[hour]["slots"] += 1

        return dict(hourly)

    def _find_peaks_and_valleys(self) -> Tuple[List[Dict], List[Dict]]:
        """Trouve les pics et creux de trafic."""
        if not self.time_slots:
            return [], []

        # Calculer la moyenne
        packets_per_slot = [s.packets for s in self.time_slots.values()]
        avg = sum(packets_per_slot) / len(packets_per_slot)
        std_dev = math.sqrt(sum((p - avg) ** 2 for p in packets_per_slot) / len(packets_per_slot))

        peaks = []
        valleys = []

        for slot_key, slot in sorted(self.time_slots.items()):
            dt = datetime.fromtimestamp(slot.timestamp)
            time_str = dt.strftime("%H:%M:%S")

            # Pic: > moyenne + 2*écart-type
            if slot.packets > avg + 2 * std_dev and std_dev > 0:
                ratio = slot.packets / avg if avg > 0 else 0
                peaks.append(
                    {
                        "time": time_str,
                        "timestamp": slot.timestamp,
                        "packets": slot.packets,
                        "bytes": slot.bytes,
                        "ratio": round(ratio, 1),
                        "unique_sources": len(slot.unique_sources),
                    }
                )

            # Creux: < moyenne - 1.5*écart-type (et au moins quelques paquets attendus)
            if avg > 10 and slot.packets < avg - 1.5 * std_dev and slot.packets < avg * 0.3:
                ratio = slot.packets / avg if avg > 0 else 0
                valleys.append(
                    {"time": time_str, "timestamp": slot.timestamp, "packets": slot.packets, "ratio": round(ratio, 2)}
                )

        # Trier et limiter
        peaks.sort(key=lambda x: x["packets"], reverse=True)
        valleys.sort(key=lambda x: x["packets"])

        return peaks[:20], valleys[:10]

    def _detect_global_periodicity(self) -> List[Dict[str, Any]]:
        """Détecte les patterns périodiques globaux."""
        all_patterns = []

        # Analyser les sources les plus actives
        sorted_sources = sorted(self.packet_times_by_source.items(), key=lambda x: len(x[1]), reverse=True)[
            :20
        ]  # Top 20 sources

        for src_ip, timestamps in sorted_sources:
            if len(timestamps) < 10:
                continue

            patterns = self._detect_periodicity(timestamps)
            for p in patterns[:3]:  # Top 3 patterns par source
                all_patterns.append(
                    {
                        "source_ip": src_ip,
                        "interval_seconds": p.interval_seconds,
                        "description": p.description,
                        "confidence": round(p.confidence * 100, 1),
                        "occurrences": p.occurrences,
                    }
                )

        # Trier par occurrences
        all_patterns.sort(key=lambda x: x["occurrences"], reverse=True)
        return all_patterns[:15]

    def _generate_report(self) -> Dict[str, Any]:
        """Generate report for hybrid mode compatibility."""
        return self.get_results()

    def get_results(self) -> Dict[str, Any]:
        """Retourne les résultats complets de l'analyse."""
        if self.first_packet_time is None or self.last_packet_time is None:
            capture_duration = 0
            capture_start = ""
            capture_end = ""
        else:
            capture_duration = self.last_packet_time - self.first_packet_time
            capture_start = datetime.fromtimestamp(self.first_packet_time).strftime("%Y-%m-%d %H:%M:%S")
            capture_end = datetime.fromtimestamp(self.last_packet_time).strftime("%Y-%m-%d %H:%M:%S")

        # Stats par créneau
        packets_per_slot = [s.packets for s in self.time_slots.values()]
        bytes_per_slot = [s.bytes for s in self.time_slots.values()]

        if packets_per_slot:
            avg_packets = sum(packets_per_slot) / len(packets_per_slot)
            max_packets = max(packets_per_slot)
            min_packets = min(packets_per_slot)
            avg_bytes = sum(bytes_per_slot) / len(bytes_per_slot)
        else:
            avg_packets = max_packets = min_packets = avg_bytes = 0

        # Distribution horaire
        hourly_dist = self._get_hourly_distribution()

        # Pics et creux
        peaks, valleys = self._find_peaks_and_valleys()

        # Patterns périodiques
        periodic_patterns = self._detect_global_periodicity()

        # Timeline (échantillonnée si trop de créneaux)
        timeline = []
        sorted_slots = sorted(self.time_slots.items())
        step = max(1, len(sorted_slots) // 100)  # Max 100 points

        for i in range(0, len(sorted_slots), step):
            slot_key, slot = sorted_slots[i]
            dt = datetime.fromtimestamp(slot.timestamp)
            timeline.append(
                {
                    "time": dt.strftime("%H:%M:%S"),
                    "timestamp": slot.timestamp,
                    "packets": slot.packets,
                    "bytes": slot.bytes,
                    "mbps": round(slot.bytes * 8 / self.slot_duration / 1_000_000, 3),
                }
            )

        return {
            "summary": {
                "capture_start": capture_start,
                "capture_end": capture_end,
                "capture_duration_seconds": round(capture_duration, 2),
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "slot_duration_seconds": self.slot_duration,
                "total_slots": len(self.time_slots),
                "peaks_detected": len(peaks),
                "valleys_detected": len(valleys),
                "periodic_patterns_detected": len(periodic_patterns),
            },
            "slot_stats": {
                "avg_packets_per_slot": round(avg_packets, 1),
                "max_packets_per_slot": max_packets,
                "min_packets_per_slot": min_packets,
                "avg_bytes_per_slot": round(avg_bytes, 0),
                "peak_to_avg_ratio": round(max_packets / avg_packets, 1) if avg_packets > 0 else 0,
            },
            "hourly_distribution": [
                {
                    "hour": hour,
                    "hour_label": f"{hour:02d}:00",
                    "packets": stats["packets"],
                    "bytes": stats["bytes"],
                    "avg_per_slot": round(stats["packets"] / stats["slots"], 1) if stats["slots"] > 0 else 0,
                }
                for hour, stats in sorted(hourly_dist.items())
            ],
            "peaks": peaks,
            "valleys": valleys,
            "periodic_patterns": periodic_patterns,
            "timeline": timeline,
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse."""
        results = self.get_results()
        summary = results["summary"]
        slot_stats = results["slot_stats"]

        lines = [
            "=== Analyse des Patterns Temporels ===",
            f"Période: {summary['capture_start']} → {summary['capture_end']}",
            f"Durée: {summary['capture_duration_seconds']:.0f}s ({summary['total_slots']} créneaux de {summary['slot_duration_seconds']}s)",
            "",
            f"Paquets/créneau: moy={slot_stats['avg_packets_per_slot']:.0f}, "
            f"min={slot_stats['min_packets_per_slot']}, max={slot_stats['max_packets_per_slot']}",
            f"Ratio pic/moyenne: {slot_stats['peak_to_avg_ratio']}x",
            "",
            f"Pics détectés: {summary['peaks_detected']}",
            f"Creux détectés: {summary['valleys_detected']}",
            f"Patterns périodiques: {summary['periodic_patterns_detected']}",
        ]

        if results["peaks"]:
            lines.append("")
            lines.append("Top 3 pics:")
            for p in results["peaks"][:3]:
                lines.append(f"  - {p['time']}: {p['packets']} paquets ({p['ratio']}x la moyenne)")

        if results["periodic_patterns"]:
            lines.append("")
            lines.append("Patterns périodiques détectés:")
            for p in results["periodic_patterns"][:3]:
                lines.append(
                    f"  - {p['source_ip']}: toutes les {p['description']} "
                    f"({p['occurrences']} occurrences, {p['confidence']}% confiance)"
                )

        return "\n".join(lines)
