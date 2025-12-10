"""
Analyseur de timestamps - Détection des ruptures de flux et délais anormaux
"""

import statistics
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Tuple, Union

from scapy.all import Packet, rdpcap

from ..utils.packet_utils import get_dst_ip, get_src_ip

# Support for fast parser metadata
try:
    from ..parsers.fast_parser import PacketMetadata
except ImportError:
    PacketMetadata = None


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
    """Analyseur de timestamps pour détecter les délais anormaux avec détection intelligente"""

    # Protocol-specific thresholds (RFC-compliant)
    TCP_INTERACTIVE_THRESHOLD = 30.0  # SSH, Telnet - user interaction time
    TCP_BULK_THRESHOLD = 2.5  # HTTP, FTP - TCP RTO detection (RFC 6298: min 1s)
    DNS_THRESHOLD = 5.0  # RFC 1035 recommendation
    ICMP_THRESHOLD = 2.0  # ICMP echo timeout
    DEFAULT_THRESHOLD = 1.0  # Fallback

    # Interactive TCP ports (SSH, Telnet)
    INTERACTIVE_PORTS = {22, 23}

    def __init__(self, gap_threshold: float = 1.0, intelligent_mode: bool = True):
        """
        Initialise l'analyseur de timestamps

        Args:
            gap_threshold: Seuil de détection des gaps en secondes (legacy mode)
            intelligent_mode: Active la détection intelligente par protocole et flux
        """
        self.gap_threshold = gap_threshold
        self.intelligent_mode = intelligent_mode
        self.gaps: list[TimestampGap] = []
        # Memory optimization: limit stored intervals using sliding window
        self.packet_intervals: list[float] = []
        self._max_intervals = 100000  # Limit to prevent memory exhaustion
        self.total_packets = 0
        self.capture_duration = 0.0
        self.first_timestamp = None
        self.last_timestamp = None
        self._packet_count = 0

        # Flow-aware tracking: {flow_key: last_timestamp}
        self._flow_last_timestamp: dict[str, float] = {}

    def analyze(self, packets: list[Packet]) -> dict[str, Any]:
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

    def process_packet(self, packet: Union[Packet, "PacketMetadata"], packet_num: int) -> None:
        """
        Traite un paquet individuel (Scapy Packet ou PacketMetadata).

        PERFORMANCE: Supports both Scapy packets and lightweight PacketMetadata from dpkt.
        Using PacketMetadata is 3-5x faster than Scapy packets.
        """
        # Handle PacketMetadata (from dpkt fast parser)
        if PacketMetadata and isinstance(packet, PacketMetadata):
            self._process_metadata(packet, packet_num)
            return

        # Handle Scapy Packet (legacy)
        if not hasattr(packet, "time"):
            return

        self._packet_count += 1
        current_time = float(packet.time)

        # Premier paquet
        if self.first_timestamp is None:
            self.first_timestamp = current_time

        self.last_timestamp = current_time

        # Calcul de l'intervalle avec le paquet précédent
        # Note: On stocke prev_time dans l'instance maintenant
        if hasattr(self, "_prev_time") and self._prev_time is not None:
            interval = current_time - self._prev_time

            # Memory optimization: use sliding window to limit memory usage
            if len(self.packet_intervals) < self._max_intervals:
                self.packet_intervals.append(interval)
            else:
                # Keep only the most recent intervals (sliding window)
                self.packet_intervals = self.packet_intervals[-self._max_intervals + 1 :] + [interval]

            # Détection de gap anormal
            if interval > self.gap_threshold:
                # PERFORMANCE OPTIMIZATION: Extract IP layer ONCE instead of multiple haslayer() calls
                # Old code called haslayer() ~10 times per gap, this now does it once
                src_ip, dst_ip, protocol = self._extract_packet_info_fast(packet)

                gap = TimestampGap(
                    packet_num_before=packet_num - 1,
                    packet_num_after=packet_num,
                    timestamp_before=self._prev_time,
                    timestamp_after=current_time,
                    gap_duration=interval,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    is_abnormal=True,
                )
                self.gaps.append(gap)

        self._prev_time = current_time

    def _process_metadata(self, metadata: "PacketMetadata", packet_num: int) -> None:
        """
        PERFORMANCE OPTIMIZED: Process lightweight PacketMetadata instead of full Scapy packet.

        This is 3-5x faster than processing Scapy packets because:
        - No expensive haslayer() calls
        - Direct attribute access
        - Smaller memory footprint

        With intelligent mode: Flow-aware gap detection with protocol-specific thresholds
        """
        self._packet_count += 1
        current_time = metadata.timestamp

        # Premier paquet
        if self.first_timestamp is None:
            self.first_timestamp = current_time

        self.last_timestamp = current_time

        # Intelligent mode: Flow-aware gap detection
        if self.intelligent_mode:
            flow_key = self._get_flow_key(metadata)

            # Check gap within this specific flow
            if flow_key in self._flow_last_timestamp:
                prev_time = self._flow_last_timestamp[flow_key]
                interval = current_time - prev_time

                # Memory optimization: use sliding window
                if len(self.packet_intervals) < self._max_intervals:
                    self.packet_intervals.append(interval)
                else:
                    self.packet_intervals = self.packet_intervals[-self._max_intervals + 1 :] + [interval]

                # Use protocol-specific threshold
                threshold = self._get_intelligent_threshold(metadata)

                if interval > threshold:
                    gap = TimestampGap(
                        packet_num_before=packet_num - 1,
                        packet_num_after=packet_num,
                        timestamp_before=prev_time,
                        timestamp_after=current_time,
                        gap_duration=interval,
                        src_ip=metadata.src_ip,
                        dst_ip=metadata.dst_ip,
                        protocol=metadata.protocol,
                        is_abnormal=True,
                    )
                    self.gaps.append(gap)

            # Update flow timestamp
            self._flow_last_timestamp[flow_key] = current_time

        # Legacy mode: Simple global gap detection
        else:
            if hasattr(self, "_prev_time") and self._prev_time is not None:
                interval = current_time - self._prev_time

                # Memory optimization: use sliding window
                if len(self.packet_intervals) < self._max_intervals:
                    self.packet_intervals.append(interval)
                else:
                    self.packet_intervals = self.packet_intervals[-self._max_intervals + 1 :] + [interval]

                # Détection de gap anormal (simple threshold)
                if interval > self.gap_threshold:
                    gap = TimestampGap(
                        packet_num_before=packet_num - 1,
                        packet_num_after=packet_num,
                        timestamp_before=self._prev_time,
                        timestamp_after=current_time,
                        gap_duration=interval,
                        src_ip=metadata.src_ip,
                        dst_ip=metadata.dst_ip,
                        protocol=metadata.protocol,
                        is_abnormal=True,
                    )
                    self.gaps.append(gap)

            self._prev_time = current_time

    def _get_flow_key(self, metadata: "PacketMetadata") -> str:
        """
        Generate flow key for flow-aware gap detection.

        Strategy varies by protocol:
        - TCP: Strict 5-tuple (per-connection tracking)
        - DNS/UDP: src_ip only (detect user experiencing DNS timeouts across queries)
        - ICMP: src_ip only (detect host experiencing ICMP timeouts)

        Returns:
            Flow key string
        """
        protocol = metadata.protocol

        # TCP: Strict per-connection tracking (5-tuple)
        if protocol == "TCP":
            src_port = getattr(metadata, "src_port", 0) or 0
            dst_port = getattr(metadata, "dst_port", 0) or 0
            return f"TCP:{metadata.src_ip}:{src_port}:{metadata.dst_ip}:{dst_port}"

        # DNS: Track per source IP (detect user having DNS issues)
        elif protocol == "UDP":
            src_port = getattr(metadata, "src_port", 0) or 0
            dst_port = getattr(metadata, "dst_port", 0) or 0

            if src_port == 53 or dst_port == 53:
                # DNS: Group by src_ip only (all DNS queries from this host)
                return f"DNS:{metadata.src_ip}"
            else:
                # Other UDP: Use 5-tuple
                return f"UDP:{metadata.src_ip}:{src_port}:{metadata.dst_ip}:{dst_port}"

        # ICMP: Track per source IP (detect host having ICMP issues)
        elif protocol == "ICMP":
            return f"ICMP:{metadata.src_ip}"

        # Default: protocol + src_ip
        return f"{protocol}:{metadata.src_ip}"

    def _get_intelligent_threshold(self, metadata: "PacketMetadata") -> float:
        """
        Determine protocol and port-specific gap threshold (RFC-compliant).

        Args:
            metadata: Packet metadata

        Returns:
            Threshold in seconds
        """
        protocol = metadata.protocol

        # TCP: Check if interactive (SSH, Telnet)
        if protocol == "TCP":
            src_port = getattr(metadata, "src_port", 0) or 0
            dst_port = getattr(metadata, "dst_port", 0) or 0

            if src_port in self.INTERACTIVE_PORTS or dst_port in self.INTERACTIVE_PORTS:
                return self.TCP_INTERACTIVE_THRESHOLD
            else:
                return self.TCP_BULK_THRESHOLD

        # DNS: RFC 1035 (5 seconds)
        elif protocol == "UDP":
            src_port = getattr(metadata, "src_port", 0) or 0
            dst_port = getattr(metadata, "dst_port", 0) or 0

            if src_port == 53 or dst_port == 53:
                return self.DNS_THRESHOLD
            else:
                # Other UDP (streaming, etc.) - use default
                return self.DEFAULT_THRESHOLD

        # ICMP: 2 seconds
        elif protocol == "ICMP":
            return self.ICMP_THRESHOLD

        # Default
        return self.DEFAULT_THRESHOLD

    def finalize(self) -> dict[str, Any]:
        """Finalise l'analyse et génère le rapport"""
        # Met à jour total_packets avec le compteur streaming
        if self._packet_count > 0:
            self.total_packets = self._packet_count

        if self.first_timestamp and self.last_timestamp:
            self.capture_duration = self.last_timestamp - self.first_timestamp

        return self._generate_report()

    def _extract_packet_info_fast(self, packet: Packet) -> tuple:
        """
        PERFORMANCE OPTIMIZATION: Extract src_ip, dst_ip, and protocol in one pass.
        This avoids multiple haslayer() calls which are expensive.

        Returns:
            tuple: (src_ip, dst_ip, protocol)
        """
        # Try IPv4 first (most common)
        if packet.haslayer("IP"):
            ip_layer = packet["IP"]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            # Determine protocol from what's above IP
            if packet.haslayer("TCP"):
                protocol = "TCP"
            elif packet.haslayer("UDP"):
                protocol = "UDP"
            elif packet.haslayer("ICMP"):
                protocol = "ICMP"
            else:
                protocol = "IP"

            return (src_ip, dst_ip, protocol)

        # Try IPv6
        elif packet.haslayer("IPv6"):
            ip_layer = packet["IPv6"]
            return (ip_layer.src, ip_layer.dst, "IPv6")

        # No IP layer
        return ("N/A", "N/A", "Other")

    def _get_src_ip(self, packet: Packet) -> str:
        """Extrait l'IP source du paquet"""
        return get_src_ip(packet)

    def _get_dst_ip(self, packet: Packet) -> str:
        """Extrait l'IP destination du paquet"""
        return get_dst_ip(packet)

    def _get_protocol(self, packet: Packet) -> str:
        """Détermine le protocole du paquet"""
        if packet.haslayer("TCP"):
            return "TCP"
        elif packet.haslayer("UDP"):
            return "UDP"
        elif packet.haslayer("ICMP"):
            return "ICMP"
        elif packet.haslayer("IPv6"):
            return "IPv6"
        elif packet.haslayer("IP"):
            return "IP"
        return "Other"

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
        coefficient_of_variation = (stdev_gap / mean_gap) if mean_gap > 0 else float("inf")

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

    def _generate_report(self) -> dict[str, Any]:
        """Génère le rapport d'analyse des timestamps"""
        stats = {}

        if self.packet_intervals:
            stats = {
                "min_interval": min(self.packet_intervals),
                "max_interval": max(self.packet_intervals),
                "mean_interval": statistics.mean(self.packet_intervals),
                "median_interval": statistics.median(self.packet_intervals),
            }

            if len(self.packet_intervals) > 1:
                stats["stdev_interval"] = statistics.stdev(self.packet_intervals)

        # Détection de pattern périodique dans les gaps
        periodic_pattern_detected = self._detect_periodic_pattern()

        non_periodic_gaps = len(self.gaps)
        if periodic_pattern_detected:
            self._mark_periodic_gaps()
            non_periodic_gaps = sum(1 for gap in self.gaps if gap.is_abnormal)

        return {
            "total_packets": self.total_packets,
            "capture_duration_seconds": self.capture_duration,
            "first_timestamp": self.first_timestamp,
            "last_timestamp": self.last_timestamp,
            "gap_threshold_seconds": self.gap_threshold,
            "gaps_detected": len(self.gaps),
            "gaps": [asdict(gap) for gap in self.gaps],
            "interval_statistics": stats,
            "packets_per_second": self.total_packets / self.capture_duration if self.capture_duration > 0 else 0,
            "periodic_pattern_detected": periodic_pattern_detected,
            "non_periodic_gaps": non_periodic_gaps,
        }

    def get_gaps_summary(self, max_display: int = 5) -> str:
        """
        Retourne un résumé textuel des gaps détectés

        Args:
            max_display: Nombre maximum de gaps à afficher (défaut: 5)
        """
        # Filtrer pour ne garder que les gaps anormaux
        abnormal_gaps = [gap for gap in self.gaps if getattr(gap, "is_abnormal", True)]

        if not abnormal_gaps:
            if self.gaps:
                return f"ℹ️ {len(self.gaps)} gap(s) périodique(s) détecté(s) (comportement normal)."
            return "Aucun gap temporel anormal détecté."

        summary = f"🔴 {len(abnormal_gaps)} gap(s) temporel(s) anormal(aux) détecté(s)"
        if len(self.gaps) > len(abnormal_gaps):
            summary += f" (sur {len(self.gaps)} total)"

        # Limiter l'affichage aux N premiers gaps
        gaps_to_display = abnormal_gaps[:max_display]

        if len(abnormal_gaps) > max_display:
            summary += f" - Affichage des {max_display} premiers:\n"
        else:
            summary += ":\n"

        for i, gap in enumerate(gaps_to_display, 1):
            summary += f"\n  Gap #{i}:\n"
            summary += f"    - Entre paquets {gap.packet_num_before} et {gap.packet_num_after}\n"
            summary += f"    - Durée: {gap.gap_duration:.3f}s\n"
            summary += f"    - Direction: {gap.src_ip} → {gap.dst_ip}\n"
            summary += f"    - Protocole: {gap.protocol}\n"

        # Si plus de gaps que max_display, ajouter des commandes pour les retrouver
        if len(abnormal_gaps) > max_display:
            summary += f"\n  ... et {len(abnormal_gaps) - max_display} autre(s) gap(s)\n"
            summary += "\n  💡 Pour visualiser tous les gaps:\n"

            # Construire un filtre avec les numéros de paquets de tous les gaps
            packet_numbers = []
            for gap in abnormal_gaps:
                packet_numbers.append(str(gap.packet_num_before))
                packet_numbers.append(str(gap.packet_num_after))

            # Commande tcpdump (affiche les paquets autour des gaps)
            # Note: tcpdump n'a pas de filtre par numéro de frame, on utilise les IPs
            unique_ips = set()
            for gap in abnormal_gaps[:10]:  # Limiter aux 10 premiers gaps
                unique_ips.add(gap.src_ip)
                unique_ips.add(gap.dst_ip)

            if len(unique_ips) <= 20:  # Si pas trop d'IPs différentes
                ip_filter = " or ".join([f"host {ip}" for ip in list(unique_ips)[:10]])
                summary += f"\n  📌 tcpdump (paquets des connexions avec gaps):\n"
                summary += f"     tcpdump -r <fichier.pcap> -nn '{ip_filter}'\n"
            else:
                summary += f"\n  📌 tcpdump (exemple pour le premier gap):\n"
                first_gap = abnormal_gaps[0]
                summary += f"     tcpdump -r <fichier.pcap> -nn 'host {first_gap.src_ip} and host {first_gap.dst_ip}'\n"

            # Commande Wireshark
            summary += f"\n  📌 Wireshark filter (numéros de frames):\n"
            summary += f"     frame.number in {{{','.join(packet_numbers[:20])}}}\n"

            # Info pour le rapport complet
            summary += f"\n  ℹ️  Consultez le rapport HTML pour la liste complète des gaps\n"

        return summary

    def filter_by_latency(self, min_latency: float) -> list[tuple[int, int, float]]:
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
