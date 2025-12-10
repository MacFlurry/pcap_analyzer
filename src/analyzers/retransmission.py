"""
TCP Retransmission and Anomaly Analyzer.

This analyzer detects TCP retransmissions, duplicate ACKs, out-of-order packets,
and other TCP anomalies according to RFC 793 and RFC 2581 (TCP Congestion Control).

Detection Methods:
1. Exact Match: Detects retransmission of identical segments (seq, len)
2. Spurious Retransmission: Segments already ACKed by receiver
3. Fast Retransmission: Triggered by 3+ duplicate ACKs (RFC 2581)
4. RTO: Timeout-based retransmission (delay > threshold)

Anomaly Detection:
- Duplicate ACKs: Same ACK number received multiple times
- Out-of-Order: Packets with sequence numbers below expected
- Zero Window: TCP window size is 0 (receiver buffer full)

Memory Management:
- LRU-like cleanup: Keeps newest segments when limit exceeded
- Periodic cleanup: Every 10,000 packets
- Max segments per flow: 10,000

References:
    RFC 793: Transmission Control Protocol
    RFC 2581: TCP Congestion Control
    RFC 6298: Computing TCP's Retransmission Timer
"""

from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from scapy.all import IP, TCP, Packet

from ..utils.packet_utils import get_ip_layer
from ..utils.tcp_utils import get_tcp_logical_length

# Import PacketMetadata for hybrid mode support (3-5x faster)
try:
    from ..parsers.fast_parser import PacketMetadata
except ImportError:
    PacketMetadata = None


@dataclass
class TCPRetransmission:
    """
    Represents a TCP retransmission event.

    Attributes:
        packet_num: Packet number of the retransmitted segment
        timestamp: Time when retransmission occurred
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source TCP port
        dst_port: Destination TCP port
        seq_num: TCP sequence number of retransmitted segment
        original_packet_num: Packet number of original transmission
        delay: Time between original and retransmission (seconds)
        retrans_type: Type of retransmission:
            - 'RTO': Retransmission timeout (delay > threshold, typically 200ms)
            - 'Fast Retransmission': Triggered by duplicate ACKs (delay < 50ms)
            - 'Retransmission': Generic retransmission (between thresholds)
    """

    packet_num: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq_num: int
    original_packet_num: int
    delay: float
    retrans_type: str = "Unknown"


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
    severity: str = "none"
    retransmission_rate: float = 0.0


class RetransmissionAnalyzer:
    """
    TCP Retransmission and Anomaly Analyzer.

    Detects and classifies TCP retransmissions using multiple algorithms:
    1. Exact segment matching (seq, len)
    2. Spurious retransmission detection (already ACKed)
    3. Fast retransmission detection (3+ duplicate ACKs per RFC 2581)
    4. RTO classification based on delay thresholds (RFC 6298)

    The analyzer also tracks TCP anomalies including duplicate ACKs,
    out-of-order packets, and zero window conditions.

    Performance:
        - Time complexity: O(1) average per packet (with periodic cleanup)
        - Space complexity: O(N*M) where N=flows, M=segments per flow (bounded)
    """

    def __init__(
        self,
        retrans_low: int = 10,
        retrans_medium: int = 50,
        retrans_critical: int = 100,
        retrans_rate_low: float = 1.0,
        retrans_rate_medium: float = 3.0,
        retrans_rate_critical: float = 5.0,
        rto_threshold_ms: float = 200.0,
        fast_retrans_delay_max_ms: float = 50.0,
    ) -> None:
        """
        Initialize retransmission analyzer.

        Args:
            retrans_low: Low severity threshold (absolute count)
            retrans_medium: Medium severity threshold (absolute count)
            retrans_critical: Critical severity threshold (absolute count)
            retrans_rate_low: Low severity rate threshold (%)
            retrans_rate_medium: Medium severity rate threshold (%)
            retrans_rate_critical: Critical severity rate threshold (%)
            rto_threshold_ms: Delay threshold for RTO classification (milliseconds).
                Per RFC 6298, typical RTO is >= 200ms.
            fast_retrans_delay_max_ms: Max delay for fast retransmission (milliseconds).
                Per RFC 2581, fast retransmit happens quickly after 3 DUP ACKs.

        Note:
            Default thresholds are suitable for most networks. For high-throughput
            or lossy environments, consider adjusting the rate thresholds.
        """
        self.retrans_low = retrans_low
        self.retrans_medium = retrans_medium
        self.retrans_critical = retrans_critical

        self.retrans_rate_low = retrans_rate_low
        self.retrans_rate_medium = retrans_rate_medium
        self.retrans_rate_critical = retrans_rate_critical

        self.rto_threshold = rto_threshold_ms / 1000.0  # Convert to seconds
        self.fast_retrans_delay_max = fast_retrans_delay_max_ms / 1000.0  # Convert to seconds

        self.retransmissions: list[TCPRetransmission] = []
        self.anomalies: list[TCPAnomaly] = []
        self.flow_stats: dict[str, FlowStats] = {}

        # Tracking interne
        # Changement: on stocke maintenant une liste de (packet_num, timestamp) pour chaque (seq, len)
        # pour détecter les retransmissions multiples du même segment
        self._seen_segments: dict[str, dict[tuple[int, int], list[tuple[int, float]]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._flow_counters: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._expected_ack: dict[str, int] = {}
        self._expected_seq: dict[str, int] = {}
        self._dup_ack_count: dict[str, int] = defaultdict(int)  # Compteur de DUP ACK par flux
        self._last_ack: dict[str, int] = {}  # Dernier ACK vu par flux
        # Tracking du plus haut seq vu par flux (méthode Wireshark)
        self._highest_seq: dict[str, tuple[int, int, float]] = {}  # flow_key -> (highest_seq, packet_num, timestamp)
        # Tracking du plus haut ACK vu par flux (pour Spurious Retransmission)
        self._max_ack_seen: dict[str, int] = defaultdict(int)

        # Memory optimization: periodic cleanup
        self._packet_counter = 0
        self._cleanup_interval = 10000
        self._max_segments_per_flow = 10000

    def analyze(self, packets: list[Packet]) -> dict[str, Any]:
        """
        Analyse les retransmissions et anomalies TCP

        Args:
            packets: Liste des paquets Scapy

        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        for i, packet in enumerate(packets):
            self.process_packet(packet, i)

        return self.finalize()

    def process_packet(self, packet: Union[Packet, "PacketMetadata"], packet_num: int) -> None:
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
        ip = get_ip_layer(packet)
        if not packet.haslayer(TCP) or not ip:
            return

        # Memory optimization: periodic cleanup
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_old_segments()

        self._analyze_packet(packet_num, packet)

    def _cleanup_old_segments(self) -> None:
        """
        Cleanup old segments to prevent memory exhaustion using LRU-like approach.

        When a flow exceeds the maximum segment limit (10,000), this method
        keeps only the newest half of segments based on most recent timestamp.
        This prevents unbounded memory growth in long captures while maintaining
        recent history for retransmission detection.

        Algorithm:
            1. For each flow exceeding max_segments_per_flow
            2. Sort segments by most recent timestamp (descending)
            3. Keep only the newest 50% of segments
            4. Discard older segments

        Note:
            Called every 10,000 packets. This balances memory usage with
            retransmission detection accuracy.
        """
        for flow_key in list(self._seen_segments.keys()):
            segments = self._seen_segments[flow_key]
            if len(segments) > self._max_segments_per_flow:
                # Keep only the most recent segments (by timestamp)
                sorted_segments = sorted(
                    segments.items(), key=lambda x: max(ts for _, ts in x[1]) if x[1] else 0, reverse=True
                )
                # Keep newest half
                keep_count = self._max_segments_per_flow // 2
                self._seen_segments[flow_key] = dict(sorted_segments[:keep_count])

    def _process_metadata(self, metadata: "PacketMetadata", packet_num: int) -> None:
        """
        PERFORMANCE OPTIMIZED: Process lightweight PacketMetadata (3-5x faster than Scapy).

        This method replicates the exact logic of _analyze_packet() but uses direct
        attribute access from dpkt-extracted metadata instead of Scapy's API.

        Implements RFC 793 and RFC 2581 retransmission detection:
        1. Exact segment matching (seq, payload_len)
        2. Spurious retransmission (already ACKed)
        3. Fast retransmission (triggered by 3+ DUP ACKs)
        4. RTO classification based on delay

        Args:
            metadata: Lightweight packet metadata from dpkt
            packet_num: Packet sequence number in capture
        """
        # Skip non-TCP packets
        if metadata.protocol != "TCP":
            return

        # Memory optimization: periodic cleanup
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_old_segments()

        timestamp = metadata.timestamp

        # Build flow key from metadata
        flow_key = f"{metadata.src_ip}:{metadata.src_port}->{metadata.dst_ip}:{metadata.dst_port}"
        reverse_key = f"{metadata.dst_ip}:{metadata.dst_port}->{metadata.src_ip}:{metadata.src_port}"

        self._flow_counters[flow_key]["total"] += 1

        # Gestion des nouvelles connexions (SYN)
        if metadata.is_syn:  # SYN flag
            if flow_key in self._highest_seq:
                del self._highest_seq[flow_key]
            if flow_key in self._max_ack_seen:
                del self._max_ack_seen[flow_key]

        # Mise à jour du Max ACK vu pour ce flux
        if metadata.is_ack:  # ACK flag
            ack = metadata.tcp_ack
            if flow_key not in self._max_ack_seen or ack > self._max_ack_seen[flow_key]:
                self._max_ack_seen[flow_key] = ack

        # Calcul de la longueur logique TCP (RFC 793: payload + SYN + FIN)
        seq = metadata.tcp_seq
        payload_len = metadata.tcp_payload_len

        logical_len = payload_len
        if metadata.is_syn:
            logical_len += 1
        if metadata.is_fin:
            logical_len += 1

        next_seq = seq + logical_len

        # On ne cherche des retransmissions QUE si le paquet transporte des données ou SYN/FIN
        has_payload_or_flags = (payload_len > 0) or metadata.is_syn or metadata.is_fin

        if has_payload_or_flags:
            # Clé unique: seq + longueur de payload pour distinguer retransmissions partielles
            segment_key = (seq, payload_len)

            is_retransmission = False
            original_num = None
            original_time = None

            # Méthode combinée (Wireshark-like + Exact Match)

            # 1. Vérifier si le segment exact (seq, len) a déjà été vu
            if segment_key in self._seen_segments[flow_key]:
                is_retransmission = True
                original_num, original_time = self._seen_segments[flow_key][segment_key][0]

            # 2. Vérifier si c'est une Spurious Retransmission (déjà ACKé par l'autre côté)
            if not is_retransmission and reverse_key in self._max_ack_seen:
                max_ack = self._max_ack_seen[reverse_key]
                if seq + logical_len <= max_ack:
                    is_retransmission = True

            # 3. Vérifier Fast Retransmission (SEQ attendu par >2 DUP ACKs)
            if not is_retransmission and self._dup_ack_count[reverse_key] > 2:
                expected_seq = self._last_ack[reverse_key]
                if seq == expected_seq:
                    is_retransmission = True

            if is_retransmission:
                # Essayer de trouver le paquet original exact
                if original_num is None:
                    if (
                        segment_key in self._seen_segments[flow_key]
                        and len(self._seen_segments[flow_key][segment_key]) > 0
                    ):
                        original_num, original_time = self._seen_segments[flow_key][segment_key][0]
                    elif flow_key in self._highest_seq:
                        _, highest_pkt, highest_time = self._highest_seq[flow_key]
                        original_num = highest_pkt
                        original_time = highest_time
                    else:
                        original_num = packet_num
                        original_time = timestamp

                delay = timestamp - original_time

                # Determine retransmission type based on delay heuristics
                retrans_type = "Retransmission"
                if delay >= self.rto_threshold:
                    retrans_type = "RTO"
                elif delay <= self.fast_retrans_delay_max:
                    retrans_type = "Fast Retransmission"

                retrans = TCPRetransmission(
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=metadata.src_ip,
                    dst_ip=metadata.dst_ip,
                    src_port=metadata.src_port,
                    dst_port=metadata.dst_port,
                    seq_num=seq,
                    original_packet_num=original_num,
                    delay=delay,
                    retrans_type=retrans_type,
                )
                self.retransmissions.append(retrans)
                self._flow_counters[flow_key]["retransmissions"] += 1

            # Store only original packet info
            if segment_key not in self._seen_segments[flow_key]:
                self._seen_segments[flow_key][segment_key] = [(packet_num, timestamp)]

        # Mettre à jour le plus haut seq vu pour ce flux
        if flow_key not in self._highest_seq or next_seq > self._highest_seq[flow_key][0]:
            self._highest_seq[flow_key] = (next_seq, packet_num, timestamp)

        # Détection de DUP ACK et Fast Retransmission
        if metadata.is_ack:  # ACK flag
            ack = metadata.tcp_ack

            # Vérifier si c'est un DUP ACK
            if reverse_key in self._last_ack and ack == self._last_ack[reverse_key]:
                # C'est un DUP ACK
                self._dup_ack_count[reverse_key] += 1

                anomaly = TCPAnomaly(
                    anomaly_type="dup_ack",
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=metadata.src_ip,
                    dst_ip=metadata.dst_ip,
                    src_port=metadata.src_port,
                    dst_port=metadata.dst_port,
                    details=f"Duplicate ACK #{self._dup_ack_count[reverse_key]} for seq {ack}",
                )
                self.anomalies.append(anomaly)
                self._flow_counters[flow_key]["dup_acks"] += 1
            else:
                # Nouvel ACK, réinitialiser le compteur de DUP ACK
                self._dup_ack_count[reverse_key] = 0

            self._last_ack[reverse_key] = ack
            self._expected_ack[reverse_key] = ack

        # Détection Out-of-Order
        if logical_len > 0:
            expected = self._expected_seq.get(flow_key, seq)

            if seq < expected:
                # Paquet reçu avec un numéro de séquence inférieur à celui attendu
                anomaly = TCPAnomaly(
                    anomaly_type="out_of_order",
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=metadata.src_ip,
                    dst_ip=metadata.dst_ip,
                    src_port=metadata.src_port,
                    dst_port=metadata.dst_port,
                    details=f"Expected seq {expected}, got {seq}",
                )
                self.anomalies.append(anomaly)
                self._flow_counters[flow_key]["out_of_order"] += 1
            else:
                self._expected_seq[flow_key] = seq + logical_len

        # Détection Zero Window
        if metadata.tcp_window == 0:
            anomaly = TCPAnomaly(
                anomaly_type="zero_window",
                packet_num=packet_num,
                timestamp=timestamp,
                src_ip=metadata.src_ip,
                dst_ip=metadata.dst_ip,
                src_port=metadata.src_port,
                dst_port=metadata.dst_port,
                details="TCP window size is 0",
            )
            self.anomalies.append(anomaly)
            self._flow_counters[flow_key]["zero_windows"] += 1

    def finalize(self) -> dict[str, Any]:
        """Finalise l'analyse et génère le rapport"""
        # Cleanup: Clear _seen_segments to free memory
        # No longer needed after analysis is complete
        self._seen_segments.clear()
        # Clear other tracking dicts to prevent memory leaks
        self._highest_seq.clear()
        self._max_ack_seen.clear()
        self._dup_ack_count.clear()

        self._calculate_flow_severity()
        return self._generate_report()

    def _analyze_packet(self, packet_num: int, packet: Packet) -> None:
        """Analyse un paquet TCP individuel"""
        tcp = packet[TCP]
        ip = get_ip_layer(packet)
        if not ip:
            return
        timestamp = float(packet.time)

        flow_key = self._get_flow_key(packet)
        self._flow_counters[flow_key]["total"] += 1

        # Gestion des nouvelles connexions (SYN)
        # Si on voit un SYN, on réinitialise le suivi de séquence pour ce flux
        if tcp.flags & 0x02:  # SYN flag
            if flow_key in self._highest_seq:
                del self._highest_seq[flow_key]
            if flow_key in self._max_ack_seen:
                del self._max_ack_seen[flow_key]

        # Mise à jour du Max ACK vu pour ce flux
        if tcp.flags & 0x10:  # ACK flag
            ack = tcp.ack
            if flow_key not in self._max_ack_seen or ack > self._max_ack_seen[flow_key]:
                self._max_ack_seen[flow_key] = ack

        # Détection de retransmissions
        # On calcule d'abord les propriétés de séquence pour TOUS les paquets TCP
        seq = tcp.seq
        payload_len = len(tcp.payload)

        # FIX: Use proper logical length calculation (RFC 793)
        # SYN and FIN flags each consume one sequence number
        logical_len = get_tcp_logical_length(tcp)

        next_seq = seq + logical_len

        # On ne cherche des retransmissions QUE si le paquet transporte des données ou SYN/FIN
        # (On ignore les purs ACKs pour la détection, mais on les utilise pour le tracking)
        has_payload_or_flags = (payload_len > 0) or (tcp.flags & 0x03)

        if has_payload_or_flags:
            # Clé unique: seq + longueur de payload pour distinguer retransmissions partielles
            segment_key = (seq, payload_len)

            is_retransmission = False
            original_num = None
            original_time = None

            # Méthode combinée (Wireshark-like + Exact Match)

            # 1. Vérifier si le segment exact (seq, len) a déjà été vu
            # C'est la méthode la plus fiable pour distinguer Retransmission vs Out-of-Order
            if segment_key in self._seen_segments[flow_key]:
                is_retransmission = True
                original_num, original_time = self._seen_segments[flow_key][segment_key][0]

            # 2. Vérifier si c'est une Spurious Retransmission (déjà ACKé par l'autre côté)
            reverse_key = self._get_reverse_flow_key(packet)
            if not is_retransmission and reverse_key in self._max_ack_seen:
                max_ack = self._max_ack_seen[reverse_key]
                # FIX: Use logical_len instead of payload_len (accounts for SYN/FIN)
                # Si le segment entier est avant le max ACK, c'est une retransmission inutile
                if seq + logical_len <= max_ack:
                    is_retransmission = True
                    # On ne connait pas forcément l'original si le tracking a commencé après,
                    # mais on sait que c'est une retransmission.
                    # On garde original_num = None pour l'instant, on le settera ci-dessous

            # 3. Vérifier Fast Retransmission (SEQ attendu par >2 DUP ACKs)
            if not is_retransmission and self._dup_ack_count[reverse_key] > 2:
                expected_seq = self._last_ack[reverse_key]
                if seq == expected_seq:
                    is_retransmission = True
                    # Fast Retransmission confirmée

            if is_retransmission:
                # Essayer de trouver le paquet original exact si pas encore trouvé
                if original_num is None:
                    if (
                        segment_key in self._seen_segments[flow_key]
                        and len(self._seen_segments[flow_key][segment_key]) > 0
                    ):
                        original_num, original_time = self._seen_segments[flow_key][segment_key][0]
                    elif flow_key in self._highest_seq:
                        # Fallback sur highest_seq info si on n'a pas l'historique complet
                        _, highest_pkt, highest_time = self._highest_seq[flow_key]
                        # Attention: ce n'est pas forcément le VRAI original, mais une approx
                        original_num = highest_pkt
                        original_time = highest_time
                    else:
                        # Dernier recours
                        original_num = packet_num
                        original_time = timestamp

                delay = timestamp - original_time

                # Determine retransmission type based on delay heuristics
                retrans_type = "Retransmission"  # Default
                if delay >= self.rto_threshold:
                    retrans_type = "RTO"
                elif delay <= self.fast_retrans_delay_max:
                    retrans_type = "Fast Retransmission"

                retrans = TCPRetransmission(
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    seq_num=seq,
                    original_packet_num=original_num,
                    delay=delay,
                    retrans_type=retrans_type,  # Assign the type
                )
                self.retransmissions.append(retrans)
                self._flow_counters[flow_key]["retransmissions"] += 1

            # Store only original packet info to prevent unbounded memory growth
            # We only need the first occurrence to detect retransmissions
            if segment_key not in self._seen_segments[flow_key]:
                self._seen_segments[flow_key][segment_key] = [(packet_num, timestamp)]
            # For retransmissions, we already have the original, no need to store more

        # Mettre à jour le plus haut seq vu pour ce flux (POUR TOUS LES PAQUETS)
        if flow_key not in self._highest_seq or next_seq > self._highest_seq[flow_key][0]:
            self._highest_seq[flow_key] = (next_seq, packet_num, timestamp)

        # Détection de DUP ACK et Fast Retransmission
        if tcp.flags & 0x10:  # ACK flag
            ack = tcp.ack
            reverse_flow = self._get_reverse_flow_key(packet)

            # Vérifier si c'est un DUP ACK
            if reverse_flow in self._last_ack and ack == self._last_ack[reverse_flow]:
                # C'est un DUP ACK
                self._dup_ack_count[reverse_flow] += 1

                anomaly = TCPAnomaly(
                    anomaly_type="dup_ack",
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    details=f"Duplicate ACK #{self._dup_ack_count[reverse_flow]} for seq {ack}",
                )
                self.anomalies.append(anomaly)
                self._flow_counters[flow_key]["dup_acks"] += 1

                # Détection de Fast Retransmission (après 3 DUP ACK selon RFC)
                if self._dup_ack_count[reverse_flow] >= 3:
                    # Marquer comme fast retransmission potentielle
                    # La vraie fast retrans sera détectée quand le segment sera renvoyé
                    pass
            else:
                # Nouvel ACK, réinitialiser le compteur de DUP ACK
                self._dup_ack_count[reverse_flow] = 0

            self._last_ack[reverse_flow] = ack
            self._expected_ack[reverse_flow] = ack

        # Détection Out-of-Order
        # FIX: Check logical_len instead of just payload (accounts for SYN/FIN)
        if logical_len > 0:
            seq = tcp.seq
            expected = self._expected_seq.get(flow_key, seq)

            if seq < expected:
                # Paquet reçu avec un numéro de séquence inférieur à celui attendu
                anomaly = TCPAnomaly(
                    anomaly_type="out_of_order",
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    details=f"Expected seq {expected}, got {seq}",
                )
                self.anomalies.append(anomaly)
                self._flow_counters[flow_key]["out_of_order"] += 1
            else:
                # FIX: Use logical_len (accounts for SYN/FIN flags)
                self._expected_seq[flow_key] = seq + logical_len

        # Détection Zero Window
        if tcp.window == 0:
            anomaly = TCPAnomaly(
                anomaly_type="zero_window",
                packet_num=packet_num,
                timestamp=timestamp,
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                details="TCP window size is 0",
            )
            self.anomalies.append(anomaly)
            self._flow_counters[flow_key]["zero_windows"] += 1

    def _get_flow_key(self, packet: Packet) -> str:
        """Génère une clé de flux unidirectionnelle"""
        ip = get_ip_layer(packet)
        if not ip:
            return ""
        tcp = packet[TCP]
        # Ensure ports are integers (they can sometimes be hex strings)
        sport = (
            int(tcp.sport)
            if isinstance(tcp.sport, int)
            else int(str(tcp.sport), 16) if isinstance(tcp.sport, str) else tcp.sport
        )
        dport = (
            int(tcp.dport)
            if isinstance(tcp.dport, int)
            else int(str(tcp.dport), 16) if isinstance(tcp.dport, str) else tcp.dport
        )
        return f"{ip.src}:{sport}->{ip.dst}:{dport}"

    def _get_reverse_flow_key(self, packet: Packet) -> str:
        """Génère la clé de flux inverse"""
        ip = get_ip_layer(packet)
        if not ip:
            return ""
        tcp = packet[TCP]
        # Ensure ports are integers (they can sometimes be hex strings)
        sport = (
            int(tcp.sport)
            if isinstance(tcp.sport, int)
            else int(str(tcp.sport), 16) if isinstance(tcp.sport, str) else tcp.sport
        )
        dport = (
            int(tcp.dport)
            if isinstance(tcp.dport, int)
            else int(str(tcp.dport), 16) if isinstance(tcp.dport, str) else tcp.dport
        )
        return f"{ip.dst}:{dport}->{ip.src}:{sport}"

    def _calculate_flow_severity(self) -> None:
        """Calcule la sévérité pour chaque flux"""
        for flow_key, counters in self._flow_counters.items():
            try:
                parts = flow_key.split("->")
                # Use rsplit to handle IPv6 addresses (e.g., ::1:46650 -> ['::1', '46650'])
                src_part, dst_part = parts[0].rsplit(":", 1), parts[1].rsplit(":", 1)

                retrans_count = counters["retransmissions"]
                total_packets = counters["total"]

                # Calcul du taux de retransmission en pourcentage
                retrans_rate = (retrans_count / total_packets * 100) if total_packets > 0 else 0

                # La sévérité est déterminée par le taux, MAIS il faut un minimum absolu de retransmissions
                # pour éviter de flagger les très petits flux (ex: 1 retrans sur 4 paquets = 25%)

                severity = "none"

                # On vérifie d'abord si on dépasse le seuil absolu minimal (low)
                if retrans_count >= self.retrans_low:
                    if retrans_rate >= self.retrans_rate_critical:
                        severity = "critical"
                    elif retrans_rate >= self.retrans_rate_medium:
                        severity = "medium"
                    elif retrans_rate >= self.retrans_rate_low:
                        severity = "low"

                    # Fallback: si le nombre absolu est très élevé, on flag quand même
                    # même si le taux est bas (ex: flux très long)
                    if severity == "none" and retrans_count >= self.retrans_critical:
                        severity = "low"  # On reste en low si c'est juste du volume mais taux faible

                # Parse ports with error handling for hex strings or invalid values
                try:
                    src_port = int(src_part[1])
                except ValueError:
                    # Try parsing as hex if decimal fails
                    src_port = int(src_part[1], 16)

                try:
                    dst_port = int(dst_part[1])
                except ValueError:
                    # Try parsing as hex if decimal fails
                    dst_port = int(dst_part[1], 16)

                stats = FlowStats(
                    flow_key=flow_key,
                    src_ip=src_part[0],
                    dst_ip=dst_part[0],
                    src_port=src_port,
                    dst_port=dst_port,
                    total_packets=counters["total"],
                    retransmissions=counters["retransmissions"],
                    dup_acks=counters["dup_acks"],
                    out_of_order=counters["out_of_order"],
                    zero_windows=counters["zero_windows"],
                    severity=severity,
                    retransmission_rate=retrans_rate,
                )

                self.flow_stats[flow_key] = stats
            except (ValueError, IndexError) as e:
                # Skip malformed flow keys
                print(f"Warning: Skipping malformed flow key '{flow_key}': {e}")
                continue

    def _count_unique_retransmitted_segments(self) -> int:
        """
        Compte le nombre de segments uniques qui ont été retransmis.
        Un segment retransmis 2 fois compte pour 1 segment unique.
        """
        unique_segments = set()
        for retrans in self.retransmissions:
            # Clé unique: (src, dst, sport, dport, seq)
            key = (retrans.src_ip, retrans.dst_ip, retrans.src_port, retrans.dst_port, retrans.seq_num)
            unique_segments.add(key)
        return len(unique_segments)

    def _generate_report(self) -> dict[str, Any]:
        """Génère le rapport d'analyse"""
        total_retrans = len(self.retransmissions)
        flows_with_issues = [f for f in self.flow_stats.values() if f.severity != "none"]

        # Compte les anomalies par type
        anomaly_counts = defaultdict(int)
        for anomaly in self.anomalies:
            anomaly_counts[anomaly.anomaly_type] += 1

        # Statistiques de sévérité
        severity_counts = defaultdict(int)
        for flow in self.flow_stats.values():
            severity_counts[flow.severity] += 1

        # Tri des retransmissions par délai décroissant (les plus graves en premier)
        sorted_retransmissions = sorted(self.retransmissions, key=lambda r: r.delay, reverse=True)

        rto_count = sum(1 for r in self.retransmissions if r.retrans_type == "RTO")
        fast_retrans_count = sum(1 for r in self.retransmissions if r.retrans_type == "Fast Retransmission")
        # All other types (including "Unknown" and "Retransmission")
        other_retrans_count = total_retrans - rto_count - fast_retrans_count

        return {
            "total_flows": len(self.flow_stats),
            "flows_with_issues": len(flows_with_issues),
            "total_retransmissions": total_retrans,
            "total_anomalies": len(self.anomalies),
            "anomaly_types": dict(anomaly_counts),
            "severity_distribution": dict(severity_counts),
            "thresholds": {"low": self.retrans_low, "medium": self.retrans_medium, "critical": self.retrans_critical},
            "retransmissions": [asdict(r) for r in sorted_retransmissions],
            "anomalies": [asdict(a) for a in self.anomalies],
            "flow_statistics": [asdict(f) for f in self.flow_stats.values()],
            "rto_count": rto_count,
            "fast_retrans_count": fast_retrans_count,
            "other_retrans_count": other_retrans_count,
            "unique_retransmitted_segments": self._count_unique_retransmitted_segments(),
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse"""
        total_retrans = len(self.retransmissions)
        unique_segments = self._count_unique_retransmitted_segments()
        flows_with_issues = [f for f in self.flow_stats.values() if f.severity != "none"]

        summary = f"📊 Analyse des retransmissions et anomalies TCP:\n"
        summary += f"  - Flux analysés: {len(self.flow_stats)}\n"
        summary += f"  - Retransmissions totales: {total_retrans}\n"
        summary += f"    ({unique_segments} segment(s) unique(s) retransmis)\n"

        rto_count = sum(1 for r in self.retransmissions if r.retrans_type == "RTO")
        fast_retrans_count = sum(1 for r in self.retransmissions if r.retrans_type == "Fast Retransmission")
        other_retrans_count = total_retrans - rto_count - fast_retrans_count

        if rto_count > 0:
            summary += f"    dont RTOs: {rto_count} 🔴 (Congestion Sévère)\n"
        if fast_retrans_count > 0:
            summary += f"    dont Fast Retransmissions: {fast_retrans_count} 🟠 (Pertes Légères / Désordre)\n"
        if other_retrans_count > 0:
            summary += f"    dont Autres Retransmissions: {other_retrans_count} 🔵 (Causes diverses)\n"

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

    def get_details(self, limit: int = 20, flow_filter: str = None) -> str:
        """
        Retourne les détails des retransmissions

        Args:
            limit: Nombre maximum de retransmissions à afficher
            flow_filter: Filtrer sur un flux spécifique (ex: "10.28.104.211:16586->10.179.161.14:10100")

        Returns:
            Chaîne formatée avec les détails des retransmissions
        """
        if not self.retransmissions:
            return "✅ Aucune retransmission à détailler."

        # Filtrage par flux si demandé
        retrans_list = self.retransmissions
        if flow_filter:
            retrans_list = [
                r for r in retrans_list if f"{r.src_ip}:{r.src_port}->{r.dst_ip}:{r.dst_port}" == flow_filter
            ]

        if not retrans_list:
            return f"✅ Aucune retransmission trouvée pour le flux: {flow_filter}"

        # Tri par délai décroissant (les pires retransmissions en premier)
        # On privilégie les RTO (délais longs) aux Fast Retransmissions (délais courts)
        retrans_list.sort(key=lambda r: r.delay, reverse=True)

        total = len(retrans_list)
        displayed = min(limit, total)

        details = f"🔍 Détails des retransmissions (Top {displayed} par délai / Total {total}):\n\n"

        for i, retrans in enumerate(retrans_list[:limit], 1):
            delay_ms = retrans.delay * 1000  # Convertir en ms
            details += f"  #{i}: Paquet {retrans.packet_num} (retrans de #{retrans.original_packet_num})\n"
            details += f"      Seq: {retrans.seq_num}, Délai: {delay_ms:.1f}ms\n"
            details += f"      {retrans.src_ip}:{retrans.src_port} → {retrans.dst_ip}:{retrans.dst_port}\n"
            if i < displayed:
                details += "\n"

        if total > limit:
            details += (
                f"\n  ... et {total - limit} autres retransmissions (utilisez --details-limit pour en voir plus)\n"
            )

        return details
