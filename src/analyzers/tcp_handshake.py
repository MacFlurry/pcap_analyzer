"""
TCP Handshake Analyzer - Measures SYN/SYN-ACK/ACK delays.

This analyzer implements TCP three-way handshake detection and timing analysis
according to RFC 793 (Transmission Control Protocol).

Key features:
- Detects complete and incomplete handshakes
- Measures SYN→SYN-ACK and SYN-ACK→ACK delays
- Identifies suspected bottlenecks (client, server, or network)
- Validates handshake completion per RFC 793 (ACK must equal SYN-ACK.SEQ + 1)
- Memory-optimized with periodic cleanup of stale handshakes

References:
    RFC 793: Transmission Control Protocol
    RFC 1323: TCP Extensions for High Performance
"""

from scapy.all import Packet, TCP
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict
from ..utils.packet_utils import get_ip_layer


@dataclass
class HandshakeFlow:
    """
    Represents a complete or partial TCP handshake.

    A TCP handshake consists of three packets (RFC 793):
    1. SYN: Client initiates connection
    2. SYN-ACK: Server responds with synchronization acknowledgment
    3. ACK: Client acknowledges server's response

    Attributes:
        src_ip: Source IP address (client)
        dst_ip: Destination IP address (server)
        src_port: Source TCP port
        dst_port: Destination TCP port
        syn_time: Timestamp of SYN packet
        syn_packet_num: Packet number of SYN
        synack_time: Timestamp of SYN-ACK packet
        synack_packet_num: Packet number of SYN-ACK
        synack_seq: SYN-ACK sequence number (for RFC 793 validation)
        ack_time: Timestamp of final ACK packet
        ack_packet_num: Packet number of final ACK
        syn_to_synack_delay: Delay from SYN to SYN-ACK (server processing time)
        synack_to_ack_delay: Delay from SYN-ACK to ACK (client processing time)
        total_handshake_time: Total time from SYN to final ACK
        complete: Whether handshake completed successfully
        suspected_side: Suspected bottleneck ('client', 'server', 'network', 'none')
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    syn_time: Optional[float] = None
    syn_packet_num: Optional[int] = None
    synack_time: Optional[float] = None
    synack_packet_num: Optional[int] = None
    synack_seq: Optional[int] = None  # Track SYN-ACK SEQ for validation
    ack_time: Optional[float] = None
    ack_packet_num: Optional[int] = None
    syn_to_synack_delay: Optional[float] = None
    synack_to_ack_delay: Optional[float] = None
    total_handshake_time: Optional[float] = None
    complete: bool = False
    suspected_side: str = "unknown"


class TCPHandshakeAnalyzer:
    """
    TCP Handshake Analyzer - Detects and measures TCP three-way handshakes.

    This analyzer implements RFC 793-compliant handshake detection, tracking
    SYN, SYN-ACK, and ACK packets to measure connection establishment delays.
    It validates handshake completion by verifying that the final ACK number
    equals SYN-ACK.SEQ + 1 as specified in RFC 793.

    Memory Management:
        - Periodic cleanup of stale incomplete handshakes (default: 60s timeout)
        - Cleanup interval: every 10,000 packets

    Performance Characteristics:
        - Time complexity: O(1) per packet
        - Space complexity: O(N) where N is number of concurrent connections
    """

    def __init__(self, syn_synack_threshold: float = 0.1, total_threshold: float = 0.3,
                 latency_filter: Optional[float] = None) -> None:
        """
        Initialize TCP handshake analyzer.

        Args:
            syn_synack_threshold: Alert threshold for SYN→SYN-ACK delay (seconds).
                Delays above this suggest server or network congestion.
            total_threshold: Alert threshold for complete handshake (seconds).
                Total time above this indicates connection establishment issues.
            latency_filter: If set, only keep handshakes with latency >= threshold (seconds).
                Useful for focusing on slow connections only.

        Note:
            Default thresholds (0.1s and 0.3s) are suitable for LAN environments.
            For WAN analysis, consider higher values (e.g., 0.5s and 1.0s).
        """
        self.syn_synack_threshold = syn_synack_threshold
        self.total_threshold = total_threshold
        self.latency_filter = latency_filter
        self.handshakes: List[HandshakeFlow] = []
        self.incomplete_handshakes: Dict[str, HandshakeFlow] = {}
        # Memory optimization: cleanup stale handshakes periodically
        self._cleanup_interval = 10000  # Cleanup every 10k packets
        self._packet_counter = 0
        self._handshake_timeout = 60.0  # Remove incomplete handshakes after 60s

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyse les handshakes TCP dans les paquets

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
        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]
        packet_time = float(packet.time)

        # Memory optimization: periodic cleanup of stale handshakes
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_stale_handshakes(packet_time)

        # Détection SYN (sans ACK)
        if tcp.flags & 0x02 and not tcp.flags & 0x10:  # SYN flag set, ACK flag not set
            flow_key = self._get_flow_key(packet, 'client')

            if flow_key not in self.incomplete_handshakes:
                ip = get_ip_layer(packet)
                if not ip:
                    return

                handshake = HandshakeFlow(
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    syn_time=packet_time,
                    syn_packet_num=packet_num
                )
                self.incomplete_handshakes[flow_key] = handshake

        # Détection SYN/ACK
        elif tcp.flags & 0x12 == 0x12:  # SYN+ACK flags set
            flow_key = self._get_flow_key(packet, 'server')

            if flow_key in self.incomplete_handshakes:
                handshake = self.incomplete_handshakes[flow_key]
                handshake.synack_time = packet_time
                handshake.synack_packet_num = packet_num
                # RFC 793: Store SYN-ACK sequence number for final ACK validation
                handshake.synack_seq = tcp.seq

                if handshake.syn_time:
                    handshake.syn_to_synack_delay = packet_time - handshake.syn_time

        # Détection ACK final (après SYN/ACK)
        elif tcp.flags & 0x10 and not tcp.flags & 0x02:  # ACK flag set, SYN not set
            flow_key = self._get_flow_key(packet, 'client')

            if flow_key in self.incomplete_handshakes:
                handshake = self.incomplete_handshakes[flow_key]

                # RFC 793: Only process if we've seen the SYN/ACK AND verify ACK number
                # The ACK number must equal SYN-ACK's SEQ + 1
                if handshake.synack_time and handshake.synack_seq is not None:
                    # RFC 793: Validate that ACK = SYN-ACK.SEQ + 1 (proper handshake completion)
                    expected_ack = handshake.synack_seq + 1
                    if tcp.ack == expected_ack:
                        handshake.ack_time = packet_time
                        handshake.ack_packet_num = packet_num
                        handshake.synack_to_ack_delay = packet_time - handshake.synack_time

                        if handshake.syn_time:
                            handshake.total_handshake_time = packet_time - handshake.syn_time
                            handshake.complete = True

                            # Détermine le côté suspect
                            handshake.suspected_side = self._identify_suspect_side(handshake)

                            # Ajout aux handshakes terminés si on doit l'inclure
                            if self._should_include_handshake(handshake):
                                self.handshakes.append(handshake)

                            # Suppression des incomplets
                            del self.incomplete_handshakes[flow_key]
                    # If ACK number doesn't match, this is not the handshake completion ACK

    def _cleanup_stale_handshakes(self, current_time: float) -> None:
        """
        Remove stale incomplete handshakes to prevent memory leaks.

        Handshakes that haven't completed within the timeout period (default 60s)
        are removed from tracking. This prevents memory exhaustion in long captures
        with many incomplete or failed connection attempts.

        Args:
            current_time: Current packet timestamp (seconds since epoch)

        Note:
            This is called every 10,000 packets. Timeout period is configurable
            via _handshake_timeout attribute.
        """
        stale_keys = []
        for key, handshake in self.incomplete_handshakes.items():
            if handshake.syn_time and (current_time - handshake.syn_time) > self._handshake_timeout:
                stale_keys.append(key)

        # Remove stale handshakes
        for key in stale_keys:
            del self.incomplete_handshakes[key]

    def finalize(self) -> Dict[str, Any]:
        """Finalise l'analyse et génère le rapport"""
        # Ajoute les handshakes incomplets à la liste finale
        for handshake in self.incomplete_handshakes.values():
            if handshake.syn_to_synack_delay:
                handshake.suspected_side = self._identify_suspect_side(handshake)
            # Applique le filtre de latence si défini
            if self._should_include_handshake(handshake):
                self.handshakes.append(handshake)

        return self._generate_report()

    def _get_flow_key(self, packet: Packet, direction: str) -> str:
        """
        Génère une clé unique pour identifier un flux TCP

        Args:
            packet: Paquet Scapy
            direction: 'client' ou 'server'

        Returns:
            Clé de flux
        """
        ip = get_ip_layer(packet)
        if not ip or not packet.haslayer(TCP):
            return ""

        tcp = packet[TCP]

        if direction == 'client':
            return f"{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}"
        else:  # server
            return f"{ip.dst}:{tcp.dport}->{ip.src}:{tcp.sport}"

    def _should_include_handshake(self, handshake: HandshakeFlow) -> bool:
        """
        Détermine si un handshake doit être inclus selon le filtre de latence

        Args:
            handshake: Flux de handshake

        Returns:
            True si le handshake doit être inclus, False sinon
        """
        if self.latency_filter is None:
            return True  # Pas de filtre, on inclut tout

        # On garde le handshake si AU MOINS UNE de ses latences dépasse le seuil
        if handshake.total_handshake_time and handshake.total_handshake_time >= self.latency_filter:
            return True
        if handshake.syn_to_synack_delay and handshake.syn_to_synack_delay >= self.latency_filter:
            return True
        if handshake.synack_to_ack_delay and handshake.synack_to_ack_delay >= self.latency_filter:
            return True

        return False

    def _identify_suspect_side(self, handshake: HandshakeFlow) -> str:
        """
        Identify the suspected bottleneck in a slow handshake.

        Uses heuristics to determine whether the client, server, or network
        is responsible for handshake delays:
        - High SYN→SYN-ACK delay (>0.5s): Server bottleneck
        - Moderate SYN→SYN-ACK delay (>threshold): Network latency
        - High SYN-ACK→ACK delay: Client bottleneck
        - Normal individual delays but high total: Network jitter

        Args:
            handshake: Handshake flow to analyze

        Returns:
            Suspected bottleneck: 'client', 'server', 'network', 'none', or 'unknown'

        Note:
            These heuristics work best for LAN analysis. WAN scenarios may
            produce different patterns due to geographic latency.
        """
        if not handshake.syn_to_synack_delay:
            return "unknown"

        # Si le délai SYN→SYN/ACK est élevé, le serveur est probablement lent
        if handshake.syn_to_synack_delay > self.syn_synack_threshold:
            if handshake.syn_to_synack_delay > 0.5:
                return "server"
            else:
                return "network"

        # Si le délai SYN/ACK→ACK est élevé, le client est probablement lent
        if handshake.synack_to_ack_delay and handshake.synack_to_ack_delay > self.syn_synack_threshold:
            return "client"

        # Si les deux délais sont normaux mais le total est élevé
        if handshake.total_handshake_time and handshake.total_handshake_time > self.total_threshold:
            return "network"

        return "none"

    def _generate_report(self) -> Dict[str, Any]:
        """Génère le rapport d'analyse des handshakes TCP"""
        complete_handshakes = [h for h in self.handshakes if h.complete]
        incomplete_handshakes = [h for h in self.handshakes if not h.complete]

        slow_handshakes = [
            h for h in complete_handshakes
            if h.total_handshake_time and h.total_handshake_time > self.total_threshold
        ]

        # Statistiques par côté suspect
        suspect_counts = defaultdict(int)
        for handshake in self.handshakes:
            suspect_counts[handshake.suspected_side] += 1

        return {
            'total_handshakes': len(self.handshakes),
            'complete_handshakes': len(complete_handshakes),
            'incomplete_handshakes': len(incomplete_handshakes),
            'slow_handshakes': len(slow_handshakes),
            'thresholds': {
                'syn_synack_seconds': self.syn_synack_threshold,
                'total_seconds': self.total_threshold
            },
            'suspect_side_distribution': dict(suspect_counts),
            'handshakes': [asdict(h) for h in self.handshakes],
            'slow_handshake_details': [asdict(h) for h in slow_handshakes]
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse des handshakes"""
        complete = sum(1 for h in self.handshakes if h.complete)
        incomplete = len(self.handshakes) - complete
        slow = sum(
            1 for h in self.handshakes
            if h.total_handshake_time and h.total_handshake_time > self.total_threshold
        )

        summary = f"📊 Analyse des handshakes TCP:\n"
        summary += f"  - Total: {len(self.handshakes)}\n"
        summary += f"  - Complets: {complete}\n"
        summary += f"  - Incomplets: {incomplete}\n"

        if slow > 0:
            summary += f"\n🔴 {slow} handshake(s) lent(s) détecté(s):\n"

            for h in self.handshakes:
                if h.total_handshake_time and h.total_handshake_time > self.total_threshold:
                    summary += f"\n  {h.src_ip}:{h.src_port} → {h.dst_ip}:{h.dst_port}\n"
                    summary += f"    - Durée totale: {h.total_handshake_time:.3f}s\n"
                    if h.syn_to_synack_delay:
                        summary += f"    - SYN→SYN/ACK: {h.syn_to_synack_delay:.3f}s\n"
                    if h.synack_to_ack_delay:
                        summary += f"    - SYN/ACK→ACK: {h.synack_to_ack_delay:.3f}s\n"
                    summary += f"    - Côté suspect: {h.suspected_side}\n"
        else:
            summary += f"\n✓ Aucun handshake lent détecté.\n"

        return summary
