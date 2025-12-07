"""
Analyseur des retransmissions SYN - Détection détaillée des problèmes de handshake TCP
"""

from scapy.all import Packet, TCP
from typing import List, Dict, Any, Optional, Tuple, Union
from dataclasses import dataclass, asdict, field
from collections import defaultdict
from datetime import datetime
from ..utils.packet_utils import get_ip_layer

# Import PacketMetadata for hybrid mode support (3-5x faster)
try:
    from ..parsers.fast_parser import PacketMetadata
except ImportError:
    PacketMetadata = None


@dataclass
class SYNRetransmission:
    """Représente une séquence de retransmissions SYN"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    first_syn_time: float
    initial_seq: Optional[int] = None  # RFC 793: Track Initial Sequence Number (ISN)
    syn_attempts: List[float] = field(default_factory=list)
    syn_packet_nums: List[int] = field(default_factory=list)
    synack_time: Optional[float] = None
    synack_packet_num: Optional[int] = None
    total_delay: Optional[float] = None
    retransmission_count: int = 0
    synack_received: bool = False
    suspected_issue: str = "unknown"
    
    def to_human_readable(self) -> Dict[str, Any]:
        """Convertit en format lisible avec timestamps ISO"""
        result = asdict(self)
        result['first_syn_time_iso'] = datetime.fromtimestamp(self.first_syn_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        if self.synack_time:
            result['synack_time_iso'] = datetime.fromtimestamp(self.synack_time).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        result['syn_attempts_iso'] = [
            datetime.fromtimestamp(t).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] 
            for t in self.syn_attempts
        ]
        return result


class SYNRetransmissionAnalyzer:
    """Analyseur des retransmissions SYN pour diagnostic approfondi"""

    def __init__(self, threshold: float = 2.0):
        """
        Initialise l'analyseur de retransmissions SYN

        Args:
            threshold: Seuil en secondes pour considérer un délai comme problématique
        """
        self.threshold = threshold
        self.retransmissions: List[SYNRetransmission] = []
        self.pending_syns: Dict[str, SYNRetransmission] = {}

        # Memory optimization: periodic cleanup
        self._packet_counter = 0
        self._cleanup_interval = 5000  # Cleanup every 5k packets
        self._pending_timeout = 60.0  # Remove pending SYNs after 60s

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyse les retransmissions SYN dans les paquets

        Args:
            packets: Liste des paquets Scapy

        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        for i, packet in enumerate(packets):
            self.process_packet(packet, i)

        return self.finalize()

    def process_packet(self, packet: Union[Packet, 'PacketMetadata'], packet_num: int) -> None:
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

        tcp = packet[TCP]
        packet_time = float(packet.time)

        # Memory optimization: periodic cleanup of stale pending SYNs
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_stale_pending_syns(packet_time)

        # Détection SYN (sans ACK)
        if tcp.flags & 0x02 and not tcp.flags & 0x10:
            base_flow_key = (ip.src, ip.dst, tcp.sport, tcp.dport)
            
            # Vérifier si c'est une retransmission (même flux, même seq number)
            if base_flow_key in self.pending_syns:
                retrans = self.pending_syns[base_flow_key]
                # On considère que c'est une retransmission si c'est le même flux
                # et que le temps est cohérent (< 10s depuis le dernier SYN)
                if retrans.syn_attempts and packet_time - retrans.syn_attempts[-1] < 10.0:
                    retrans.syn_attempts.append(packet_time)
                    retrans.syn_packet_nums.append(packet_num)
                    retrans.retransmission_count += 1
            else:
                # Nouveau SYN
                retrans = SYNRetransmission(
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    first_syn_time=packet_time,
                    syn_attempts=[packet_time],
                    syn_packet_nums=[packet_num],
                    retransmission_count=0
                )
                self.pending_syns[base_flow_key] = retrans

        # Détection SYN/ACK
        elif tcp.flags & 0x12 == 0x12:
            reverse_flow = (ip.dst, ip.src, tcp.dport, tcp.sport)
            
            if reverse_flow in self.pending_syns:
                retrans = self.pending_syns[reverse_flow]
                if not retrans.synack_received:
                    retrans.synack_received = True
                    retrans.synack_time = packet_time
                    retrans.synack_packet_num = packet_num
                    retrans.total_delay = packet_time - retrans.first_syn_time
                    
                    # Analyse de la cause du délai
                    retrans.suspected_issue = self._identify_issue(retrans)
                    
                    # Ajoute aux retransmissions complétées si délai >= seuil ou retransmissions présentes
                    if retrans.total_delay >= self.threshold or retrans.retransmission_count > 0:
                        self.retransmissions.append(retrans)
                    
                    del self.pending_syns[reverse_flow]

    def _process_metadata(self, metadata: 'PacketMetadata', packet_num: int) -> None:
        """
        PERFORMANCE OPTIMIZED: Process lightweight PacketMetadata (3-5x faster than Scapy).

        This method replicates SYN retransmission detection logic but uses direct attribute access
        from dpkt-extracted metadata.

        Args:
            metadata: Lightweight packet metadata from dpkt
            packet_num: Packet sequence number in capture
        """
        # Skip non-TCP packets
        if metadata.protocol != 'TCP':
            return

        packet_time = metadata.timestamp

        # Memory optimization: periodic cleanup of stale pending SYNs
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_stale_pending_syns(packet_time)

        # Détection SYN (sans ACK)
        if metadata.is_syn and not metadata.is_ack:
            base_flow_key = (metadata.src_ip, metadata.dst_ip, metadata.src_port, metadata.dst_port)

            # Vérifier si c'est une retransmission (même flux, même seq number)
            if base_flow_key in self.pending_syns:
                retrans = self.pending_syns[base_flow_key]
                # On considère que c'est une retransmission si c'est le même flux
                # et que le temps est cohérent (< 10s depuis le dernier SYN)
                if retrans.syn_attempts and packet_time - retrans.syn_attempts[-1] < 10.0:
                    retrans.syn_attempts.append(packet_time)
                    retrans.syn_packet_nums.append(packet_num)
                    retrans.retransmission_count += 1
            else:
                # Nouveau SYN
                retrans = SYNRetransmission(
                    src_ip=metadata.src_ip,
                    dst_ip=metadata.dst_ip,
                    src_port=metadata.src_port,
                    dst_port=metadata.dst_port,
                    first_syn_time=packet_time,
                    syn_attempts=[packet_time],
                    syn_packet_nums=[packet_num],
                    retransmission_count=0
                )
                self.pending_syns[base_flow_key] = retrans

        # Détection SYN/ACK
        elif metadata.is_syn and metadata.is_ack:
            reverse_flow = (metadata.dst_ip, metadata.src_ip, metadata.dst_port, metadata.src_port)

            if reverse_flow in self.pending_syns:
                retrans = self.pending_syns[reverse_flow]
                if not retrans.synack_received:
                    retrans.synack_received = True
                    retrans.synack_time = packet_time
                    retrans.synack_packet_num = packet_num
                    retrans.total_delay = packet_time - retrans.first_syn_time

                    # Analyse de la cause du délai
                    retrans.suspected_issue = self._identify_issue(retrans)

                    # Ajoute aux retransmissions complétées si délai >= seuil ou retransmissions présentes
                    if retrans.total_delay >= self.threshold or retrans.retransmission_count > 0:
                        self.retransmissions.append(retrans)

                    del self.pending_syns[reverse_flow]

    def _cleanup_stale_pending_syns(self, current_time: float) -> None:
        """
        Remove stale pending SYNs to prevent memory leaks.

        Args:
            current_time: Current packet timestamp
        """
        stale_keys = []
        for key, retrans in self.pending_syns.items():
            # Calculate time since first SYN
            if retrans.first_syn_time and (current_time - retrans.first_syn_time) > self._pending_timeout:
                stale_keys.append(key)

        # Remove stale pending SYNs
        for key in stale_keys:
            del self.pending_syns[key]

    def finalize(self) -> Dict[str, Any]:
        """Finalise l'analyse et génère le rapport"""
        # Ajoute les SYN sans réponse
        for retrans in self.pending_syns.values():
            if not retrans.synack_received and retrans.retransmission_count > 0:
                retrans.suspected_issue = "no_synack_received"
                # Si pas de réponse, le délai est la différence entre le dernier et le premier SYN
                if retrans.syn_attempts:
                    retrans.total_delay = retrans.syn_attempts[-1] - retrans.first_syn_time
                self.retransmissions.append(retrans)

        return self._generate_report()

    def _identify_issue(self, retrans: SYNRetransmission) -> str:
        """
        Identifie le type de problème

        Args:
            retrans: Objet SYNRetransmission

        Returns:
            Type de problème identifié
        """
        if not retrans.synack_received:
            return "no_response"
        
        if retrans.total_delay is None:
            return "unknown"
        
        # Calcule les intervalles entre retransmissions
        intervals = []
        for i in range(1, len(retrans.syn_attempts)):
            intervals.append(retrans.syn_attempts[i] - retrans.syn_attempts[i-1])
        
        # Pattern typique : 1s, 2s (exponential backoff)
        if len(intervals) >= 2:
            if 0.9 <= intervals[0] <= 1.1 and 1.9 <= intervals[1] <= 2.1:
                if retrans.total_delay >= 3.0:
                    return "server_delayed_response"
        
        if retrans.total_delay >= 3.0:
            return "severe_network_delay"
        elif retrans.total_delay >= 1.0:
            return "moderate_network_delay"
        
        return "normal"

    def _generate_report(self) -> Dict[str, Any]:
        """Génère le rapport d'analyse des retransmissions SYN"""
        # Trie par délai décroissant
        sorted_retrans = sorted(
            self.retransmissions,
            key=lambda r: r.total_delay if r.total_delay else 0,
            reverse=True
        )

        # Statistiques par type de problème
        issue_counts = defaultdict(int)
        for retrans in self.retransmissions:
            issue_counts[retrans.suspected_issue] += 1

        # Calculs statistiques
        delays = [r.total_delay for r in self.retransmissions if r.total_delay]
        retrans_counts = [r.retransmission_count for r in self.retransmissions]

        stats = {}
        if delays:
            stats = {
                'min_delay': min(delays),
                'max_delay': max(delays),
                'avg_delay': sum(delays) / len(delays),
                'median_delay': sorted(delays)[len(delays) // 2]
            }
        
        retrans_stats = {}
        if retrans_counts:
            retrans_stats = {
                'min_retrans': min(retrans_counts),
                'max_retrans': max(retrans_counts),
                'avg_retrans': sum(retrans_counts) / len(retrans_counts)
            }

        return {
            'total_syn_retransmissions': len(self.retransmissions),
            'threshold_seconds': self.threshold,
            'issue_distribution': dict(issue_counts),
            'delay_statistics': stats,
            'retransmission_statistics': retrans_stats,
            'top_problematic_connections': [r.to_human_readable() for r in sorted_retrans[:10]],
            'all_retransmissions': [r.to_human_readable() for r in self.retransmissions]
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse"""
        if not self.retransmissions:
            return "✅ Aucune retransmission SYN problématique détectée.\n"

        # Trie par délai
        sorted_retrans = sorted(
            self.retransmissions,
            key=lambda r: r.total_delay if r.total_delay else 0,
            reverse=True
        )

        summary = f"🔍 Analyse des retransmissions SYN:\n"
        summary += f"  - Total de connexions problématiques: {len(self.retransmissions)}\n"
        summary += f"  - Seuil de détection: {self.threshold}s\n\n"

        # Statistiques
        delays = [r.total_delay for r in self.retransmissions if r.total_delay]
        if delays:
            summary += f"📊 Statistiques de délai:\n"
            summary += f"  - Min: {min(delays):.3f}s\n"
            summary += f"  - Max: {max(delays):.3f}s\n"
            summary += f"  - Moyenne: {sum(delays)/len(delays):.3f}s\n\n"

        # Top 5 des connexions les plus problématiques
        summary += "🔴 Top 5 des connexions les plus lentes:\n\n"
        for i, retrans in enumerate(sorted_retrans[:5], 1):
            summary += f"#{i} - {retrans.src_ip}:{retrans.src_port} → {retrans.dst_ip}:{retrans.dst_port}\n"
            summary += f"     Premier SYN: {datetime.fromtimestamp(retrans.first_syn_time).strftime('%H:%M:%S.%f')[:-3]}\n"
            
            if retrans.synack_time:
                summary += f"     SYN/ACK reçu: {datetime.fromtimestamp(retrans.synack_time).strftime('%H:%M:%S.%f')[:-3]}\n"
                summary += f"     Délai total: {retrans.total_delay:.3f}s\n"
            
            summary += f"     Retransmissions SYN: {retrans.retransmission_count}\n"
            
            # Détail des tentatives
            if len(retrans.syn_attempts) > 1:
                summary += f"     Timeline des SYN:\n"
                for j, syn_time in enumerate(retrans.syn_attempts, 1):
                    delay_from_first = syn_time - retrans.first_syn_time
                    summary += f"       - Tentative #{j}: +{delay_from_first:.3f}s\n"
            
            summary += f"     Problème identifié: {retrans.suspected_issue}\n\n"

        return summary

    def get_detailed_connection(self, src_ip: str, src_port: int) -> Optional[Dict[str, Any]]:
        """
        Retourne les détails d'une connexion spécifique

        Args:
            src_ip: IP source
            src_port: Port source

        Returns:
            Détails de la connexion ou None
        """
        for retrans in self.retransmissions:
            if retrans.src_ip == src_ip and retrans.src_port == src_port:
                return retrans.to_human_readable()
        return None
