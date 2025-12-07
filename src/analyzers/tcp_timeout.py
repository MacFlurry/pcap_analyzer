"""
Analyseur des timeouts TCP - Détection des connexions abandonnées et zombie
"""

from scapy.all import Packet, TCP, IP
from typing import List, Dict, Any, Optional, Union
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime

# Import PacketMetadata for hybrid mode support (3-5x faster)
try:
    from ..parsers.fast_parser import PacketMetadata
except ImportError:
    PacketMetadata = None


@dataclass
class TCPConnectionState:
    """État d'une connexion TCP"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    first_seen: float
    last_seen: float
    
    # Flags de progression
    syn_seen: bool = False
    syn_ack_seen: bool = False
    ack_seen: bool = False  # ACK final du handshake
    data_seen: bool = False
    fin_seen: bool = False
    rst_seen: bool = False
    
    # Compteurs
    packet_count: int = 0
    bytes_total: int = 0
    
    # Numéros de paquets pour référence
    syn_packet_num: Optional[int] = None
    last_packet_num: Optional[int] = None
    
    # Diagnostics
    state: str = "unknown"
    idle_time: float = 0.0
    
    @property
    def flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port} → {self.dst_ip}:{self.dst_port}"
    
    @property
    def duration(self) -> float:
        return self.last_seen - self.first_seen


class TCPTimeoutAnalyzer:
    """Analyseur des timeouts et connexions TCP problématiques"""

    def __init__(self, idle_threshold: float = 30.0, zombie_threshold: float = 60.0):
        """
        Initialise l'analyseur de timeouts TCP
        
        Args:
            idle_threshold: Seuil d'inactivité pour détecter une pause (secondes)
            zombie_threshold: Seuil pour considérer une connexion comme zombie (secondes)
        """
        self.idle_threshold = idle_threshold
        self.zombie_threshold = zombie_threshold
        
        # Suivi des connexions par clé normalisée
        self.connections: Dict[str, TCPConnectionState] = {}
        
        # Timestamp global
        self.first_packet_time: Optional[float] = None
        self.last_packet_time: Optional[float] = None
        self.packet_count = 0
        
        # Compteur RST pour cohérence avec tcp_reset.py
        self.total_rst_packets = 0

    def _normalize_flow_key(self, src_ip: str, dst_ip: str, 
                            src_port: int, dst_port: int) -> str:
        """Génère une clé de flux normalisée (bidirectionnelle)"""
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}<->{dst_ip}:{dst_port}"
        else:
            return f"{dst_ip}:{dst_port}<->{src_ip}:{src_port}"

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
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return

        self.packet_count += 1

        ip = packet[IP]
        tcp = packet[TCP]
        packet_time = float(packet.time)
        
        # Mise à jour des timestamps globaux
        if self.first_packet_time is None:
            self.first_packet_time = packet_time
        self.last_packet_time = packet_time
        
        # Clé normalisée pour le flux
        flow_key = self._normalize_flow_key(ip.src, ip.dst, tcp.sport, tcp.dport)
        
        # Créer ou récupérer l'état de connexion
        if flow_key not in self.connections:
            conn = TCPConnectionState(
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                first_seen=packet_time,
                last_seen=packet_time
            )
            self.connections[flow_key] = conn
        else:
            conn = self.connections[flow_key]
        
        # Mise à jour des compteurs
        conn.packet_count += 1
        conn.bytes_total += len(packet)
        conn.last_seen = packet_time
        conn.last_packet_num = packet_num
        
        # Calcul du payload TCP
        tcp_payload_len = len(tcp.payload) if tcp.payload else 0
        
        # Détection des flags TCP
        flags = tcp.flags
        
        # SYN (sans ACK) - Début de connexion
        if flags & 0x02 and not flags & 0x10:
            conn.syn_seen = True
            if conn.syn_packet_num is None:
                conn.syn_packet_num = packet_num
        
        # SYN-ACK - Réponse du serveur
        elif flags & 0x12 == 0x12:
            conn.syn_ack_seen = True
        
        # ACK (sans SYN) - Potentiellement fin de handshake ou données
        elif flags & 0x10 and not flags & 0x02:
            if conn.syn_ack_seen and not conn.ack_seen:
                conn.ack_seen = True
            if tcp_payload_len > 0:
                conn.data_seen = True
        
        # FIN - Fermeture propre
        if flags & 0x01:
            conn.fin_seen = True
        
        # RST - Fermeture brutale
        if flags & 0x04:
            conn.rst_seen = True
            self.total_rst_packets += 1  # Comptage global pour cohérence

    def _process_metadata(self, metadata: 'PacketMetadata', packet_num: int) -> None:
        """
        PERFORMANCE OPTIMIZED: Process lightweight PacketMetadata (3-5x faster than Scapy).

        This method replicates TCP timeout detection logic but uses direct attribute access
        from dpkt-extracted metadata.

        Args:
            metadata: Lightweight packet metadata from dpkt
            packet_num: Packet sequence number in capture
        """
        # Skip non-TCP packets
        if metadata.protocol != 'TCP':
            return

        self.packet_count += 1

        packet_time = metadata.timestamp

        # Mise à jour des timestamps globaux
        if self.first_packet_time is None:
            self.first_packet_time = packet_time
        self.last_packet_time = packet_time

        # Clé normalisée pour le flux
        flow_key = self._normalize_flow_key(
            metadata.src_ip, metadata.dst_ip,
            metadata.src_port, metadata.dst_port
        )

        # Créer ou récupérer l'état de connexion
        if flow_key not in self.connections:
            conn = TCPConnectionState(
                src_ip=metadata.src_ip,
                dst_ip=metadata.dst_ip,
                src_port=metadata.src_port,
                dst_port=metadata.dst_port,
                first_seen=packet_time,
                last_seen=packet_time
            )
            self.connections[flow_key] = conn
        else:
            conn = self.connections[flow_key]

        # Mise à jour des compteurs
        conn.packet_count += 1
        conn.bytes_total += metadata.packet_length
        conn.last_seen = packet_time
        conn.last_packet_num = packet_num

        # Détection des flags TCP via convenience flags
        # SYN (sans ACK) - Début de connexion
        if metadata.is_syn and not metadata.is_ack:
            conn.syn_seen = True
            if conn.syn_packet_num is None:
                conn.syn_packet_num = packet_num

        # SYN-ACK - Réponse du serveur
        elif metadata.is_syn and metadata.is_ack:
            conn.syn_ack_seen = True

        # ACK (sans SYN) - Potentiellement fin de handshake ou données
        elif metadata.is_ack and not metadata.is_syn:
            if conn.syn_ack_seen and not conn.ack_seen:
                conn.ack_seen = True
            if metadata.tcp_payload_len > 0:
                conn.data_seen = True

        # FIN - Fermeture propre
        if metadata.is_fin:
            conn.fin_seen = True

        # RST - Fermeture brutale
        if metadata.is_rst:
            conn.rst_seen = True
            self.total_rst_packets += 1  # Comptage global pour cohérence

    def finalize(self) -> Dict[str, Any]:
        """Finalise l'analyse et classifie les connexions"""
        # Classifie toutes les connexions
        for flow_key, conn in self.connections.items():
            self._classify_connection(conn)
        
        return self.get_results()

    def _classify_connection(self, conn: TCPConnectionState) -> None:
        """Classifie l'état d'une connexion TCP"""
        capture_end = self.last_packet_time or conn.last_seen
        conn.idle_time = capture_end - conn.last_seen
        
        # Connexion fermée proprement
        if conn.fin_seen:
            conn.state = "closed_fin"
            return
        
        # Connexion fermée par RST
        if conn.rst_seen:
            conn.state = "closed_rst"
            return
        
        # SYN envoyé mais pas de SYN-ACK reçu
        if conn.syn_seen and not conn.syn_ack_seen:
            if conn.idle_time > self.idle_threshold:
                conn.state = "syn_timeout"
            else:
                conn.state = "syn_waiting"
            return
        
        # SYN-ACK reçu mais pas d'ACK final (half-open)
        if conn.syn_seen and conn.syn_ack_seen and not conn.ack_seen:
            conn.state = "half_open"
            return
        
        # Connexion établie mais pas de données
        if conn.syn_seen and conn.syn_ack_seen and conn.ack_seen and not conn.data_seen:
            if conn.idle_time > self.idle_threshold:
                conn.state = "established_idle"
            else:
                conn.state = "established_no_data"
            return
        
        # Connexion avec données mais pas fermée
        if conn.data_seen and not conn.fin_seen and not conn.rst_seen:
            if conn.idle_time > self.zombie_threshold:
                conn.state = "zombie"
            elif conn.idle_time > self.idle_threshold:
                conn.state = "idle"
            else:
                conn.state = "active"
            return
        
        # Cas par défaut
        conn.state = "unknown"

    def get_results(self) -> Dict[str, Any]:
        """Génère les résultats d'analyse"""
        # Catégoriser les connexions
        categories = {
            'syn_timeout': [],      # SYN sans réponse
            'half_open': [],        # Handshake incomplet
            'zombie': [],           # Connexions zombie
            'idle': [],             # Connexions inactives
            'established_idle': [], # Établies mais inactives
            'closed_fin': [],       # Fermées proprement
            'closed_rst': [],       # Fermées par RST
            'active': [],           # Actives
            'other': []             # Autres
        }
        
        for flow_key, conn in self.connections.items():
            state = conn.state
            if state in categories:
                categories[state].append(conn)
            else:
                categories['other'].append(conn)
        
        # Statistiques globales
        total_connections = len(self.connections)
        problematic_count = (
            len(categories['syn_timeout']) + 
            len(categories['half_open']) + 
            len(categories['zombie']) + 
            len(categories['idle']) +
            len(categories['established_idle'])
        )
        
        # Trier les problématiques par idle_time décroissant
        for cat in ['syn_timeout', 'half_open', 'zombie', 'idle', 'established_idle']:
            categories[cat].sort(key=lambda c: c.idle_time, reverse=True)
        
        # Calculer la durée de capture
        capture_duration = 0
        if self.first_packet_time and self.last_packet_time:
            capture_duration = self.last_packet_time - self.first_packet_time
        
        return {
            'total_connections': total_connections,
            'problematic_count': problematic_count,
            'capture_duration': capture_duration,
            'thresholds': {
                'idle_threshold': self.idle_threshold,
                'zombie_threshold': self.zombie_threshold
            },
            'categories': {
                'syn_timeout': self._format_connections(categories['syn_timeout'][:10]),
                'syn_timeout_count': len(categories['syn_timeout']),
                'half_open': self._format_connections(categories['half_open'][:10]),
                'half_open_count': len(categories['half_open']),
                'zombie': self._format_connections(categories['zombie'][:10]),
                'zombie_count': len(categories['zombie']),
                'idle': self._format_connections(categories['idle'][:10]),
                'idle_count': len(categories['idle']),
                'established_idle': self._format_connections(categories['established_idle'][:10]),
                'established_idle_count': len(categories['established_idle']),
                'closed_fin_count': len(categories['closed_fin']),
                'closed_rst_count': len(categories['closed_rst']),
                'total_rst_packets': self.total_rst_packets,  # Total des paquets RST vus
                'active_count': len(categories['active'])
            }
        }

    def _format_connections(self, connections: List[TCPConnectionState]) -> List[Dict[str, Any]]:
        """Formate les connexions pour le rapport"""
        result = []
        for conn in connections:
            result.append({
                'flow': conn.flow_key,
                'src_ip': conn.src_ip,
                'dst_ip': conn.dst_ip,
                'src_port': conn.src_port,
                'dst_port': conn.dst_port,
                'first_seen': conn.first_seen,
                'first_seen_iso': datetime.fromtimestamp(conn.first_seen).strftime('%H:%M:%S.%f')[:-3],
                'last_seen': conn.last_seen,
                'last_seen_iso': datetime.fromtimestamp(conn.last_seen).strftime('%H:%M:%S.%f')[:-3],
                'duration': round(conn.duration, 3),
                'idle_time': round(conn.idle_time, 3),
                'packet_count': conn.packet_count,
                'bytes_total': conn.bytes_total,
                'state': conn.state,
                'syn_seen': conn.syn_seen,
                'syn_ack_seen': conn.syn_ack_seen,
                'data_seen': conn.data_seen,
                'fin_seen': conn.fin_seen,
                'rst_seen': conn.rst_seen
            })
        return result

    def get_summary(self) -> str:
        """Génère un résumé textuel"""
        results = self.get_results()
        cats = results['categories']
        
        lines = [
            f"=== Analyse des Timeouts TCP ===",
            f"Connexions totales: {results['total_connections']}",
            f"Connexions problématiques: {results['problematic_count']}",
            f"",
            f"Répartition:",
            f"  - SYN timeout (pas de réponse): {cats['syn_timeout_count']}",
            f"  - Half-open (handshake incomplet): {cats['half_open_count']}",
            f"  - Zombie (inactives depuis >{results['thresholds']['zombie_threshold']}s): {cats['zombie_count']}",
            f"  - Idle (inactives depuis >{results['thresholds']['idle_threshold']}s): {cats['idle_count']}",
            f"  - Établies sans données: {cats['established_idle_count']}",
            f"  - Fermées proprement (FIN): {cats['closed_fin_count']}",
            f"  - Fermées brutalement (RST): {cats['closed_rst_count']}",
            f"  - Actives: {cats['active_count']}"
        ]
        
        return "\n".join(lines)
