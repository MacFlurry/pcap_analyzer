"""
Analyseur SACK (Selective Acknowledgment) et D-SACK.
Détecte l'utilisation des accusés de réception sélectifs TCP.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP
from datetime import datetime
import struct


@dataclass
class SackBlock:
    """Bloc SACK représentant une plage de séquences reçues."""
    left_edge: int
    right_edge: int
    
    def size(self) -> int:
        """Taille du bloc en octets."""
        return self.right_edge - self.left_edge
    
    def __str__(self) -> str:
        return f"{self.left_edge}-{self.right_edge}"


@dataclass
class SackEvent:
    """Événement SACK détecté."""
    timestamp: float
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sack_blocks: List[SackBlock]
    is_dsack: bool = False
    dsack_sequence: Optional[int] = None
    total_sacked_bytes: int = 0
    
    def time_iso(self) -> str:
        """Timestamp en format ISO."""
        return datetime.fromtimestamp(self.timestamp).strftime("%H:%M:%S.%f")[:-3]


@dataclass
class FlowSackStats:
    """Statistiques SACK pour un flux."""
    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sack_events: int = 0
    dsack_events: int = 0
    total_sacked_bytes: int = 0
    unique_sack_blocks: Set[Tuple[int, int]] = field(default_factory=set)
    first_sack_time: Optional[float] = None
    last_sack_time: Optional[float] = None
    
    def __post_init__(self):
        if not isinstance(self.unique_sack_blocks, set):
            self.unique_sack_blocks = set()


class SackAnalyzer:
    """
    Analyseur SACK (Selective Acknowledgment) et D-SACK.
    
    Détecte et analyse:
    - Utilisation de SACK (TCP Option 5)
    - Blocs SACK (plages de séquences reçues)
    - D-SACK (Duplicate SACK) pour détecter les doublons
    - Efficacité des retransmissions sélectives
    - Flux utilisant SACK vs non-SACK
    """
    
    def __init__(self):
        """Initialise l'analyseur."""
        # Stockage par flux
        self.flows: Dict[str, FlowSackStats] = {}
        
        # Événements SACK
        self.sack_events: List[SackEvent] = []
        
        # Stats globales
        self.total_packets = 0
        self.tcp_packets = 0
        self.sack_packets = 0
        self.dsack_packets = 0
        
        # Suivi des séquences pour détecter D-SACK
        self.flow_sequences: Dict[str, Set[int]] = defaultdict(set)
    
    def _get_flow_key(self, src_ip: str, dst_ip: str, 
                     src_port: int, dst_port: int) -> str:
        """Génère une clé de flux normalisée (bidirectionnelle)."""
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        else:
            return f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"
    
    def _parse_sack_option(self, tcp_packet: TCP) -> Optional[List[SackBlock]]:
        """
        Parse l'option SACK TCP (option 5).
        
        Format: Kind(1) + Length(1) + Blocks(8*n bytes)
        Chaque bloc: Left Edge(4) + Right Edge(4)
        """
        if not hasattr(tcp_packet, 'options') or not tcp_packet.options:
            return None
        
        sack_blocks = []
        
        for option in tcp_packet.options:
            if isinstance(option, tuple) and len(option) == 2:
                kind, data = option
                
                # Option 5 = SACK
                if kind == 5 and data:
                    # Data contient les blocs SACK
                    if len(data) % 8 != 0:
                        continue  # Longueur invalide
                    
                    # Chaque bloc fait 8 octets (2 x 4 octets)
                    num_blocks = len(data) // 8
                    
                    for i in range(num_blocks):
                        offset = i * 8
                        try:
                            # Unpack 2 entiers de 4 octets (big endian)
                            left_edge, right_edge = struct.unpack('!II', 
                                                                 data[offset:offset+8])
                            
                            if left_edge < right_edge:  # Validation
                                sack_blocks.append(SackBlock(left_edge, right_edge))
                        except struct.error:
                            continue
        
        return sack_blocks if sack_blocks else None
    
    def _is_dsack(self, sack_blocks: List[SackBlock], 
                  ack_num: int) -> Tuple[bool, Optional[int]]:
        """
        Détecte si c'est un D-SACK (Duplicate SACK).
        
        D-SACK = Premier bloc SACK avec séquence déjà acquittée
        """
        if not sack_blocks:
            return False, None
        
        first_block = sack_blocks[0]
        
        # D-SACK si le premier bloc est avant le numéro d'ACK
        if first_block.right_edge <= ack_num:
            return True, first_block.left_edge
        
        # D-SACK si le premier bloc chevauche avec le deuxième
        if len(sack_blocks) > 1:
            second_block = sack_blocks[1]
            if (first_block.left_edge >= second_block.left_edge and 
                first_block.right_edge <= second_block.right_edge):
                return True, first_block.left_edge
        
        return False, None
    
    def process_packet(self, packet: Packet, packet_num: int = 0) -> None:
        """Traite un paquet et détecte les options SACK."""
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return
        
        self.total_packets += 1
        
        ip = packet[IP]
        tcp = packet[TCP]
        timestamp = float(packet.time)
        
        self.tcp_packets += 1
        
        # Parser les options SACK
        sack_blocks = self._parse_sack_option(tcp)
        if not sack_blocks:
            return
        
        self.sack_packets += 1
        
        # Informations du flux
        src_ip = ip.src
        dst_ip = ip.dst
        src_port = tcp.sport
        dst_port = tcp.dport
        flow_key = self._get_flow_key(src_ip, dst_ip, src_port, dst_port)
        
        # Calculer octets SACK
        total_sacked = sum(block.size() for block in sack_blocks)
        
        # Détecter D-SACK
        is_dsack, dsack_seq = self._is_dsack(sack_blocks, tcp.ack)
        if is_dsack:
            self.dsack_packets += 1
        
        # Créer l'événement SACK
        event = SackEvent(
            timestamp=timestamp,
            flow_key=flow_key,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            sack_blocks=sack_blocks,
            is_dsack=is_dsack,
            dsack_sequence=dsack_seq,
            total_sacked_bytes=total_sacked
        )
        
        self.sack_events.append(event)
        
        # Mettre à jour les stats du flux
        if flow_key not in self.flows:
            self.flows[flow_key] = FlowSackStats(
                flow_key=flow_key,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port
            )
        
        flow_stats = self.flows[flow_key]
        flow_stats.sack_events += 1
        flow_stats.total_sacked_bytes += total_sacked
        
        if is_dsack:
            flow_stats.dsack_events += 1
        
        # Première/dernière occurrence
        if flow_stats.first_sack_time is None:
            flow_stats.first_sack_time = timestamp
        flow_stats.last_sack_time = timestamp
        
        # Blocs uniques
        for block in sack_blocks:
            flow_stats.unique_sack_blocks.add((block.left_edge, block.right_edge))
    
    def finalize(self) -> None:
        """Finalise l'analyse."""
        pass
    
    def get_top_sack_flows(self, limit: int = 20) -> List[FlowSackStats]:
        """Retourne les flux avec le plus d'événements SACK."""
        flows = list(self.flows.values())
        flows.sort(key=lambda f: f.sack_events, reverse=True)
        return flows[:limit]
    
    def get_dsack_flows(self) -> List[FlowSackStats]:
        """Retourne les flux avec des D-SACK (problématiques)."""
        return [f for f in self.flows.values() if f.dsack_events > 0]
    
    def get_results(self) -> Dict[str, Any]:
        """Retourne les résultats complets de l'analyse."""
        # Stats globales
        sack_usage_pct = (self.sack_packets / self.tcp_packets * 100) if self.tcp_packets > 0 else 0
        dsack_ratio = (self.dsack_packets / self.sack_packets * 100) if self.sack_packets > 0 else 0
        
        # Top flows
        top_flows = self.get_top_sack_flows(20)
        dsack_flows = self.get_dsack_flows()
        
        # Calculs d'efficacité
        total_sacked_bytes = sum(f.total_sacked_bytes for f in self.flows.values())
        flows_using_sack = len(self.flows)
        
        # Classification des événements SACK
        normal_sack_events = [e for e in self.sack_events if not e.is_dsack]
        dsack_events = [e for e in self.sack_events if e.is_dsack]
        
        return {
            "summary": {
                "total_packets": self.total_packets,
                "tcp_packets": self.tcp_packets,
                "sack_packets": self.sack_packets,
                "dsack_packets": self.dsack_packets,
                "sack_usage_percentage": round(sack_usage_pct, 2),
                "dsack_ratio_percentage": round(dsack_ratio, 2),
                "flows_using_sack": flows_using_sack,
                "total_sacked_bytes": total_sacked_bytes,
                "total_sack_events": len(self.sack_events)
            },
            "efficiency": {
                "avg_sacked_bytes_per_event": round(total_sacked_bytes / len(self.sack_events), 0) if self.sack_events else 0,
                "flows_with_dsack": len(dsack_flows),
                "dsack_flows_percentage": round(len(dsack_flows) / flows_using_sack * 100, 1) if flows_using_sack > 0 else 0,
                "estimated_retransmission_savings_mb": round(total_sacked_bytes / 1_048_576, 2)
            },
            "top_sack_flows": [
                {
                    "flow": f"{f.src_ip}:{f.src_port} ↔ {f.dst_ip}:{f.dst_port}",
                    "sack_events": f.sack_events,
                    "dsack_events": f.dsack_events,
                    "sacked_bytes": f.total_sacked_bytes,
                    "unique_blocks": len(f.unique_sack_blocks),
                    "dsack_ratio": round(f.dsack_events / f.sack_events * 100, 1) if f.sack_events > 0 else 0,
                    "first_sack": datetime.fromtimestamp(f.first_sack_time).strftime("%H:%M:%S") if f.first_sack_time else "",
                    "duration_seconds": round(f.last_sack_time - f.first_sack_time, 1) if f.first_sack_time and f.last_sack_time else 0
                }
                for f in top_flows
            ],
            "dsack_analysis": {
                "problematic_flows": [
                    {
                        "flow": f"{f.src_ip}:{f.src_port} ↔ {f.dst_ip}:{f.dst_port}",
                        "dsack_events": f.dsack_events,
                        "total_sack_events": f.sack_events,
                        "dsack_percentage": round(f.dsack_events / f.sack_events * 100, 1) if f.sack_events > 0 else 0
                    }
                    for f in sorted(dsack_flows, key=lambda x: x.dsack_events, reverse=True)[:10]
                ]
            },
            "recent_sack_events": [
                {
                    "time": e.time_iso(),
                    "flow": f"{e.src_ip}:{e.src_port} → {e.dst_ip}:{e.dst_port}",
                    "blocks": [str(block) for block in e.sack_blocks[:3]],  # Limiter à 3 blocs
                    "sacked_bytes": e.total_sacked_bytes,
                    "is_dsack": e.is_dsack,
                    "dsack_sequence": e.dsack_sequence
                }
                for e in self.sack_events[-20:]  # 20 plus récents
            ]
        }
    
    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse."""
        results = self.get_results()
        summary = results["summary"]
        efficiency = results["efficiency"]
        
        lines = [
            "=== Analyse SACK/D-SACK ===",
            f"Paquets TCP analysés: {summary['tcp_packets']}",
            f"Paquets avec SACK: {summary['sack_packets']} ({summary['sack_usage_percentage']}%)",
            f"D-SACK détectés: {summary['dsack_packets']} ({summary['dsack_ratio_percentage']}% des SACK)",
            "",
            f"Flux utilisant SACK: {summary['flows_using_sack']}",
            f"Octets acquittés sélectivement: {efficiency['estimated_retransmission_savings_mb']} MB",
            f"Économie estimée en retransmissions: {efficiency['estimated_retransmission_savings_mb']} MB",
            ""
        ]
        
        if efficiency["flows_with_dsack"] > 0:
            lines.append(f"⚠️  Flux avec D-SACK: {efficiency['flows_with_dsack']} ({efficiency['dsack_flows_percentage']}%)")
            lines.append("   (D-SACK indique des doublons ou retransmissions inutiles)")
        
        if results["top_sack_flows"]:
            lines.append("")
            lines.append("Top 3 flux SACK:")
            for f in results["top_sack_flows"][:3]:
                dsack_info = f" ({f['dsack_events']} D-SACK)" if f["dsack_events"] > 0 else ""
                lines.append(f"  - {f['flow']}: {f['sack_events']} événements{dsack_info}")
        
        return "\n".join(lines)