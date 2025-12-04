"""
Analyseur du handshake TCP - Mesure des délais SYN/SYN-ACK/ACK
"""

from scapy.all import Packet, TCP
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class HandshakeFlow:
    """Représente un handshake TCP complet ou partiel"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    syn_time: Optional[float] = None
    syn_packet_num: Optional[int] = None
    synack_time: Optional[float] = None
    synack_packet_num: Optional[int] = None
    ack_time: Optional[float] = None
    ack_packet_num: Optional[int] = None
    syn_to_synack_delay: Optional[float] = None
    synack_to_ack_delay: Optional[float] = None
    total_handshake_time: Optional[float] = None
    complete: bool = False
    suspected_side: str = "unknown"


class TCPHandshakeAnalyzer:
    """Analyseur des handshakes TCP"""

    def __init__(self, syn_synack_threshold: float = 0.1, total_threshold: float = 0.3,
                 latency_filter: Optional[float] = None):
        """
        Initialise l'analyseur de handshake TCP

        Args:
            syn_synack_threshold: Seuil d'alerte SYN→SYN/ACK en secondes
            total_threshold: Seuil d'alerte pour le handshake complet en secondes
            latency_filter: Si défini, ne garde que les handshakes avec latence >= ce seuil
        """
        self.syn_synack_threshold = syn_synack_threshold
        self.total_threshold = total_threshold
        self.latency_filter = latency_filter
        self.handshakes: List[HandshakeFlow] = []
        self.incomplete_handshakes: Dict[str, HandshakeFlow] = {}

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

        # Détection SYN (sans ACK)
        if tcp.flags & 0x02 and not tcp.flags & 0x10:  # SYN flag set, ACK flag not set
            flow_key = self._get_flow_key(packet, 'client')

            if flow_key not in self.incomplete_handshakes:
                handshake = HandshakeFlow(
                    src_ip=packet['IP'].src,
                    dst_ip=packet['IP'].dst,
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

                if handshake.syn_time:
                    handshake.syn_to_synack_delay = packet_time - handshake.syn_time

        # Détection ACK final (après SYN/ACK)
        elif tcp.flags & 0x10 and not tcp.flags & 0x02:  # ACK flag set, SYN not set
            flow_key = self._get_flow_key(packet, 'client')

            if flow_key in self.incomplete_handshakes:
                handshake = self.incomplete_handshakes[flow_key]
                
                # On ne traite que si on a vu le SYN/ACK
                if handshake.synack_time:
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
        if not packet.haslayer('IP') or not packet.haslayer(TCP):
            return ""

        ip = packet['IP']
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
        Identifie le côté suspect (client, réseau, serveur)

        Args:
            handshake: Flux de handshake

        Returns:
            Côté suspect ('client', 'network', 'server', 'unknown')
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
