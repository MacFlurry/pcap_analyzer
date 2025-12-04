"""
Analyseur de retransmissions et anomalies TCP
"""

from scapy.all import Packet, TCP, IP
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class TCPRetransmission:
    """Représente une retransmission TCP"""
    packet_num: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq_num: int
    original_packet_num: int
    delay: float


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
    severity: str  # 'low', 'medium', 'critical'


class RetransmissionAnalyzer:
    """Analyseur de retransmissions et anomalies TCP"""

    def __init__(self, retrans_low: int = 5, retrans_medium: int = 15,
                 retrans_critical: int = 30):
        """
        Initialise l'analyseur de retransmissions

        Args:
            retrans_low: Seuil bas de retransmissions par flux
            retrans_medium: Seuil moyen de retransmissions par flux
            retrans_critical: Seuil critique de retransmissions par flux
        """
        self.retrans_low = retrans_low
        self.retrans_medium = retrans_medium
        self.retrans_critical = retrans_critical

        self.retransmissions: List[TCPRetransmission] = []
        self.anomalies: List[TCPAnomaly] = []
        self.flow_stats: Dict[str, FlowStats] = {}

        # Tracking interne
        # Changement: on stocke maintenant une liste de (packet_num, timestamp) pour chaque (seq, len)
        # pour détecter les retransmissions multiples du même segment
        self._seen_segments: Dict[str, Dict[Tuple[int, int], List[Tuple[int, float]]]] = defaultdict(lambda: defaultdict(list))
        self._flow_counters: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._expected_ack: Dict[str, int] = {}
        self._expected_seq: Dict[str, int] = {}
        self._dup_ack_count: Dict[str, int] = defaultdict(int)  # Compteur de DUP ACK par flux
        self._last_ack: Dict[str, int] = {}  # Dernier ACK vu par flux
        # Tracking du plus haut seq vu par flux (méthode Wireshark)
        self._highest_seq: Dict[str, Tuple[int, int, float]] = {}  # flow_key -> (highest_seq, packet_num, timestamp)
        # Tracking du plus haut ACK vu par flux (pour Spurious Retransmission)
        self._max_ack_seen: Dict[str, int] = defaultdict(int)

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyse les retransmissions et anomalies TCP

        Args:
            packets: Liste des paquets Scapy

        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        for i, packet in enumerate(packets):
            if not packet.haslayer(TCP) or not packet.haslayer(IP):
                continue

            self._analyze_packet(i, packet)

        self._calculate_flow_severity()

        return self._generate_report()

    def _analyze_packet(self, packet_num: int, packet: Packet) -> None:
        """Analyse un paquet TCP individuel"""
        tcp = packet[TCP]
        ip = packet[IP]
        timestamp = float(packet.time)

        flow_key = self._get_flow_key(packet)
        self._flow_counters[flow_key]['total'] += 1

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
        # Pour SYN/FIN, la longueur logique est 1
        logical_len = payload_len
        if tcp.flags & 0x03: # SYN or FIN
             if payload_len == 0:
                 logical_len = 1
        
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
            
            # 1. Vérifier si c'est une retransmission basée sur le numéro de séquence (Wireshark)
            # Si le numéro de séquence + len est <= au plus haut vu, c'est une retransmission
            if flow_key in self._highest_seq:
                highest_seq, highest_pkt, highest_time = self._highest_seq[flow_key]
                
                # Vérification KeepAlive: len=0/1, seq = highest_seq - 1
                is_keepalive = (payload_len <= 1) and (seq == highest_seq - 1)
                
                if not is_keepalive and seq < highest_seq:
                    is_retransmission = True
                    # ... (logique existante pour original_num)

            # 2. Vérifier si c'est une Spurious Retransmission (déjà ACKé par l'autre côté)
            reverse_key = self._get_reverse_flow_key(packet)
            if not is_retransmission and reverse_key in self._max_ack_seen:
                max_ack = self._max_ack_seen[reverse_key]
                # Si le segment entier est avant le max ACK, c'est une retransmission inutile
                if seq + payload_len <= max_ack:
                    is_retransmission = True
                    # On ne connait pas forcément l'original, mais on sait que c'est une retransmission
                    if original_num is None:
                        pass

            # 3. Vérifier Fast Retransmission
            # Si on a reçu > 2 DUP ACKs demandant ce SEQ
            if not is_retransmission and self._dup_ack_count[reverse_key] > 2:
                 expected_seq = self._last_ack[reverse_key]
                 if seq == expected_seq:
                     is_retransmission = True
                     # C'est une Fast Retransmission

            if is_retransmission:
                # Essayer de trouver le paquet original exact si pas encore trouvé
                if original_num is None:
                    if segment_key in self._seen_segments[flow_key] and len(self._seen_segments[flow_key][segment_key]) > 0:
                        original_num, original_time = self._seen_segments[flow_key][segment_key][0]
                    elif flow_key in self._highest_seq:
                         # Fallback sur highest_seq info
                         _, highest_pkt, highest_time = self._highest_seq[flow_key]
                         original_num = highest_pkt
                         original_time = highest_time
                    else:
                        # Dernier recours
                        original_num = packet_num
                        original_time = timestamp

                delay = timestamp - original_time

                retrans = TCPRetransmission(
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    seq_num=seq,
                    original_packet_num=original_num,
                    delay=delay
                )
                self.retransmissions.append(retrans)
                self._flow_counters[flow_key]['retransmissions'] += 1
            
            # On enregistre TOUTES les occurrences (original + retransmissions)
            self._seen_segments[flow_key][segment_key].append((packet_num, timestamp))
            
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
                    anomaly_type='dup_ack',
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    details=f"Duplicate ACK #{self._dup_ack_count[reverse_flow]} for seq {ack}"
                )
                self.anomalies.append(anomaly)
                self._flow_counters[flow_key]['dup_acks'] += 1
                
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
        if len(tcp.payload) > 0:
            seq = tcp.seq
            expected = self._expected_seq.get(flow_key, seq)

            if seq < expected:
                # Paquet reçu avec un numéro de séquence inférieur à celui attendu
                anomaly = TCPAnomaly(
                    anomaly_type='out_of_order',
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    details=f"Expected seq {expected}, got {seq}"
                )
                self.anomalies.append(anomaly)
                self._flow_counters[flow_key]['out_of_order'] += 1
            else:
                self._expected_seq[flow_key] = seq + len(tcp.payload)

        # Détection Zero Window
        if tcp.window == 0:
            anomaly = TCPAnomaly(
                anomaly_type='zero_window',
                packet_num=packet_num,
                timestamp=timestamp,
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                details="TCP window size is 0"
            )
            self.anomalies.append(anomaly)
            self._flow_counters[flow_key]['zero_windows'] += 1

    def _get_flow_key(self, packet: Packet) -> str:
        """Génère une clé de flux unidirectionnelle"""
        ip = packet[IP]
        tcp = packet[TCP]
        return f"{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}"

    def _get_reverse_flow_key(self, packet: Packet) -> str:
        """Génère la clé de flux inverse"""
        ip = packet[IP]
        tcp = packet[TCP]
        return f"{ip.dst}:{tcp.dport}->{ip.src}:{tcp.sport}"

    def _calculate_flow_severity(self) -> None:
        """Calcule la sévérité pour chaque flux"""
        for flow_key, counters in self._flow_counters.items():
            parts = flow_key.split('->')
            src_part, dst_part = parts[0].split(':'), parts[1].split(':')

            retrans_count = counters['retransmissions']

            if retrans_count >= self.retrans_critical:
                severity = 'critical'
            elif retrans_count >= self.retrans_medium:
                severity = 'medium'
            elif retrans_count >= self.retrans_low:
                severity = 'low'
            else:
                severity = 'none'

            stats = FlowStats(
                flow_key=flow_key,
                src_ip=src_part[0],
                dst_ip=dst_part[0],
                src_port=int(src_part[1]),
                dst_port=int(dst_part[1]),
                total_packets=counters['total'],
                retransmissions=counters['retransmissions'],
                dup_acks=counters['dup_acks'],
                out_of_order=counters['out_of_order'],
                zero_windows=counters['zero_windows'],
                severity=severity
            )

            self.flow_stats[flow_key] = stats

    def _count_unique_retransmitted_segments(self) -> int:
        """
        Compte le nombre de segments uniques qui ont été retransmis.
        Un segment retransmis 2 fois compte pour 1 segment unique.
        """
        unique_segments = set()
        for retrans in self.retransmissions:
            # Clé unique: (src, dst, sport, dport, seq)
            key = (retrans.src_ip, retrans.dst_ip, retrans.src_port, 
                   retrans.dst_port, retrans.seq_num)
            unique_segments.add(key)
        return len(unique_segments)

    def _generate_report(self) -> Dict[str, Any]:
        """Génère le rapport d'analyse"""
        total_retrans = len(self.retransmissions)
        flows_with_issues = [f for f in self.flow_stats.values() if f.severity != 'none']

        # Compte les anomalies par type
        anomaly_counts = defaultdict(int)
        for anomaly in self.anomalies:
            anomaly_counts[anomaly.anomaly_type] += 1

        # Statistiques de sévérité
        severity_counts = defaultdict(int)
        for flow in self.flow_stats.values():
            severity_counts[flow.severity] += 1

        return {
            'total_flows': len(self.flow_stats),
            'flows_with_issues': len(flows_with_issues),
            'total_retransmissions': total_retrans,
            'total_anomalies': len(self.anomalies),
            'anomaly_types': dict(anomaly_counts),
            'severity_distribution': dict(severity_counts),
            'thresholds': {
                'low': self.retrans_low,
                'medium': self.retrans_medium,
                'critical': self.retrans_critical
            },
            'retransmissions': [asdict(r) for r in self.retransmissions],
            'anomalies': [asdict(a) for a in self.anomalies],
            'flow_statistics': [asdict(f) for f in self.flow_stats.values()]
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse"""
        total_retrans = len(self.retransmissions)
        unique_segments = self._count_unique_retransmitted_segments()
        flows_with_issues = [f for f in self.flow_stats.values() if f.severity != 'none']

        summary = f"📊 Analyse des retransmissions et anomalies TCP:\n"
        summary += f"  - Flux analysés: {len(self.flow_stats)}\n"
        summary += f"  - Retransmissions totales: {total_retrans}\n"
        summary += f"    ({unique_segments} segment(s) unique(s) retransmis)\n"
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
            retrans_list = [r for r in retrans_list 
                          if f"{r.src_ip}:{r.src_port}->{r.dst_ip}:{r.dst_port}" == flow_filter]
        
        if not retrans_list:
            return f"✅ Aucune retransmission trouvée pour le flux: {flow_filter}"
        
        total = len(retrans_list)
        displayed = min(limit, total)
        
        details = f"🔍 Détails des retransmissions ({displayed}/{total}):\n\n"
        
        for i, retrans in enumerate(retrans_list[:limit], 1):
            delay_ms = retrans.delay * 1000  # Convertir en ms
            details += f"  #{i}: Paquet {retrans.packet_num} (retrans de #{retrans.original_packet_num})\n"
            details += f"      Seq: {retrans.seq_num}, Délai: {delay_ms:.1f}ms\n"
            details += f"      {retrans.src_ip}:{retrans.src_port} → {retrans.dst_ip}:{retrans.dst_port}\n"
            if i < displayed:
                details += "\n"
        
        if total > limit:
            details += f"\n  ... et {total - limit} autres retransmissions (utilisez --details-limit pour en voir plus)\n"
        
        return details
