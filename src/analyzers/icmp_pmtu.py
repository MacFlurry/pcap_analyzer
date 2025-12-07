"""
Analyseur ICMP et détection de problèmes PMTU
"""

from scapy.all import Packet, ICMP, IP, TCP, IPv6, ICMPv6DestUnreach
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict


@dataclass
class ICMPMessage:
    """Message ICMP détecté"""
    packet_num: int
    timestamp: float
    icmp_type: int
    icmp_code: int
    icmp_type_name: str
    src_ip: str
    dst_ip: str
    original_src: str = ""  # IP source du paquet original qui a déclenché l'ICMP
    original_dst: str = ""  # IP dest du paquet original
    mtu: int = 0  # MTU suggéré (pour "Fragmentation Needed")
    message: str = ""
    severity: str = "info"  # 'info', 'warning', 'error'


class ICMPAnalyzer:
    """Analyseur ICMP et PMTU"""

    # Types ICMP courants
    ICMP_TYPES = {
        0: "Echo Reply",
        3: "Destination Unreachable",
        4: "Source Quench",
        5: "Redirect",
        8: "Echo Request",
        11: "Time Exceeded",
        12: "Parameter Problem",
    }

    # Codes pour Destination Unreachable (Type 3)
    DEST_UNREACH_CODES = {
        0: "Network Unreachable",
        1: "Host Unreachable",
        2: "Protocol Unreachable",
        3: "Port Unreachable",
        4: "Fragmentation Needed and DF Set",  # PMTU Discovery
        5: "Source Route Failed",
        6: "Network Unknown",
        7: "Host Unknown",
        13: "Communication Administratively Prohibited",
    }

    def __init__(self):
        """Initialise l'analyseur ICMP"""
        self.icmp_messages: List[ICMPMessage] = []
        self.pmtu_issues: List[ICMPMessage] = []
        self.dest_unreachable: List[ICMPMessage] = []

    def analyze(self, packets: List[Packet]) -> Dict[str, Any]:
        """
        Analyse les messages ICMP

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
        # ICMP IPv4
        if packet.haslayer(ICMP):
            self._analyze_icmp_packet(packet_num, packet)

        # ICMPv6
        elif packet.haslayer(ICMPv6DestUnreach):
            self._analyze_icmpv6_packet(packet_num, packet)

    def finalize(self) -> Dict[str, Any]:
        """Finalise l'analyse et génère le rapport"""
        return self._generate_report()

    def _analyze_icmp_packet(self, packet_num: int, packet: Packet) -> None:
        """Analyse un paquet ICMP IPv4"""
        icmp = packet[ICMP]
        ip = packet[IP]
        timestamp = float(packet.time)

        icmp_type = icmp.type
        icmp_code = icmp.code

        icmp_type_name = self.ICMP_TYPES.get(icmp_type, f"Type {icmp_type}")

        # Informations sur le paquet original (si présent dans le payload ICMP)
        original_src = ""
        original_dst = ""
        mtu = 0

        # Pour Destination Unreachable, le payload contient le paquet original
        if icmp_type == 3 and hasattr(icmp, 'payload') and icmp.payload:
            try:
                # Le payload ICMP contient l'en-tête IP + 8 octets du paquet original
                if hasattr(icmp.payload, 'src'):
                    original_src = icmp.payload.src
                if hasattr(icmp.payload, 'dst'):
                    original_dst = icmp.payload.dst
            except (AttributeError, ValueError, TypeError):
                # Malformed ICMP payload - unable to extract original packet info
                # This can happen with truncated or corrupted packets
                pass

            # MTU pour "Fragmentation Needed" (code 4)
            if icmp_code == 4:
                if hasattr(icmp, 'nexthopmtu'):
                    mtu = icmp.nexthopmtu
                elif hasattr(icmp, 'unused') and icmp.unused:
                    # Ancienne méthode : MTU dans le champ unused
                    mtu = icmp.unused

        # Détermine le message et la sévérité
        message, severity = self._classify_icmp_message(icmp_type, icmp_code, mtu)

        # Ajoute un détail pour les codes de Destination Unreachable
        if icmp_type == 3:
            code_name = self.DEST_UNREACH_CODES.get(icmp_code, f"Code {icmp_code}")
            icmp_type_name = f"{icmp_type_name} - {code_name}"

        icmp_msg = ICMPMessage(
            packet_num=packet_num,
            timestamp=timestamp,
            icmp_type=icmp_type,
            icmp_code=icmp_code,
            icmp_type_name=icmp_type_name,
            src_ip=ip.src,
            dst_ip=ip.dst,
            original_src=original_src,
            original_dst=original_dst,
            mtu=mtu,
            message=message,
            severity=severity
        )

        self.icmp_messages.append(icmp_msg)

        # Catégorise les messages importants
        if icmp_type == 3:
            self.dest_unreachable.append(icmp_msg)
            if icmp_code == 4:  # Fragmentation Needed
                self.pmtu_issues.append(icmp_msg)

    def _analyze_icmpv6_packet(self, packet_num: int, packet: Packet) -> None:
        """Analyse un paquet ICMPv6"""
        icmpv6 = packet[ICMPv6DestUnreach]
        ipv6 = packet[IPv6]
        timestamp = float(packet.time)

        icmp_msg = ICMPMessage(
            packet_num=packet_num,
            timestamp=timestamp,
            icmp_type=1,  # ICMPv6 Destination Unreachable
            icmp_code=icmpv6.code,
            icmp_type_name=f"ICMPv6 Destination Unreachable - Code {icmpv6.code}",
            src_ip=ipv6.src,
            dst_ip=ipv6.dst,
            message="ICMPv6 Destination Unreachable",
            severity="warning"
        )

        self.icmp_messages.append(icmp_msg)
        self.dest_unreachable.append(icmp_msg)

    def _classify_icmp_message(self, icmp_type: int, icmp_code: int, mtu: int) -> Tuple[str, str]:
        """
        Classifie un message ICMP et détermine sa sévérité

        Args:
            icmp_type: Type ICMP
            icmp_code: Code ICMP
            mtu: MTU (si applicable)

        Returns:
            Tuple (message descriptif, niveau de sévérité)
        """
        # Fragmentation Needed (PMTU Discovery)
        if icmp_type == 3 and icmp_code == 4:
            if mtu > 0:
                message = (f"⚠️ Fragmentation nécessaire (PMTU). MTU max: {mtu} bytes. "
                          "Le paquet DF (Don't Fragment) est trop grand.")
            else:
                message = "⚠️ Fragmentation nécessaire (PMTU). Paquet trop grand avec DF flag."
            return message, "error"

        # Destination Unreachable
        elif icmp_type == 3:
            code_name = self.DEST_UNREACH_CODES.get(icmp_code, f"Code {icmp_code}")

            if icmp_code in [0, 1, 6, 7]:  # Network/Host unreachable
                return f"❌ Destination injoignable: {code_name}", "error"
            elif icmp_code == 3:  # Port Unreachable
                return f"⚠️ Port injoignable: {code_name}", "warning"
            elif icmp_code == 13:  # Admin prohibited
                return f"🚫 Communication bloquée: {code_name}", "error"
            else:
                return f"⚠️ Destination injoignable: {code_name}", "warning"

        # Time Exceeded
        elif icmp_type == 11:
            if icmp_code == 0:
                return "⏱️ TTL expiré en transit (possible boucle de routage)", "warning"
            else:
                return "⏱️ Temps dépassé", "warning"

        # Echo Request/Reply (ping)
        elif icmp_type in [0, 8]:
            return "Ping (Echo Request/Reply)", "info"

        # Source Quench (deprecated)
        elif icmp_type == 4:
            return "⚠️ Source Quench (congestion)", "warning"

        # Redirect
        elif icmp_type == 5:
            return "↪️ Redirect", "info"

        # Parameter Problem
        elif icmp_type == 12:
            return "⚠️ Problème de paramètre dans l'en-tête IP", "warning"

        # Autre
        else:
            return f"Message ICMP type {icmp_type} code {icmp_code}", "info"

    def _generate_report(self) -> Dict[str, Any]:
        """Génère le rapport d'analyse ICMP"""
        # Compte par type ICMP
        type_counts = defaultdict(int)
        for msg in self.icmp_messages:
            type_counts[msg.icmp_type_name] += 1

        # Compte par sévérité
        severity_counts = defaultdict(int)
        for msg in self.icmp_messages:
            severity_counts[msg.severity] += 1

        # Agrégation des destinations injoignables
        unreach_stats = defaultdict(lambda: {'count': 0, 'reasons': defaultdict(int)})
        for msg in self.dest_unreachable:
            # Utilise original_dst si dispo (la cible réelle), sinon dst_ip (le routeur qui répond, moins utile)
            target_ip = msg.original_dst if msg.original_dst else f"Unknown (from {msg.src_ip})"
            unreach_stats[target_ip]['count'] += 1
            unreach_stats[target_ip]['reasons'][msg.icmp_type_name] += 1

        # Formatage du Top 10
        top_unreachable = []
        for ip, stats in sorted(unreach_stats.items(), key=lambda item: item[1]['count'], reverse=True)[:10]:
            # Trouve la raison la plus fréquente
            main_reason = max(stats['reasons'].items(), key=lambda item: item[1])[0]
            top_unreachable.append({
                'ip': ip,
                'count': stats['count'],
                'reason': main_reason
            })

        # Suggestions pour les problèmes PMTU
        pmtu_suggestions = []
        if self.pmtu_issues:
            pmtu_suggestions = [
                "🔧 Vérifier la configuration MTU sur les interfaces réseau",
                "🔧 Considérer l'activation de Path MTU Discovery",
                "🔧 Ajuster la MSS (Maximum Segment Size) TCP si nécessaire",
                f"🔧 MTU suggéré par les messages ICMP: {max((m.mtu for m in self.pmtu_issues if m.mtu > 0), default=1500)} bytes"
            ]

        return {
            'total_icmp_messages': len(self.icmp_messages),
            'pmtu_issues_count': len(self.pmtu_issues),
            'dest_unreachable_count': len(self.dest_unreachable),
            'top_unreachable_destinations': top_unreachable, # Added this
            'type_distribution': dict(type_counts),
            'severity_distribution': dict(severity_counts),
            'icmp_messages': [asdict(m) for m in self.icmp_messages],
            'pmtu_issues': [asdict(m) for m in self.pmtu_issues],
            'dest_unreachable': [asdict(m) for m in self.dest_unreachable],
            'pmtu_suggestions': pmtu_suggestions
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse ICMP"""
        if not self.icmp_messages:
            return "📊 Aucun message ICMP détecté."

        summary = f"📊 Analyse ICMP:\n"
        summary += f"  - Messages ICMP totaux: {len(self.icmp_messages)}\n"
        summary += f"  - Destination Unreachable: {len(self.dest_unreachable)}\n"

        if self.pmtu_issues:
            summary += f"\n🔴 {len(self.pmtu_issues)} problème(s) PMTU détecté(s):\n"

            for msg in self.pmtu_issues:
                summary += f"\n  Paquet #{msg.packet_num}\n"
                summary += f"    - {msg.message}\n"
                if msg.original_src and msg.original_dst:
                    summary += f"    - Flux affecté: {msg.original_src} → {msg.original_dst}\n"
                summary += f"    - Source ICMP: {msg.src_ip}\n"

            summary += f"\n  💡 Suggestions:\n"
            summary += f"    - Vérifier la configuration MTU sur les interfaces\n"
            summary += f"    - Ajuster la MSS TCP si nécessaire\n"
            if any(m.mtu > 0 for m in self.pmtu_issues):
                max_mtu = max(m.mtu for m in self.pmtu_issues if m.mtu > 0)
                summary += f"    - MTU suggéré: {max_mtu} bytes\n"

        if self.dest_unreachable:
            errors = [m for m in self.dest_unreachable if m.severity == "error"]
            if errors:
                summary += f"\n⚠️ {len(errors)} erreur(s) de destination injoignable:\n"
                for msg in errors[:5]:  # Limite à 5 pour la lisibilité
                    summary += f"    - {msg.icmp_type_name}: {msg.src_ip} → {msg.dst_ip}\n"

        if not self.pmtu_issues and not any(m.severity == "error" for m in self.icmp_messages):
            summary += f"\n✓ Aucun problème ICMP critique détecté.\n"

        return summary
