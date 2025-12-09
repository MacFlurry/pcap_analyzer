"""
Analyseur de trafic asymétrique.
Détecte les déséquilibres de trafic entre les deux directions d'une communication.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet


@dataclass
class DirectionalStats:
    """Statistiques pour une direction de flux."""

    bytes: int = 0
    packets: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0

    def duration(self) -> float:
        """Calcule la durée du flux en secondes."""
        if self.first_seen == 0 or self.last_seen == 0:
            return 0.0
        return self.last_seen - self.first_seen

    def throughput_bps(self) -> float:
        """Calcule le débit en bits/seconde."""
        duration = self.duration()
        if duration <= 0:
            return 0.0
        return (self.bytes * 8) / duration


@dataclass
class FlowAsymmetry:
    """Représente l'asymétrie d'un flux bidirectionnel."""

    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    forward: DirectionalStats = field(default_factory=DirectionalStats)
    reverse: DirectionalStats = field(default_factory=DirectionalStats)

    def byte_ratio(self) -> float:
        """
        Calcule le ratio d'asymétrie en octets.
        Retourne un nombre entre 0 et 1 où:
        - 0 = trafic complètement asymétrique (une seule direction)
        - 1 = trafic parfaitement symétrique (50%/50%)
        """
        total = self.forward.bytes + self.reverse.bytes
        if total == 0:
            return 1.0
        min_bytes = min(self.forward.bytes, self.reverse.bytes)
        max_bytes = max(self.forward.bytes, self.reverse.bytes)
        if max_bytes == 0:
            return 1.0
        return min_bytes / max_bytes

    def packet_ratio(self) -> float:
        """
        Calcule le ratio d'asymétrie en paquets.
        """
        total = self.forward.packets + self.reverse.packets
        if total == 0:
            return 1.0
        min_packets = min(self.forward.packets, self.reverse.packets)
        max_packets = max(self.forward.packets, self.reverse.packets)
        if max_packets == 0:
            return 1.0
        return min_packets / max_packets

    def dominant_direction(self) -> str:
        """Retourne la direction dominante (forward ou reverse)."""
        if self.forward.bytes >= self.reverse.bytes:
            return "forward"
        return "reverse"

    def asymmetry_percentage(self) -> float:
        """
        Retourne le pourcentage d'asymétrie (0% = symétrique, 100% = une direction).
        """
        return (1 - self.byte_ratio()) * 100

    def is_unidirectional(self) -> bool:
        """Retourne True si le flux est presque unidirectionnel (>95% dans une direction)."""
        return self.byte_ratio() < 0.05

    def total_bytes(self) -> int:
        """Retourne le total d'octets dans les deux directions."""
        return self.forward.bytes + self.reverse.bytes

    def total_packets(self) -> int:
        """Retourne le total de paquets dans les deux directions."""
        return self.forward.packets + self.reverse.packets


class AsymmetricTrafficAnalyzer:
    """
    Analyseur de trafic asymétrique.

    Identifie les flux avec un déséquilibre significatif entre les directions,
    ce qui peut indiquer:
    - Téléchargements massifs (download)
    - Uploads massifs (backup, streaming sortant)
    - Connexions unidirectionnelles anormales
    - Problèmes de routage (traffic allant dans une direction mais pas dans l'autre)
    """

    def __init__(
        self, asymmetry_threshold: float = 0.3, min_bytes_threshold: int = 10000, min_packets_threshold: int = 10
    ):
        """
        Initialise l'analyseur.

        Args:
            asymmetry_threshold: Ratio en dessous duquel un flux est considéré asymétrique
                                (0.3 = une direction a moins de 30% de l'autre)
            min_bytes_threshold: Nombre minimum d'octets pour considérer un flux
            min_packets_threshold: Nombre minimum de paquets pour considérer un flux
        """
        self.asymmetry_threshold = asymmetry_threshold
        self.min_bytes_threshold = min_bytes_threshold
        self.min_packets_threshold = min_packets_threshold

        # Stockage des flux: clé normalisée -> FlowAsymmetry
        self.flows: Dict[str, FlowAsymmetry] = {}

        # Stats globales
        self.total_packets = 0
        self.total_bytes = 0

    def _normalize_flow_key(
        self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str
    ) -> Tuple[str, bool]:
        """
        Génère une clé normalisée pour un flux bidirectionnel.

        Returns:
            Tuple (clé, is_forward) où is_forward indique si c'est la direction forward
        """
        # On normalise en ordonnant par IP puis par port
        if (src_ip, src_port) <= (dst_ip, dst_port):
            key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}/{protocol}"
            return key, True  # Direction forward
        else:
            key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}/{protocol}"
            return key, False  # Direction reverse

    def process_packet(self, packet: Packet, packet_num: int = 0) -> None:
        """
        Traite un paquet et met à jour les statistiques d'asymétrie.
        """
        if not packet.haslayer(IP):
            return

        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        packet_len = len(packet)
        timestamp = float(packet.time)

        # Déterminer le protocole et les ports
        src_port = 0
        dst_port = 0
        protocol = "IP"

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            protocol = "TCP"
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            protocol = "UDP"

        # Stats globales
        self.total_packets += 1
        self.total_bytes += packet_len

        # Obtenir la clé normalisée et la direction
        flow_key, is_forward = self._normalize_flow_key(src_ip, dst_ip, src_port, dst_port, protocol)

        # Créer le flux si nécessaire
        if flow_key not in self.flows:
            if is_forward:
                self.flows[flow_key] = FlowAsymmetry(
                    flow_key=flow_key,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=protocol,
                )
            else:
                self.flows[flow_key] = FlowAsymmetry(
                    flow_key=flow_key,
                    src_ip=dst_ip,
                    dst_ip=src_ip,
                    src_port=dst_port,
                    dst_port=src_port,
                    protocol=protocol,
                )

        flow = self.flows[flow_key]

        # Mettre à jour les stats de la direction appropriée
        if is_forward:
            stats = flow.forward
        else:
            stats = flow.reverse

        stats.bytes += packet_len
        stats.packets += 1
        if stats.first_seen == 0:
            stats.first_seen = timestamp
        stats.last_seen = timestamp

    def finalize(self) -> None:
        """Finalise l'analyse (pas d'action nécessaire ici)."""
        pass

    def get_asymmetric_flows(self) -> List[FlowAsymmetry]:
        """
        Retourne les flux asymétriques triés par degré d'asymétrie.
        """
        asymmetric = []

        for flow in self.flows.values():
            # Filtrer les flux trop petits
            if flow.total_bytes() < self.min_bytes_threshold:
                continue
            if flow.total_packets() < self.min_packets_threshold:
                continue

            # Vérifier le seuil d'asymétrie
            if flow.byte_ratio() < self.asymmetry_threshold:
                asymmetric.append(flow)

        # Trier par asymétrie décroissante (ratio le plus bas = plus asymétrique)
        asymmetric.sort(key=lambda f: f.byte_ratio())

        return asymmetric

    def get_unidirectional_flows(self) -> List[FlowAsymmetry]:
        """
        Retourne les flux quasi-unidirectionnels (>95% dans une direction).
        """
        return [f for f in self.get_asymmetric_flows() if f.is_unidirectional()]

    def get_top_download_flows(self, top_n: int = 10) -> List[FlowAsymmetry]:
        """
        Retourne les flux avec le plus de données entrantes (download).
        Pour cette analyse, on considère "download" comme la direction avec le plus d'octets.
        """
        flows = list(self.flows.values())
        flows.sort(key=lambda f: f.total_bytes(), reverse=True)

        # Retourner les N plus gros flux
        result = []
        for flow in flows[:top_n]:
            if flow.total_bytes() >= self.min_bytes_threshold:
                result.append(flow)

        return result

    def get_results(self) -> Dict[str, Any]:
        """
        Retourne les résultats complets de l'analyse.
        """
        asymmetric_flows = self.get_asymmetric_flows()
        unidirectional_flows = self.get_unidirectional_flows()
        top_flows = self.get_top_download_flows(20)

        # Statistiques globales
        total_flows = len(self.flows)
        asymmetric_count = len(asymmetric_flows)
        unidirectional_count = len(unidirectional_flows)

        # Calculer les seuils de symétrie
        symmetric_flows = [
            f for f in self.flows.values() if f.byte_ratio() >= 0.8 and f.total_bytes() >= self.min_bytes_threshold
        ]

        # Distribution par protocole
        protocol_stats = defaultdict(lambda: {"flows": 0, "bytes": 0, "asymmetric": 0})
        for flow in self.flows.values():
            proto = flow.protocol
            protocol_stats[proto]["flows"] += 1
            protocol_stats[proto]["bytes"] += flow.total_bytes()
            if flow.byte_ratio() < self.asymmetry_threshold:
                protocol_stats[proto]["asymmetric"] += 1

        return {
            "summary": {
                "total_flows": total_flows,
                "total_packets": self.total_packets,
                "total_bytes": self.total_bytes,
                "asymmetric_flows": asymmetric_count,
                "unidirectional_flows": unidirectional_count,
                "symmetric_flows": len(symmetric_flows),
                "asymmetry_threshold": self.asymmetry_threshold,
                "asymmetric_percentage": (asymmetric_count / total_flows * 100) if total_flows > 0 else 0,
            },
            "protocol_breakdown": dict(protocol_stats),
            "asymmetric_flows": [
                {
                    "flow_key": f.flow_key,
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "src_port": f.src_port,
                    "dst_port": f.dst_port,
                    "protocol": f.protocol,
                    "forward_bytes": f.forward.bytes,
                    "reverse_bytes": f.reverse.bytes,
                    "forward_packets": f.forward.packets,
                    "reverse_packets": f.reverse.packets,
                    "byte_ratio": round(f.byte_ratio(), 4),
                    "asymmetry_percent": round(f.asymmetry_percentage(), 1),
                    "dominant_direction": f.dominant_direction(),
                    "is_unidirectional": f.is_unidirectional(),
                    "total_bytes": f.total_bytes(),
                    "forward_throughput_bps": round(f.forward.throughput_bps(), 2),
                    "reverse_throughput_bps": round(f.reverse.throughput_bps(), 2),
                }
                for f in asymmetric_flows[:50]  # Limiter à 50 pour le rapport
            ],
            "top_flows_by_volume": [
                {
                    "flow_key": f.flow_key,
                    "src_ip": f.src_ip,
                    "dst_ip": f.dst_ip,
                    "protocol": f.protocol,
                    "total_bytes": f.total_bytes(),
                    "forward_bytes": f.forward.bytes,
                    "reverse_bytes": f.reverse.bytes,
                    "byte_ratio": round(f.byte_ratio(), 4),
                    "asymmetry_percent": round(f.asymmetry_percentage(), 1),
                }
                for f in top_flows
            ],
        }

    def get_summary(self) -> str:
        """
        Retourne un résumé textuel de l'analyse.
        """
        results = self.get_results()
        summary = results["summary"]

        lines = [
            "=== Analyse du Trafic Asymétrique ===",
            f"Total des flux analysés: {summary['total_flows']}",
            f"Flux asymétriques (ratio < {summary['asymmetry_threshold']}): {summary['asymmetric_flows']} ({summary['asymmetric_percentage']:.1f}%)",
            f"Flux quasi-unidirectionnels: {summary['unidirectional_flows']}",
            f"Flux symétriques (ratio >= 0.8): {summary['symmetric_flows']}",
            "",
            "--- Répartition par protocole ---",
        ]

        for proto, stats in results["protocol_breakdown"].items():
            lines.append(f"  {proto}: {stats['flows']} flux, {stats['asymmetric']} asymétriques")

        if results["asymmetric_flows"]:
            lines.append("")
            lines.append("--- Top 5 flux les plus asymétriques ---")
            for f in results["asymmetric_flows"][:5]:
                direction = "→" if f["dominant_direction"] == "forward" else "←"
                lines.append(
                    f"  {f['src_ip']}:{f['src_port']} {direction} {f['dst_ip']}:{f['dst_port']} "
                    f"({f['protocol']}): {f['asymmetry_percent']:.1f}% asymétrique, "
                    f"{f['forward_bytes']}B/{f['reverse_bytes']}B"
                )

        return "\n".join(lines)
