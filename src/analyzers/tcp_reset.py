"""
Analyseur des Reset TCP (RST)
Détecte et analyse les connexions TCP fermées brutalement
"""

from collections import defaultdict
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Union

from scapy.all import IP, TCP

if TYPE_CHECKING:
    from scapy.packet import Packet

# Import PacketMetadata for hybrid mode support (3-5x faster)
try:
    from ..parsers.fast_parser import PacketMetadata
except ImportError:
    PacketMetadata = None


class TCPResetAnalyzer:
    """Analyse les paquets TCP RST pour identifier les problèmes"""

    def __init__(self):
        self.reset_packets = []
        self.flows = defaultdict(lambda: {"syn_seen": False, "data_exchanged": False, "packets": [], "rst_count": 0})

    def process_packet(self, packet: Union["Packet", "PacketMetadata"], packet_num: int):
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

        tcp = packet[TCP]
        ip = packet[IP]

        src_ip = ip.src
        dst_ip = ip.dst
        src_port = tcp.sport
        dst_port = tcp.dport

        # Clé de flux bidirectionnelle (normalisée)
        flow_key = self._get_flow_key(src_ip, src_port, dst_ip, dst_port)

        # Suivre l'état du flux
        if tcp.flags & 0x02:  # SYN
            self.flows[flow_key]["syn_seen"] = True

        # Détecter échange de données (PSH ou payload)
        if (tcp.flags & 0x08) or (len(tcp.payload) > 0):
            self.flows[flow_key]["data_exchanged"] = True

        # Détecter RST
        if tcp.flags & 0x04:  # RST
            self.flows[flow_key]["rst_count"] += 1

            rst_info = {
                "packet_num": packet_num,
                "timestamp": float(packet.time),  # Raw timestamp
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "flow_key": flow_key,
                "syn_seen": self.flows[flow_key]["syn_seen"],
                "data_exchanged": self.flows[flow_key]["data_exchanged"],
                "flags": tcp.flags,
                "seq": tcp.seq,
                "ack": tcp.ack if tcp.flags & 0x10 else None,
            }

            self.reset_packets.append(rst_info)

    def _get_flow_key(self, ip1: str, port1: int, ip2: str, port2: int) -> str:
        """Génère une clé de flux normalisée (bidirectionnelle)"""
        if (ip1, port1) < (ip2, port2):
            return f"{ip1}:{port1} → {ip2}:{port2}"
        else:
            return f"{ip2}:{port2} → {ip1}:{port1}"

    def _process_metadata(self, metadata: "PacketMetadata", packet_num: int) -> None:
        """
        PERFORMANCE OPTIMIZED: Process lightweight PacketMetadata (3-5x faster than Scapy).

        This method replicates RST detection logic but uses direct attribute access
        from dpkt-extracted metadata.

        Args:
            metadata: Lightweight packet metadata from dpkt
            packet_num: Packet sequence number in capture
        """
        # Skip non-TCP packets
        if metadata.protocol != "TCP":
            return

        src_ip = metadata.src_ip
        dst_ip = metadata.dst_ip
        src_port = metadata.src_port
        dst_port = metadata.dst_port
        timestamp = metadata.timestamp

        # Clé de flux bidirectionnelle (normalisée)
        flow_key = self._get_flow_key(src_ip, src_port, dst_ip, dst_port)

        # Suivre l'état du flux
        if metadata.is_syn:  # SYN flag
            self.flows[flow_key]["syn_seen"] = True

        # Détecter échange de données (PSH ou payload)
        if metadata.is_psh or metadata.tcp_payload_len > 0:
            self.flows[flow_key]["data_exchanged"] = True

        # Détecter RST
        if metadata.is_rst:  # RST flag
            self.flows[flow_key]["rst_count"] += 1

            rst_info = {
                "packet_num": packet_num,
                "timestamp": timestamp,
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "flow_key": flow_key,
                "syn_seen": self.flows[flow_key]["syn_seen"],
                "data_exchanged": self.flows[flow_key]["data_exchanged"],
                "flags": metadata.tcp_flags,
                "seq": metadata.tcp_seq,
                "ack": metadata.tcp_ack if metadata.is_ack else None,
            }

            self.reset_packets.append(rst_info)

    def finalize(self) -> dict[str, Any]:
        """Finalize analysis and return results"""
        return self.get_results()

    def _generate_report(self) -> dict[str, Any]:
        """Generate report for hybrid mode compatibility"""
        return self.get_results()

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse des RST TCP"""
        results = self.get_results()

        total = results["total_resets"]
        premature = results["premature_resets"]
        post_data = results["post_data_resets"]
        flows = results["flows_with_resets"]

        summary = f"📊 Analyse des Reset TCP (RST):\n"
        summary += f"  - Reset totaux: {total}\n"

        if total == 0:
            summary += "\n✓ Aucun paquet RST détecté."
            return summary

        summary += f"  - Reset prématurés: {premature}\n"
        summary += f"  - Reset post-données: {post_data}\n"
        summary += f"  - Flux affectés: {flows}\n"

        if premature > total * 0.5:
            summary += "\n⚠️  ATTENTION: Nombre élevé de RST prématurés (avant échange de données)."
        elif total > 10:
            summary += f"\n⚠️  {total} paquets RST détectés - vérifier les connexions."
        else:
            summary += "\n✓ Nombre de RST dans les limites normales."

        return summary

    def get_results(self) -> dict[str, Any]:
        """Retourne les résultats de l'analyse"""
        if not self.reset_packets:
            return {
                "total_resets": 0,
                "premature_resets": 0,
                "post_data_resets": 0,
                "flows_with_resets": 0,
                "reset_details": [],
                "top_reset_flows": [],
            }

        # Classifier les RST
        premature_resets = []  # RST avant échange de données
        post_data_resets = []  # RST après échange de données

        for rst in self.reset_packets:
            if not rst["data_exchanged"]:
                premature_resets.append(rst)
            else:
                post_data_resets.append(rst)

        # Compter les flux avec RST
        flows_with_rst = len([f for f in self.flows.values() if f["rst_count"] > 0])

        # Collecter les timestamps RST par flux et les convertir en ISO
        flow_timestamps = defaultdict(list)
        for rst in self.reset_packets:
            flow_timestamps[rst["flow_key"]].append(datetime.fromtimestamp(rst["timestamp"]).isoformat())

        # Top flux avec le plus de RST
        flow_rst_counts = []
        for flow_key, flow_data in self.flows.items():
            if flow_data["rst_count"] > 0:
                flow_rst_counts.append(
                    {
                        "flow_key": flow_key,
                        "count": flow_data["rst_count"],
                        "premature": not flow_data["data_exchanged"],
                        "timestamps": sorted(flow_timestamps[flow_key]),  # Already ISO
                    }
                )

        flow_rst_counts.sort(key=lambda x: x["count"], reverse=True)

        # Détails pour le rapport (Top 20)
        reset_details = []
        for rst in sorted(self.reset_packets, key=lambda x: x["timestamp"])[:20]:
            reset_details.append(
                {
                    "packet_num": rst["packet_num"],
                    "timestamp": datetime.fromtimestamp(rst["timestamp"]).isoformat(),  # Convert to ISO
                    "flow": rst["flow_key"],
                    "type": "Prématuré" if not rst["data_exchanged"] else "Post-données",
                    "syn_seen": rst["syn_seen"],
                }
            )

        return {
            "total_resets": len(self.reset_packets),
            "premature_resets": len(premature_resets),
            "post_data_resets": len(post_data_resets),
            "flows_with_resets": flows_with_rst,
            "reset_details": reset_details,
            "top_reset_flows": flow_rst_counts[:10],
        }
