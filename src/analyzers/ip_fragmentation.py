"""
Analyseur de fragmentation IP
Détecte et analyse la fragmentation IP pour diagnostiquer les problèmes PMTU
"""

import time
from collections import defaultdict
from typing import Any, Dict, List

from scapy.all import IP


class IPFragmentationAnalyzer:
    """Analyse la fragmentation IP pour détecter les problèmes PMTU"""

    def __init__(self):
        # Statistiques globales
        self.total_fragments = 0
        self.total_packets_with_df = 0  # Don't Fragment
        self.total_fragmented_packets = 0

        # Suivi des fragments par ID
        # Key: (src_ip, dst_ip, ip_id)
        self.fragments = defaultdict(
            lambda: {
                "fragments": [],  # Liste des offsets reçus
                "last_seen": 0,
                "total_length": None,  # Longueur totale attendue
                "complete": False,
                "src_ip": None,
                "dst_ip": None,
                "protocol": None,
            }
        )

        # Flux avec fragmentation
        # Key: "src_ip:dst_ip"
        self.fragmented_flows = defaultdict(
            lambda: {
                "fragment_count": 0,
                "packets_count": 0,
                "min_fragment_size": float("inf"),
                "max_fragment_size": 0,
                "avg_fragment_size": 0,
                "incomplete_reassemblies": 0,
            }
        )

        # Fragments perdus/incomplets
        self.incomplete_fragments = []
        self.timeout_seconds = 30  # Timeout pour considérer un fragment perdu

    def process_packet(self, packet, packet_num: int):
        """Analyse un paquet pour détecter la fragmentation IP"""
        if not packet.haslayer(IP):
            return

        ip = packet[IP]

        # Incrémenter le compteur de flux
        flow_key = f"{ip.src}:{ip.dst}"
        self.fragmented_flows[flow_key]["packets_count"] += 1

        # Vérifier le flag Don't Fragment
        if ip.flags & 0x02:  # DF flag
            self.total_packets_with_df += 1

        # Détecter fragmentation
        # MF (More Fragments) = 0x01, ou offset > 0
        is_fragment = (ip.flags & 0x01) or (ip.frag > 0)

        if is_fragment:
            self.total_fragments += 1
            self.fragmented_flows[flow_key]["fragment_count"] += 1

            # Clé unique pour ce groupe de fragments
            frag_key = (ip.src, ip.dst, ip.id)

            # Enregistrer les informations du fragment
            frag_info = self.fragments[frag_key]
            frag_info["src_ip"] = ip.src
            frag_info["dst_ip"] = ip.dst
            frag_info["protocol"] = ip.proto
            frag_info["last_seen"] = float(packet.time)

            # Offset en bytes (frag est en unités de 8 octets)
            offset = ip.frag * 8
            fragment_size = len(ip.payload)

            # Enregistrer ce fragment
            frag_info["fragments"].append(
                {
                    "offset": offset,
                    "size": fragment_size,
                    "packet_num": packet_num,
                    "timestamp": float(packet.time),
                    "more_fragments": bool(ip.flags & 0x01),
                }
            )

            # Mettre à jour les stats de taille
            flow_stats = self.fragmented_flows[flow_key]
            flow_stats["min_fragment_size"] = min(flow_stats["min_fragment_size"], fragment_size)
            flow_stats["max_fragment_size"] = max(flow_stats["max_fragment_size"], fragment_size)

            # Si c'est le dernier fragment (MF=0), calculer la taille totale
            if not (ip.flags & 0x01):
                frag_info["total_length"] = offset + fragment_size

            # Vérifier si le réassemblage est complet
            self._check_reassembly(frag_key)

            # Cleanup completed fragment groups to prevent memory leaks
            if frag_info["complete"]:
                # Mark for deletion after processing (can't delete during iteration)
                pass

    def _check_reassembly(self, frag_key):
        """Vérifie si tous les fragments ont été reçus"""
        frag_info = self.fragments[frag_key]

        # On ne peut vérifier que si on connaît la longueur totale
        if frag_info["total_length"] is None:
            return

        # Trier les fragments par offset
        sorted_frags = sorted(frag_info["fragments"], key=lambda x: x["offset"])

        # Vérifier la continuité
        expected_offset = 0
        complete = True

        for frag in sorted_frags:
            if frag["offset"] != expected_offset:
                complete = False
                break
            expected_offset = frag["offset"] + frag["size"]

        # Vérifier qu'on atteint bien la fin
        if complete and expected_offset == frag_info["total_length"]:
            frag_info["complete"] = True
        else:
            frag_info["complete"] = False

    def finalize(self):
        """Finalise l'analyse - détecte les fragments perdus"""
        current_time = time.time()

        # Track completed fragments for cleanup
        completed_fragments = []

        for frag_key, frag_info in self.fragments.items():
            # Mark completed reassemblies for cleanup
            if frag_info["complete"]:
                completed_fragments.append(frag_key)
                continue

            # Si le fragment n'est pas complet après le timeout
            if not frag_info["complete"]:
                age = current_time - frag_info["last_seen"]

                # Marquer comme incomplet
                flow_key = f"{frag_info['src_ip']}:{frag_info['dst_ip']}"
                self.fragmented_flows[flow_key]["incomplete_reassemblies"] += 1

                self.incomplete_fragments.append(
                    {
                        "src_ip": frag_info["src_ip"],
                        "dst_ip": frag_info["dst_ip"],
                        "ip_id": frag_key[2],
                        "fragments_received": len(frag_info["fragments"]),
                        "total_length": frag_info["total_length"],
                        "age": age,
                        "flow_key": flow_key,
                    }
                )

        # Cleanup completed fragment groups to free memory
        for frag_key in completed_fragments:
            del self.fragments[frag_key]

        # Calculer les moyennes
        for flow_key, stats in self.fragmented_flows.items():
            if stats["fragment_count"] > 0:
                if stats["min_fragment_size"] == float("inf"):
                    stats["min_fragment_size"] = 0
                # Moyenne simple (pourrait être pondérée)
                stats["avg_fragment_size"] = (stats["min_fragment_size"] + stats["max_fragment_size"]) / 2

    def get_results(self) -> dict[str, Any]:
        """Retourne les résultats de l'analyse"""
        # Top flows avec fragmentation
        top_flows = []
        for flow_key, stats in self.fragmented_flows.items():
            if stats["fragment_count"] > 0:
                top_flows.append(
                    {
                        "flow_key": flow_key,
                        "fragment_count": stats["fragment_count"],
                        "packets_count": stats["packets_count"],
                        "fragmentation_rate": (
                            (stats["fragment_count"] / stats["packets_count"] * 100)
                            if stats["packets_count"] > 0
                            else 0
                        ),
                        "min_fragment_size": stats["min_fragment_size"],
                        "max_fragment_size": stats["max_fragment_size"],
                        "avg_fragment_size": stats["avg_fragment_size"],
                        "incomplete_reassemblies": stats["incomplete_reassemblies"],
                    }
                )

        top_flows.sort(key=lambda x: x["fragment_count"], reverse=True)

        # Statistiques de réassemblage
        total_fragment_groups = len(self.fragments)
        complete_reassemblies = sum(1 for f in self.fragments.values() if f["complete"])
        incomplete_reassemblies = len(self.incomplete_fragments)

        # PMTU estimé (basé sur la taille max des fragments)
        estimated_pmtu = 1500  # Valeur par défaut
        if top_flows:
            # Prendre le plus petit max_fragment_size comme indication de PMTU
            estimated_pmtu = min(f["max_fragment_size"] for f in top_flows) + 20  # +20 pour l'en-tête IP

        return {
            "total_fragments": self.total_fragments,
            "total_packets_with_df": self.total_packets_with_df,
            "total_fragment_groups": total_fragment_groups,
            "complete_reassemblies": complete_reassemblies,
            "incomplete_reassemblies": incomplete_reassemblies,
            "incomplete_fragments_details": self.incomplete_fragments[:20],  # Top 20
            "top_fragmented_flows": top_flows[:10],  # Top 10
            "estimated_pmtu": estimated_pmtu,
            "has_fragmentation": self.total_fragments > 0,
        }
