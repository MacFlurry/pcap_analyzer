from scapy.all import rdpcap
from typing import Optional, Tuple
import logging
import os

logger = logging.getLogger(__name__)

class PCAPValidationError(Exception):
    """Custom exception for PCAP validation failures"""

    def __init__(self, error_type: str, details: dict):
        self.error_type = error_type
        self.details = details
        super().__init__(self._build_message())

    def _build_message(self) -> str:
        """Build user-friendly error message in French"""
        messages = {
            "INVALID_TIMESTAMPS": "Timestamps incohérents détectés",
            "DUPLICATE_PACKETS": "Ratio élevé de paquets dupliqués détecté",
            "INSUFFICIENT_PACKETS": "Nombre de paquets insuffisant pour l'analyse",
            "SELF_LOOPING": "Flux réseau invalides (auto-communication) détectés",
            "INVALID_FORMAT": "Format de fichier invalide"
        }
        return messages.get(self.error_type, "Erreur de validation PCAP")

    def to_dict(self) -> dict:
        """Convert to JSON-serializable dict for API response"""
        return {
            "error_type": self.error_type,
            "title": self._build_message(),
            "description": self.details.get("description", ""),
            "detected_issues": self.details.get("issues", []),
            "suggestions": self.details.get("suggestions", []),
            "wireshark_link": "https://www.wireshark.org/download.html"
        }


def validate_pcap(file_path: str, sample_size: int = 100) -> Tuple[bool, Optional[PCAPValidationError]]:
    """
    Validate PCAP file for latency analysis compatibility.

    Args:
        file_path: Path to PCAP file
        sample_size: Number of packets to sample for validation

    Returns:
        (is_valid, error) where error is None if valid
    """
    try:
        # Load sample packets efficiently
        packets = rdpcap(file_path, count=sample_size)

        # Run validation checks in order of importance
        if error := _check_minimum_packets(packets):
            return False, PCAPValidationError("INSUFFICIENT_PACKETS", error)

        if error := _check_timestamps(packets):
            return False, PCAPValidationError("INVALID_TIMESTAMPS", error)

        if error := _check_duplicates(packets):
            return False, PCAPValidationError("DUPLICATE_PACKETS", error)

        if error := _check_self_loops(packets):
            return False, PCAPValidationError("SELF_LOOPING", error)

        return True, None

    except Exception as e:
        logger.error(f"PCAP validation failed: {e}")
        error_details = {
            "description": "Impossible de lire le fichier PCAP",
            "issues": [f"Erreur technique: {str(e)}"],
            "suggestions": [
                "Vérifiez que le fichier est un PCAP valide (.pcap ou .pcapng)",
                "Essayez de l'ouvrir avec Wireshark pour confirmer sa validité"
            ]
        }
        return False, PCAPValidationError("INVALID_FORMAT", error_details)


def _check_minimum_packets(packets: list) -> Optional[dict]:
    """Check minimum packet count (>= 2 for latency analysis)"""
    if len(packets) < 2:
        return {
            "description": "Nombre de paquets insuffisant pour analyser les latences.",
            "issues": [f"Seulement {len(packets)} paquet(s) détecté(s), minimum requis: 2"],
            "suggestions": [
                "Capturez plus de trafic réseau",
                "Vérifiez que la capture n'a pas été tronquée"
            ]
        }
    return None


def _check_timestamps(packets: list) -> Optional[dict]:
    """Check for timestamp anomalies (jumps > 1 year = 31536000 seconds)"""
    if len(packets) < 2:
        return None

    timestamps = [float(p.time) for p in packets]
    max_jump = 0
    jump_indices = []

    for i in range(len(timestamps) - 1):
        jump = abs(timestamps[i+1] - timestamps[i])
        if jump > max_jump:
            max_jump = jump
        if jump > 31536000:  # 1 year in seconds
            jump_indices.append((i, i+1, jump))

    if jump_indices:
        issues = [
            f"Saut temporel de {max_jump / 86400:.0f} jours entre paquets {jump_indices[0][0]} et {jump_indices[0][1]}"
        ]
        if len(jump_indices) > 1:
            issues.append(f"{len(jump_indices)} sauts temporels anormaux détectés")

        return {
            "description": "Les timestamps de ce fichier ne sont pas cohérents avec une capture réseau réelle.",
            "issues": issues + ["Ce fichier semble être un PCAP synthétique/éducatif"],
            "suggestions": [
                "Ce type de fichier est conçu pour l'apprentissage des protocoles réseau",
                "PCAP Analyzer analyse les captures réelles de production",
                "Utilisez Wireshark pour explorer ce fichier pédagogique"
            ]
        }

    return None


def _check_duplicates(packets: list) -> Optional[dict]:
    """Check for duplicate packet ratio > 50%"""
    if len(packets) < 2:
        return None

    seen = set()
    duplicates = 0

    for p in packets:
        # Create fingerprint: timestamp + raw bytes
        fingerprint = (float(p.time), bytes(p))
        if fingerprint in seen:
            duplicates += 1
        seen.add(fingerprint)

    duplicate_ratio = duplicates / len(packets)

    if duplicate_ratio > 0.5:  # > 50% duplicates
        return {
            "description": "Ratio anormalement élevé de paquets dupliqués détecté.",
            "issues": [
                f"Paquets dupliqués: {duplicates}/{len(packets)} ({duplicate_ratio*100:.1f}%)",
                "Ce fichier peut être corrompu ou synthétique"
            ],
            "suggestions": [
                "Vérifiez l'intégrité du fichier",
                "Recapturez le trafic si possible",
                "Les fichiers PCAP éducatifs contiennent souvent des doublons intentionnels"
            ]
        }

    return None


def _check_self_loops(packets: list) -> Optional[dict]:
    """Check for self-looping flows (source == destination)"""
    self_loops = 0

    for p in packets:
        # Check Ethernet layer (MAC addresses)
        if hasattr(p, 'src') and hasattr(p, 'dst'):
            if p.src == p.dst:
                self_loops += 1
                continue

        # Check IP layer
        if p.haslayer('IP'):
            if p['IP'].src == p['IP'].dst:
                self_loops += 1
        elif p.haslayer('IPv6'):
            if p['IPv6'].src == p['IPv6'].dst:
                self_loops += 1

    if self_loops > len(packets) * 0.1:  # > 10% self-loops
        return {
            "description": "Flux réseau invalides détectés (source = destination).",
            "issues": [
                f"{self_loops}/{len(packets)} paquets avec source = destination",
                "Ce comportement n'existe pas dans un réseau réel"
            ],
            "suggestions": [
                "Ce fichier semble être un PCAP synthétique/test",
                "Utilisez un fichier capturé depuis un réseau de production"
            ]
        }

    return None
