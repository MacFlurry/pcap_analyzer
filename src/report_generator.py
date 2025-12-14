"""
Générateur de rapports JSON pour l'analyse PCAP

Note: HTML report generation is handled by src/exporters/html_report.py
This module provides only JSON export functionality.
"""

import json
from pathlib import Path
from typing import Any


class ReportGenerator:
    """
    Générateur de rapports JSON pour l'analyse PCAP

    Usage:
        >>> gen = ReportGenerator(output_dir="reports")
        >>> gen._generate_json(results, Path("report.json"))
    """

    def __init__(self, output_dir: str = "reports") -> None:
        """
        Initialise le générateur de rapports

        Args:
            output_dir: Répertoire de sortie des rapports JSON
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _generate_json(self, data: dict[str, Any], output_path: Path) -> None:
        """
        Génère le rapport JSON

        Args:
            data: Dictionnaire contenant les résultats d'analyse
            output_path: Chemin du fichier JSON de sortie
        """
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
