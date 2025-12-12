"""
Service d'analyse PCAP avec callbacks pour SSE.
Wrapper autour de analyze_pcap_hybrid() du CLI.
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Callable, Optional

from src.cli import analyze_pcap_hybrid as cli_analyze_pcap_hybrid
from src.config import get_config

from app.models.schemas import TaskStatus

logger = logging.getLogger(__name__)


class ProgressCallback:
    """
    Callback handler pour envoyer les mises à jour de progression via SSE.
    """

    def __init__(self, task_id: str, callback_fn: Optional[Callable] = None):
        """
        Args:
            task_id: ID de la tâche
            callback_fn: Fonction async à appeler pour chaque mise à jour
                        Signature: async def callback(task_id, phase, progress, message)
        """
        self.task_id = task_id
        self.callback_fn = callback_fn
        self.current_phase = None
        self.total_packets = 0
        self.packets_processed = 0

    async def update(
        self,
        phase: str,
        progress_percent: int,
        packets_processed: Optional[int] = None,
        total_packets: Optional[int] = None,
        current_analyzer: Optional[str] = None,
        message: Optional[str] = None,
    ):
        """
        Envoie une mise à jour de progression.

        Args:
            phase: Phase actuelle ("metadata", "analysis", "finalize")
            progress_percent: Pourcentage de progression (0-100)
            packets_processed: Nombre de paquets traités
            total_packets: Nombre total de paquets
            current_analyzer: Nom de l'analyseur en cours
            message: Message descriptif
        """
        self.current_phase = phase
        if packets_processed is not None:
            self.packets_processed = packets_processed
        if total_packets is not None:
            self.total_packets = total_packets

        if self.callback_fn:
            await self.callback_fn(
                task_id=self.task_id,
                phase=phase,
                progress_percent=progress_percent,
                packets_processed=packets_processed,
                total_packets=total_packets,
                current_analyzer=current_analyzer,
                message=message,
            )

        logger.debug(
            f"Task {self.task_id} - Phase: {phase}, Progress: {progress_percent}%, "
            f"Packets: {packets_processed}/{total_packets}, Analyzer: {current_analyzer}"
        )


class AnalyzerService:
    """
    Service pour exécuter l'analyse PCAP avec support SSE.
    """

    def __init__(self, data_dir: str = "/data"):
        """
        Args:
            data_dir: Répertoire racine pour uploads/reports
        """
        self.data_dir = Path(data_dir)
        self.uploads_dir = self.data_dir / "uploads"
        self.reports_dir = self.data_dir / "reports"

        # Créer les répertoires si nécessaires
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    async def analyze_pcap(
        self,
        task_id: str,
        pcap_path: str,
        progress_callback: Optional[ProgressCallback] = None,
    ) -> dict[str, Any]:
        """
        Analyse un fichier PCAP avec callbacks de progression.

        Cette fonction est un wrapper async autour de analyze_pcap_hybrid() qui:
        1. Exécute l'analyse dans un thread séparé (run_in_executor)
        2. Envoie des mises à jour de progression via callback
        3. Génère les rapports HTML/JSON

        Args:
            task_id: ID unique de la tâche
            pcap_path: Chemin vers le fichier PCAP à analyser
            progress_callback: Callback pour mises à jour SSE

        Returns:
            Dictionnaire avec résultats d'analyse et chemins des rapports

        Raises:
            Exception: Si l'analyse échoue
        """
        logger.info(f"Starting analysis for task {task_id}: {pcap_path}")

        # Charger la configuration
        config = get_config()

        # Callback wrapper pour synchroniser avec asyncio
        if progress_callback:
            await progress_callback.update(
                phase="metadata",
                progress_percent=0,
                message="Initialisation de l'analyse...",
            )

        try:
            # Exécuter l'analyse dans un thread séparé (blocking operation)
            # TODO: Instrumenter analyze_pcap_hybrid pour accepter des callbacks
            # Pour l'instant, on l'exécute tel quel et on simule les updates
            loop = asyncio.get_event_loop()

            # Phase 1: Metadata extraction (0-50%)
            if progress_callback:
                await progress_callback.update(
                    phase="metadata",
                    progress_percent=10,
                    message="Extraction des métadonnées (dpkt)...",
                )

            # Exécuter l'analyse (blocking)
            results = await loop.run_in_executor(
                None,  # Default executor
                lambda: self._run_analysis_sync(pcap_path, config),
            )

            # Phase 2: Analysis complete (100%)
            if progress_callback:
                total_packets = results.get("metadata", {}).get("total_packets", 0)
                await progress_callback.update(
                    phase="finalize",
                    progress_percent=90,
                    packets_processed=total_packets,
                    total_packets=total_packets,
                    message="Génération des rapports...",
                )

            # Générer les rapports
            report_paths = await self._generate_reports(task_id, results, pcap_path)

            if progress_callback:
                await progress_callback.update(
                    phase="completed",
                    progress_percent=100,
                    message="Analyse terminée avec succès",
                )

            logger.info(f"Analysis completed for task {task_id}")

            return {
                "results": results,
                "reports": report_paths,
            }

        except Exception as e:
            logger.error(f"Analysis failed for task {task_id}: {e}", exc_info=True)
            if progress_callback:
                await progress_callback.update(
                    phase="failed",
                    progress_percent=0,
                    message=f"Erreur: {str(e)}",
                )
            raise

    def _run_analysis_sync(self, pcap_path: str, config) -> dict[str, Any]:
        """
        Exécute l'analyse synchrone (version CLI).

        Cette méthode sera exécutée dans un thread séparé via run_in_executor.

        Args:
            pcap_path: Chemin vers le fichier PCAP
            config: Configuration object

        Returns:
            Dictionnaire avec résultats d'analyse
        """
        # Appeler la fonction CLI existante
        # NOTE: Cette fonction utilise Rich Progress qui affiche dans le terminal
        # Pour la version web, il faudrait instrumenter la fonction pour accepter des callbacks
        results = cli_analyze_pcap_hybrid(
            pcap_file=pcap_path,
            config=config,
            latency_filter=None,
            show_details=False,
            include_localhost=False,
            enable_streaming=True,
            enable_parallel=False,
        )

        return results

    async def _generate_reports(
        self,
        task_id: str,
        results: dict[str, Any],
        pcap_path: str,
    ) -> dict[str, str]:
        """
        Génère les rapports HTML et JSON.

        Args:
            task_id: ID de la tâche
            results: Résultats d'analyse
            pcap_path: Chemin du fichier PCAP

        Returns:
            Dictionnaire avec chemins des rapports {"html": "...", "json": "..."}
        """
        from datetime import datetime

        from jinja2 import Environment, FileSystemLoader

        from src.exporters.html_report import HTMLReportGenerator
        from src.report_generator import ReportGenerator

        # Préparer les chemins de sortie
        html_path = self.reports_dir / f"{task_id}.html"
        json_path = self.reports_dir / f"{task_id}.json"

        # Ajouter métadonnées si manquantes
        if "metadata" not in results:
            results["metadata"] = {}
        results["metadata"]["pcap_file"] = Path(pcap_path).name

        # Extraire total_packets depuis protocol_distribution
        if "protocol_distribution" in results:
            results["metadata"]["total_packets"] = results["protocol_distribution"].get("total_packets", 0)

        # Extraire capture_duration depuis timestamps
        if "timestamps" in results:
            results["metadata"]["capture_duration"] = results["timestamps"].get("capture_duration", 0)

        # Générer JSON
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: ReportGenerator(output_dir=str(self.reports_dir))._generate_json(results, json_path),
        )

        # Générer HTML
        await loop.run_in_executor(
            None,
            lambda: HTMLReportGenerator().save(results, str(html_path)),
        )

        logger.info(f"Reports generated for task {task_id}: {html_path}, {json_path}")

        return {
            "html": str(html_path),
            "json": str(json_path),
        }


# Singleton instance
_analyzer_service: Optional[AnalyzerService] = None


def get_analyzer_service() -> AnalyzerService:
    """
    Retourne l'instance singleton du AnalyzerService.

    Returns:
        AnalyzerService instance
    """
    global _analyzer_service
    if _analyzer_service is None:
        data_dir = os.getenv("DATA_DIR", "/data")
        _analyzer_service = AnalyzerService(data_dir=data_dir)
    return _analyzer_service
