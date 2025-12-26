"""
Service d'analyse PCAP avec callbacks pour SSE.
Wrapper autour de analyze_pcap_hybrid() du CLI.
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Any, Callable, Optional

from app.models.schemas import TaskStatus
from src.cli import analyze_pcap_hybrid as cli_analyze_pcap_hybrid
from src.config import get_config

from app.utils.config import get_data_dir

logger = logging.getLogger(__name__)


def translate_error_to_human(error: Exception) -> str:
    """
    Traduit une erreur technique en message compréhensible pour l'utilisateur.

    Args:
        error: Exception à traduire

    Returns:
        Message d'erreur en français, compréhensible par l'utilisateur
    """
    error_msg = str(error).lower()
    error_type = type(error).__name__

    # Erreurs de fichier PCAP corrompu/tronqué
    if "got" in error_msg and "needed at least" in error_msg:
        return (
            "Le fichier PCAP est corrompu ou tronqué. "
            "Il semble incomplet et ne peut pas être analysé correctement. "
            "Veuillez vérifier que la capture s'est terminée correctement."
        )

    # Erreur de couche réseau manquante (Scapy)
    if "layer" in error_msg and "not found" in error_msg:
        layer_name = str(error).split("[")[1].split("]")[0] if "[" in str(error) else "réseau"
        return (
            f"Le fichier PCAP contient des paquets sans couche {layer_name}. "
            "Cela peut arriver avec certains types de captures (IPv6, tunnels, etc.). "
            "Essayez avec un fichier de capture réseau standard (IPv4)."
        )

    # IndexError générique (problème de parsing)
    if error_type == "IndexError":
        return (
            "Erreur lors de l'analyse des paquets réseau. "
            "Le fichier contient probablement des paquets malformés ou des protocoles non supportés."
        )

    # Erreur de permissions
    if "permission denied" in error_msg:
        return "Erreur de permissions lors de la lecture du fichier. " "Vérifiez que le fichier est accessible."

    # Fichier vide
    if "empty" in error_msg or "no packets" in error_msg:
        return "Le fichier PCAP ne contient aucun paquet. Vérifiez que la capture a bien enregistré du trafic réseau."

    # Fichier non trouvé (vérifier AVANT "not found" générique)
    if "no such file" in error_msg:
        return "Le fichier PCAP n'a pas été trouvé. Il a peut-être été supprimé ou déplacé."

    # Erreur de format
    if "invalid" in error_msg and ("pcap" in error_msg or "format" in error_msg):
        return "Le format du fichier n'est pas valide. " "Assurez-vous qu'il s'agit bien d'un fichier PCAP ou PCAP-NG."

    # Erreur de mémoire
    if "memory" in error_msg or "memoryerror" in error_type.lower():
        return (
            "Le fichier est trop volumineux pour être traité avec les ressources disponibles. "
            "Essayez avec un fichier plus petit."
        )

    # Timeout
    if "timeout" in error_msg:
        return "L'analyse a pris trop de temps et a été interrompue. Le fichier est peut-être trop volumineux."

    # Erreur générique avec le type d'erreur
    if error_type in ["ValueError", "TypeError", "AttributeError"]:
        return f"Erreur de traitement des données : {str(error)}"

    # Par défaut, retourner l'erreur originale mais nettoyée
    return f"Erreur inattendue : {str(error)}"


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
        loop = asyncio.get_event_loop()

        # Create sync wrapper for progress callback that can be called from executor thread
        sync_progress_callback = None
        if progress_callback:
            logger.info(f"[CALLBACK DEBUG] Task {task_id}: progress_callback exists, creating wrapper")
            def sync_callback_wrapper(phase: str, progress_percent: int, message: str):
                """
                Synchronous wrapper that schedules the async callback in the event loop.
                This can be called from the executor thread (synchronous code).
                """
                logger.info(f"[CALLBACK DEBUG] Task {task_id}: Wrapper called - phase={phase}, progress={progress_percent}%, message={message}")
                # Schedule the async callback in the main event loop (fire-and-forget)
                asyncio.run_coroutine_threadsafe(
                    progress_callback.update(
                        phase=phase,
                        progress_percent=progress_percent,
                        message=message,
                    ),
                    loop
                )

            sync_progress_callback = sync_callback_wrapper
            logger.info(f"[CALLBACK DEBUG] Task {task_id}: Wrapper created successfully")
        else:
            logger.warning(f"[CALLBACK DEBUG] Task {task_id}: No progress_callback provided!")

        try:
            # Exécuter l'analyse dans un thread séparé avec callbacks en temps réel
            results = await loop.run_in_executor(
                None,  # Default executor
                lambda: self._run_analysis_sync(pcap_path, config, sync_progress_callback),
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
            # Traduire l'erreur technique en message compréhensible
            human_error = translate_error_to_human(e)
            logger.error(f"Analysis failed for task {task_id}: {e}", exc_info=True)

            if progress_callback:
                await progress_callback.update(
                    phase="failed",
                    progress_percent=0,
                    message=human_error,
                )

            # Re-raise avec le message traduit pour que le worker puisse le stocker
            raise Exception(human_error) from e

    def _run_analysis_sync(self, pcap_path: str, config, progress_callback=None) -> dict[str, Any]:
        """
        Exécute l'analyse synchrone (version CLI).

        Cette méthode sera exécutée dans un thread séparé via run_in_executor.

        Args:
            pcap_path: Chemin vers le fichier PCAP
            config: Configuration object
            progress_callback: Optional synchronous callback for progress updates

        Returns:
            Dictionnaire avec résultats d'analyse
        """
        if progress_callback:
            logger.info(f"[CALLBACK DEBUG] _run_analysis_sync received callback: {progress_callback}")
        else:
            logger.warning(f"[CALLBACK DEBUG] _run_analysis_sync received NO callback!")

        # Appeler la fonction CLI avec support de callbacks pour progression en temps réel
        results = cli_analyze_pcap_hybrid(
            pcap_file=pcap_path,
            config=config,
            latency_filter=None,
            show_details=False,
            include_localhost=False,
            enable_streaming=True,
            enable_parallel=False,
            progress_callback=progress_callback,  # Pass callback for real-time progress
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

        # Extraire total_packets - priorité aux données Phase 1 (dpkt) qui sont toujours fiables
        total_packets = 0
        # 1. Essayer timestamps (Phase 1 - dpkt)
        if "timestamps" in results and "total_packets" in results["timestamps"]:
            total_packets = results["timestamps"].get("total_packets", 0)
        # 2. Sinon essayer retransmission (Phase 1 - dpkt)
        elif "retransmission" in results and "total_packets_analyzed" in results["retransmission"]:
            total_packets = results["retransmission"].get("total_packets_analyzed", 0)
        # 3. En dernier recours protocol_distribution (Phase 2 - Scapy, peut être vide)
        elif "protocol_distribution" in results:
            total_packets = results["protocol_distribution"].get("total_packets", 0)

        results["metadata"]["total_packets"] = total_packets

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
        data_dir = get_data_dir()
        _analyzer_service = AnalyzerService(data_dir=str(data_dir))
    return _analyzer_service
