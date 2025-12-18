"""
Background worker pour traitement asynchrone des analyses PCAP.
Utilise asyncio.Queue pour gérer les tâches.
"""

import asyncio
import logging
import os
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from app.models.schemas import TaskStatus
from app.services.analyzer import AnalyzerService, ProgressCallback, get_analyzer_service
from app.services.database import DatabaseService, get_db_service

logger = logging.getLogger(__name__)


@dataclass
class ProgressUpdate:
    """Update de progression pour SSE"""

    task_id: str
    phase: str
    progress_percent: int
    packets_processed: Optional[int] = None
    total_packets: Optional[int] = None
    current_analyzer: Optional[str] = None
    message: Optional[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


class AnalysisWorker:
    """
    Worker pour traiter les analyses PCAP en arrière-plan.

    Utilise asyncio.Queue pour gérer la file d'attente:
    - maxsize=5 pour limiter la charge
    - 1 worker asyncio task qui traite les tâches séquentiellement
    """

    def __init__(
        self,
        max_queue_size: int = 5,
        data_dir: str = "/data",
        db_service: Optional[DatabaseService] = None,
        analyzer_service: Optional[AnalyzerService] = None,
    ):
        """
        Args:
            max_queue_size: Taille maximale de la queue
            data_dir: Répertoire racine des données
            db_service: Service database (injection dépendance)
            analyzer_service: Service analyzer (injection dépendance)
        """
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=max_queue_size)
        self.data_dir = Path(data_dir)
        self.db_service = db_service or get_db_service()
        self.analyzer_service = analyzer_service or get_analyzer_service()

        # Stockage des updates SSE pour chaque tâche active
        # Structure: {task_id: [ProgressUpdate, ...]}
        self.progress_updates: dict[str, list[ProgressUpdate]] = defaultdict(list)

        # Tracking de la dernière progression persistée (pour minimiser les écritures DB)
        # Structure: {task_id: progress_percent}
        self._last_persisted_progress: dict[str, int] = {}

        # Worker task
        self.worker_task: Optional[asyncio.Task] = None
        self.is_running = False

    async def start(self):
        """Démarre le worker en arrière-plan"""
        if self.is_running:
            logger.warning("Worker already running")
            return

        self.is_running = True
        self.worker_task = asyncio.create_task(self._worker_loop())
        logger.info("Analysis worker started")

    async def stop(self):
        """Arrête le worker proprement"""
        if not self.is_running:
            return

        self.is_running = False

        # Attendre que la queue se vide
        await self.queue.join()

        # Annuler le worker task
        if self.worker_task:
            self.worker_task.cancel()
            try:
                await self.worker_task
            except asyncio.CancelledError:
                pass

        logger.info("Analysis worker stopped")

    async def enqueue(self, task_id: str, pcap_path: str) -> bool:
        """
        Ajoute une tâche à la queue.

        Args:
            task_id: ID de la tâche
            pcap_path: Chemin vers le fichier PCAP

        Returns:
            True si ajouté, False si queue pleine
        """
        try:
            # Non-blocking put
            self.queue.put_nowait((task_id, pcap_path))
            logger.info(f"Task {task_id} enqueued (queue size: {self.queue.qsize()})")
            return True
        except asyncio.QueueFull:
            logger.warning(f"Queue full, cannot enqueue task {task_id}")
            return False

    def get_queue_size(self) -> int:
        """Retourne la taille actuelle de la queue"""
        return self.queue.qsize()

    def get_progress_updates(self, task_id: str) -> list[ProgressUpdate]:
        """
        Récupère les mises à jour de progression pour une tâche.

        Args:
            task_id: ID de la tâche

        Returns:
            Liste des updates (peut être vide)
        """
        return self.progress_updates.get(task_id, [])

    def clear_progress_updates(self, task_id: str):
        """Nettoie les updates d'une tâche terminée"""
        if task_id in self.progress_updates:
            del self.progress_updates[task_id]
            logger.debug(f"Progress updates cleared for task {task_id}")

    async def _worker_loop(self):
        """
        Boucle principale du worker.
        Traite les tâches de la queue une par une.
        """
        logger.info("Worker loop started")

        while self.is_running:
            try:
                # Attendre une tâche (blocking avec timeout)
                task_id, pcap_path = await asyncio.wait_for(self.queue.get(), timeout=1.0)

                logger.info(f"Processing task {task_id} from queue")

                try:
                    await self._process_task(task_id, pcap_path)
                except Exception as e:
                    logger.error(f"Error processing task {task_id}: {e}", exc_info=True)
                    await self._handle_task_error(task_id, str(e))
                finally:
                    # Marquer la tâche comme complétée dans la queue
                    self.queue.task_done()

            except asyncio.TimeoutError:
                # Timeout normal, continuer la boucle
                continue
            except asyncio.CancelledError:
                logger.info("Worker loop cancelled")
                break
            except Exception as e:
                logger.error(f"Unexpected error in worker loop: {e}", exc_info=True)
                await asyncio.sleep(1)  # Éviter une boucle infinie en cas d'erreur

    def _should_persist_progress(self, task_id: str, progress_percent: int) -> bool:
        """
        Détermine si la progression doit être persistée en base de données.

        Stratégie pour minimiser les écritures:
        - Première mise à jour (0%)
        - Tous les 5% (5, 10, 15, ..., 95)
        - Dernière mise à jour (100%)

        Args:
            task_id: ID de la tâche
            progress_percent: Pourcentage de progression actuel

        Returns:
            True si la progression doit être persistée
        """
        last_persisted = self._last_persisted_progress.get(task_id)

        # Première mise à jour
        if last_persisted is None:
            return True

        # Dernière mise à jour
        if progress_percent == 100:
            return True

        # Tous les 5%
        if progress_percent % 5 == 0 and progress_percent != last_persisted:
            return True

        return False

    async def _heartbeat_loop(self, task_id: str):
        """
        Boucle de heartbeat pour une tâche en cours.

        Envoie un heartbeat toutes les 10 secondes jusqu'à ce que
        la tâche soit terminée ou annulée.

        Args:
            task_id: ID de la tâche
        """
        logger.debug(f"Heartbeat loop started for task {task_id}")

        try:
            while True:
                await asyncio.sleep(10)  # Heartbeat toutes les 10 secondes
                await self.db_service.update_heartbeat(task_id)
                logger.debug(f"Heartbeat sent for task {task_id}")
        except asyncio.CancelledError:
            logger.debug(f"Heartbeat loop cancelled for task {task_id}")
            raise

    async def _process_task(self, task_id: str, pcap_path: str):
        """
        Traite une tâche d'analyse.

        Args:
            task_id: ID de la tâche
            pcap_path: Chemin vers le fichier PCAP
        """
        # Mettre à jour le statut en PROCESSING
        await self.db_service.update_status(task_id, TaskStatus.PROCESSING)

        # Envoyer le heartbeat initial
        await self.db_service.update_heartbeat(task_id)

        # Lancer la boucle de heartbeat en arrière-plan
        heartbeat_task = asyncio.create_task(self._heartbeat_loop(task_id))

        try:
            # Créer le callback de progression
            async def progress_callback_fn(
                task_id: str,
                phase: str,
                progress_percent: int,
                packets_processed: Optional[int] = None,
                total_packets: Optional[int] = None,
                current_analyzer: Optional[str] = None,
                message: Optional[str] = None,
            ):
                """Callback appelé lors des mises à jour de progression"""
                # Créer l'update pour SSE
                update = ProgressUpdate(
                    task_id=task_id,
                    phase=phase,
                    progress_percent=progress_percent,
                    packets_processed=packets_processed,
                    total_packets=total_packets,
                    current_analyzer=current_analyzer,
                    message=message,
                )
                self.progress_updates[task_id].append(update)

                # Persister en base de données si nécessaire (tous les 5%)
                if self._should_persist_progress(task_id, progress_percent):
                    await self.db_service.create_progress_snapshot(
                        task_id=task_id,
                        phase=phase,
                        progress_percent=progress_percent,
                        packets_processed=packets_processed,
                        total_packets=total_packets,
                        current_analyzer=current_analyzer,
                        message=message,
                    )
                    self._last_persisted_progress[task_id] = progress_percent
                    logger.debug(f"Progress persisted for task {task_id}: {progress_percent}%")

            progress_callback = ProgressCallback(task_id=task_id, callback_fn=progress_callback_fn)

            # Exécuter l'analyse
            result = await self.analyzer_service.analyze_pcap(
                task_id=task_id,
                pcap_path=pcap_path,
                progress_callback=progress_callback,
            )

            # Mettre à jour la base de données avec les résultats
            analysis_results = result["results"]
            report_paths = result["reports"]

            total_packets = analysis_results.get("metadata", {}).get("total_packets", 0)
            # Fix: la clé est "overall_score" pas "score"
            health_score = analysis_results.get("health_score", {}).get("overall_score", 0.0)

            await self.db_service.update_results(
                task_id=task_id,
                total_packets=total_packets,
                health_score=health_score,
                report_html_path=report_paths["html"],
                report_json_path=report_paths["json"],
            )

            # Mettre à jour le statut en COMPLETED
            await self.db_service.update_status(task_id, TaskStatus.COMPLETED)

            # Supprimer le fichier PCAP (ne conserver que les rapports)
            try:
                Path(pcap_path).unlink()
                logger.info(f"PCAP file deleted: {pcap_path}")
            except Exception as e:
                logger.warning(f"Failed to delete PCAP file {pcap_path}: {e}")

            logger.info(f"Task {task_id} completed successfully")

        finally:
            # Annuler la boucle de heartbeat
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

            # Nettoyer le tracking de progression
            if task_id in self._last_persisted_progress:
                del self._last_persisted_progress[task_id]

    async def _handle_task_error(self, task_id: str, error_message: str):
        """
        Gère une erreur lors du traitement d'une tâche.

        Args:
            task_id: ID de la tâche
            error_message: Message d'erreur
        """
        await self.db_service.update_status(task_id, TaskStatus.FAILED, error_message=error_message)

        # Ajouter un update d'erreur
        error_update = ProgressUpdate(
            task_id=task_id,
            phase="failed",
            progress_percent=0,
            message=f"Erreur: {error_message}",
        )
        self.progress_updates[task_id].append(error_update)

        logger.error(f"Task {task_id} failed: {error_message}")


# Singleton instance
_worker: Optional[AnalysisWorker] = None


def get_worker() -> AnalysisWorker:
    """
    Retourne l'instance singleton du worker.

    Returns:
        AnalysisWorker instance
    """
    global _worker
    if _worker is None:
        data_dir = os.getenv("DATA_DIR", "/data")
        max_queue_size = int(os.getenv("MAX_QUEUE_SIZE", "5"))
        _worker = AnalysisWorker(max_queue_size=max_queue_size, data_dir=data_dir)
    return _worker
