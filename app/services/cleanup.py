"""
Service de cleanup automatique des fichiers temporaires
Supprime les fichiers PCAP et rapports expirés (>24h)
"""

import logging
import os
from datetime import datetime, timedelta
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

logger = logging.getLogger(__name__)


class CleanupScheduler:
    """
    Scheduler pour nettoyage automatique des fichiers.

    - PCAP uploads: Supprimés immédiatement après analyse
    - Rapports HTML/JSON: TTL 24h (nettoyage hourly)
    """

    def __init__(self, data_dir: str = "/data", retention_hours: int = 24):
        """
        Args:
            data_dir: Répertoire racine des données
            retention_hours: Durée de conservation des rapports (heures)
        """
        self.data_dir = Path(data_dir)
        self.retention_hours = retention_hours
        self.scheduler = AsyncIOScheduler()

        # Configurer job de cleanup (toutes les heures)
        self.scheduler.add_job(
            self.cleanup_old_files,
            CronTrigger(hour="*"),  # Toutes les heures
            id="cleanup_old_files",
            name="Cleanup old PCAP and reports",
            replace_existing=True,
        )

        # Configurer job de cleanup des tâches orphelines (toutes les 5 minutes)
        self.scheduler.add_job(
            self.cleanup_orphaned_tasks,
            CronTrigger(minute="*/5"),  # Toutes les 5 minutes
            id="cleanup_orphaned_tasks",
            name="Cleanup orphaned tasks (OOMKilled detection)",
            replace_existing=True,
        )

    def start(self):
        """Démarre le scheduler"""
        if not self.scheduler.running:
            self.scheduler.start()
            logger.info(f"Cleanup scheduler started (retention: {self.retention_hours}h)")

    def stop(self):
        """Arrête le scheduler"""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
            logger.info("Cleanup scheduler stopped")

    async def cleanup_old_files(self):
        """
        Nettoie les fichiers expirés dans reports/ et uploads/.

        - Fichiers >24h: Supprimés
        - Logs: Événement logué pour chaque suppression
        """
        cutoff_time = datetime.now() - timedelta(hours=self.retention_hours)
        cutoff_timestamp = cutoff_time.timestamp()

        logger.info(f"Starting cleanup (cutoff: {cutoff_time.isoformat()})")

        deleted_count = 0
        freed_bytes = 0

        # Cleanup répertoires
        for dir_name in ["reports", "uploads"]:
            dir_path = self.data_dir / dir_name

            if not dir_path.exists():
                logger.warning(f"Directory {dir_path} does not exist, skipping")
                continue

            # Parcourir tous les fichiers du répertoire
            for file_path in dir_path.iterdir():
                if not file_path.is_file():
                    continue

                # Vérifier date de modification
                try:
                    file_mtime = file_path.stat().st_mtime

                    if file_mtime < cutoff_timestamp:
                        file_size = file_path.stat().st_size
                        file_path.unlink()
                        deleted_count += 1
                        freed_bytes += file_size

                        logger.info(
                            f"Deleted expired file: {file_path.name} "
                            f"(size: {file_size / (1024**2):.2f} MB, "
                            f"age: {(datetime.now().timestamp() - file_mtime) / 3600:.1f}h)"
                        )

                except Exception as e:
                    logger.error(f"Error deleting file {file_path}: {e}")

        logger.info(f"Cleanup completed: {deleted_count} files deleted, " f"{freed_bytes / (1024**2):.2f} MB freed")

        # TODO: Mettre à jour SQLite pour marquer tâches comme 'expired'

    async def cleanup_orphaned_tasks(self):
        """
        Détecte et nettoie les tâches orphelines (pods OOMKilled).

        Les tâches en status PROCESSING sans heartbeat depuis 2 minutes
        sont considérées comme orphelines (pod crashé/OOMKilled).

        Recovery Strategy:
        1. Trouver les tâches avec heartbeat expiré (>120 secondes)
        2. Marquer comme FAILED avec message d'erreur descriptif
        3. Logger l'événement pour monitoring
        """
        try:
            # Import dynamique pour éviter circular dependencies
            from app.services.database import get_db_service

            db_service = get_db_service()

            # Trouver les tâches orphelines (no heartbeat for 120 seconds)
            orphaned_task_ids = await db_service.find_orphaned_tasks(
                heartbeat_timeout_seconds=120
            )

            if not orphaned_task_ids:
                logger.debug("No orphaned tasks found")
                return

            logger.warning(
                f"Found {len(orphaned_task_ids)} orphaned tasks: {orphaned_task_ids}"
            )

            # Marquer chaque tâche comme FAILED
            for task_id in orphaned_task_ids:
                await db_service.mark_task_as_failed_orphan(
                    task_id=task_id,
                    error_message=(
                        "Analysis terminated unexpectedly. "
                        "Possible causes: pod OOMKilled, pod restart, or network interruption. "
                        "Please try with a smaller PCAP file or increase pod memory limits."
                    ),
                )
                logger.info(f"Marked orphaned task {task_id} as FAILED")

        except Exception as e:
            logger.error(f"Error during orphan cleanup: {e}", exc_info=True)
            # Don't raise - allow scheduler to continue

    async def delete_file(self, file_path: Path):
        """
        Supprime un fichier immédiatement (pas de TTL).
        Utilisé pour supprimer PCAP après analyse.

        Args:
            file_path: Chemin du fichier à supprimer
        """
        try:
            if file_path.exists():
                file_size = file_path.stat().st_size
                file_path.unlink()
                logger.info(f"Deleted file: {file_path.name} " f"(size: {file_size / (1024**2):.2f} MB)")
            else:
                logger.warning(f"File {file_path} does not exist, skipping deletion")

        except Exception as e:
            logger.error(f"Error deleting file {file_path}: {e}")
