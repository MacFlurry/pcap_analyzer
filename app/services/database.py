"""
Service de gestion de la base de données SQLite pour tracking des analyses.
Utilise aiosqlite pour opérations asynchrones.
"""

import logging
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import aiosqlite

from app.models.schemas import TaskInfo, TaskStatus

logger = logging.getLogger(__name__)

# SQLite schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS tasks (
    task_id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    status TEXT NOT NULL,
    uploaded_at TIMESTAMP NOT NULL,
    analyzed_at TIMESTAMP,
    file_size_bytes INTEGER NOT NULL,
    total_packets INTEGER,
    health_score REAL,
    report_html_path TEXT,
    report_json_path TEXT,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_uploaded_at ON tasks(uploaded_at);
"""


class DatabaseService:
    """
    Service pour opérations CRUD sur la base de données SQLite.

    Thread-safe via aiosqlite (async SQLite wrapper).
    """

    def __init__(self, db_path: str = "/data/pcap_analyzer.db"):
        """
        Args:
            db_path: Chemin vers le fichier SQLite
        """
        self.db_path = db_path
        self._ensure_data_dir()

    def _ensure_data_dir(self):
        """Crée le répertoire parent si nécessaire"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

    async def init_db(self):
        """
        Initialise la base de données avec le schéma.
        Idempotent: peut être appelé plusieurs fois sans problème.
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.executescript(SCHEMA)
            await db.commit()
        logger.info(f"Database initialized at {self.db_path}")

    async def create_task(
        self,
        task_id: str,
        filename: str,
        file_size_bytes: int,
    ) -> TaskInfo:
        """
        Crée une nouvelle tâche d'analyse (status=PENDING).

        Args:
            task_id: ID unique de la tâche (UUID)
            filename: Nom du fichier PCAP uploadé
            file_size_bytes: Taille du fichier en octets

        Returns:
            TaskInfo object
        """
        uploaded_at = datetime.utcnow()

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO tasks (
                    task_id, filename, status, uploaded_at, file_size_bytes
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (task_id, filename, TaskStatus.PENDING.value, uploaded_at, file_size_bytes),
            )
            await db.commit()

        logger.info(f"Task created: {task_id} ({filename}, {file_size_bytes} bytes)")

        return TaskInfo(
            task_id=task_id,
            filename=filename,
            status=TaskStatus.PENDING,
            uploaded_at=uploaded_at,
            file_size_bytes=file_size_bytes,
        )

    async def get_task(self, task_id: str) -> Optional[TaskInfo]:
        """
        Récupère les informations d'une tâche.

        Args:
            task_id: ID de la tâche

        Returns:
            TaskInfo si trouvée, None sinon
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT task_id, filename, status, uploaded_at, analyzed_at,
                       file_size_bytes, total_packets, health_score,
                       report_html_path, report_json_path, error_message
                FROM tasks WHERE task_id = ?
                """,
                (task_id,),
            ) as cursor:
                row = await cursor.fetchone()

        if not row:
            return None

        # Convert to TaskInfo
        return TaskInfo(
            task_id=row["task_id"],
            filename=row["filename"],
            status=TaskStatus(row["status"]),
            uploaded_at=datetime.fromisoformat(row["uploaded_at"]) if row["uploaded_at"] else datetime.utcnow(),
            analyzed_at=datetime.fromisoformat(row["analyzed_at"]) if row["analyzed_at"] else None,
            file_size_bytes=row["file_size_bytes"],
            total_packets=row["total_packets"],
            health_score=row["health_score"],
            report_html_url=f"/api/reports/{task_id}/html" if row["report_html_path"] else None,
            report_json_url=f"/api/reports/{task_id}/json" if row["report_json_path"] else None,
            error_message=row["error_message"],
        )

    async def update_status(self, task_id: str, status: TaskStatus, error_message: Optional[str] = None):
        """
        Met à jour le statut d'une tâche.

        Args:
            task_id: ID de la tâche
            status: Nouveau statut
            error_message: Message d'erreur (si status=FAILED)
        """
        analyzed_at = datetime.utcnow() if status in [TaskStatus.COMPLETED, TaskStatus.FAILED] else None

        async with aiosqlite.connect(self.db_path) as db:
            if analyzed_at:
                await db.execute(
                    "UPDATE tasks SET status = ?, analyzed_at = ?, error_message = ? WHERE task_id = ?",
                    (status.value, analyzed_at, error_message, task_id),
                )
            else:
                await db.execute(
                    "UPDATE tasks SET status = ?, error_message = ? WHERE task_id = ?",
                    (status.value, error_message, task_id),
                )
            await db.commit()

        logger.info(f"Task {task_id} status updated: {status.value}")

    async def update_results(
        self,
        task_id: str,
        total_packets: int,
        health_score: float,
        report_html_path: str,
        report_json_path: str,
    ):
        """
        Met à jour les résultats d'analyse d'une tâche.

        Args:
            task_id: ID de la tâche
            total_packets: Nombre total de paquets analysés
            health_score: Score de santé (0-100)
            report_html_path: Chemin vers le rapport HTML
            report_json_path: Chemin vers le rapport JSON
        """
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE tasks
                SET total_packets = ?, health_score = ?,
                    report_html_path = ?, report_json_path = ?
                WHERE task_id = ?
                """,
                (total_packets, health_score, report_html_path, report_json_path, task_id),
            )
            await db.commit()

        logger.info(f"Task {task_id} results updated: {total_packets} packets, score {health_score:.1f}")

    async def get_recent_tasks(self, limit: int = 20) -> list[TaskInfo]:
        """
        Récupère les tâches récentes (historique).

        Args:
            limit: Nombre maximum de tâches à retourner

        Returns:
            Liste de TaskInfo, triée par date décroissante
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT task_id, filename, status, uploaded_at, analyzed_at,
                       file_size_bytes, total_packets, health_score,
                       report_html_path, report_json_path, error_message
                FROM tasks
                ORDER BY uploaded_at DESC
                LIMIT ?
                """,
                (limit,),
            ) as cursor:
                rows = await cursor.fetchall()

        tasks = []
        for row in rows:
            tasks.append(
                TaskInfo(
                    task_id=row["task_id"],
                    filename=row["filename"],
                    status=TaskStatus(row["status"]),
                    uploaded_at=datetime.fromisoformat(row["uploaded_at"]) if row["uploaded_at"] else datetime.utcnow(),
                    analyzed_at=datetime.fromisoformat(row["analyzed_at"]) if row["analyzed_at"] else None,
                    file_size_bytes=row["file_size_bytes"],
                    total_packets=row["total_packets"],
                    health_score=row["health_score"],
                    report_html_url=f"/api/reports/{row['task_id']}/html" if row["report_html_path"] else None,
                    report_json_url=f"/api/reports/{row['task_id']}/json" if row["report_json_path"] else None,
                    error_message=row["error_message"],
                )
            )

        return tasks

    async def mark_expired_tasks(self, retention_hours: int = 24) -> int:
        """
        Marque les tâches expirées (>retention_hours) comme EXPIRED.

        Args:
            retention_hours: Durée de conservation (heures)

        Returns:
            Nombre de tâches marquées comme expirées
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=retention_hours)

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                UPDATE tasks
                SET status = ?
                WHERE uploaded_at < ?
                  AND status NOT IN (?, ?)
                """,
                (TaskStatus.EXPIRED.value, cutoff_time, TaskStatus.EXPIRED.value, TaskStatus.PROCESSING.value),
            )
            count = cursor.rowcount
            await db.commit()

        if count > 0:
            logger.info(f"Marked {count} tasks as expired (cutoff: {cutoff_time.isoformat()})")

        return count

    async def get_stats(self) -> dict:
        """
        Récupère des statistiques globales sur les tâches.

        Returns:
            Dictionnaire avec statistiques (total, completed, failed, pending, etc.)
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            # Count by status
            async with db.execute("SELECT status, COUNT(*) as count FROM tasks GROUP BY status") as cursor:
                rows = await cursor.fetchall()

        stats = {
            "total": 0,
            "pending": 0,
            "processing": 0,
            "completed": 0,
            "failed": 0,
            "expired": 0,
        }

        for row in rows:
            status = row["status"]
            count = row["count"]
            stats["total"] += count
            if status in stats:
                stats[status] = count

        return stats


# Singleton instance
_db_service: Optional[DatabaseService] = None


def get_db_service() -> DatabaseService:
    """
    Retourne l'instance singleton du DatabaseService.

    Returns:
        DatabaseService instance
    """
    global _db_service
    if _db_service is None:
        data_dir = os.getenv("DATA_DIR", "/data")
        db_path = f"{data_dir}/pcap_analyzer.db"
        _db_service = DatabaseService(db_path=db_path)
    return _db_service
