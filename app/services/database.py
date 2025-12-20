"""
Service de gestion de la base de données SQLite pour tracking des analyses.
Utilise aiosqlite pour opérations asynchrones.
"""

import logging
import os
from datetime import datetime, timedelta, timezone
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
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_heartbeat TIMESTAMP,
    progress_percent INTEGER DEFAULT 0,
    current_phase TEXT
);

CREATE INDEX IF NOT EXISTS idx_status ON tasks(status);
CREATE INDEX IF NOT EXISTS idx_uploaded_at ON tasks(uploaded_at);
CREATE INDEX IF NOT EXISTS idx_tasks_heartbeat ON tasks(last_heartbeat);

CREATE TABLE IF NOT EXISTS progress_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    progress_percent INTEGER NOT NULL,
    packets_processed INTEGER,
    total_packets INTEGER,
    current_analyzer TEXT,
    message TEXT,
    timestamp TIMESTAMP NOT NULL,
    FOREIGN KEY (task_id) REFERENCES tasks(task_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_progress_task_id ON progress_snapshots(task_id);
CREATE INDEX IF NOT EXISTS idx_progress_timestamp ON progress_snapshots(timestamp);
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
        owner_id: str = None,
    ) -> TaskInfo:
        """
        Crée une nouvelle tâche d'analyse (status=PENDING).

        Args:
            task_id: ID unique de la tâche (UUID)
            filename: Nom du fichier PCAP uploadé
            file_size_bytes: Taille du fichier en octets
            owner_id: User ID of the owner (multi-tenant)

        Returns:
            TaskInfo object
        """
        uploaded_at = datetime.now(timezone.utc)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO tasks (
                    task_id, filename, status, uploaded_at, file_size_bytes, owner_id
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (task_id, filename, TaskStatus.PENDING.value, uploaded_at, file_size_bytes, owner_id),
            )
            await db.commit()

        logger.info(f"Task created: {task_id} ({filename}, {file_size_bytes} bytes, owner: {owner_id})")

        return TaskInfo(
            task_id=task_id,
            filename=filename,
            status=TaskStatus.PENDING,
            uploaded_at=uploaded_at,
            file_size_bytes=file_size_bytes,
            owner_id=owner_id,
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
                       report_html_path, report_json_path, error_message, owner_id
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
            uploaded_at=(
                datetime.fromisoformat(row["uploaded_at"]) if row["uploaded_at"] else datetime.now(timezone.utc)
            ),
            analyzed_at=datetime.fromisoformat(row["analyzed_at"]) if row["analyzed_at"] else None,
            file_size_bytes=row["file_size_bytes"],
            total_packets=row["total_packets"],
            health_score=row["health_score"],
            report_html_url=f"/api/reports/{task_id}/html" if row["report_html_path"] else None,
            report_json_url=f"/api/reports/{task_id}/json" if row["report_json_path"] else None,
            error_message=row["error_message"],
            owner_id=row["owner_id"],
        )

    async def update_status(self, task_id: str, status: TaskStatus, error_message: Optional[str] = None):
        """
        Met à jour le statut d'une tâche.

        Args:
            task_id: ID de la tâche
            status: Nouveau statut
            error_message: Message d'erreur (si status=FAILED)
        """
        analyzed_at = datetime.now(timezone.utc) if status in [TaskStatus.COMPLETED, TaskStatus.FAILED] else None

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

    async def get_recent_tasks(self, limit: int = 20, owner_id: str = None) -> list[TaskInfo]:
        """
        Récupère les tâches récentes (historique).

        Args:
            limit: Nombre maximum de tâches à retourner
            owner_id: Filter by owner ID (multi-tenant). If None, returns all tasks.

        Returns:
            Liste de TaskInfo, triée par date décroissante
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row

            if owner_id:
                # Filter by owner_id (regular users)
                async with db.execute(
                    """
                    SELECT task_id, filename, status, uploaded_at, analyzed_at,
                           file_size_bytes, total_packets, health_score,
                           report_html_path, report_json_path, error_message, owner_id
                    FROM tasks
                    WHERE owner_id = ?
                    ORDER BY uploaded_at DESC
                    LIMIT ?
                    """,
                    (owner_id, limit),
                ) as cursor:
                    rows = await cursor.fetchall()
            else:
                # No filter (admin users)
                async with db.execute(
                    """
                    SELECT task_id, filename, status, uploaded_at, analyzed_at,
                           file_size_bytes, total_packets, health_score,
                           report_html_path, report_json_path, error_message, owner_id
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
                    uploaded_at=(
                        datetime.fromisoformat(row["uploaded_at"]) if row["uploaded_at"] else datetime.now(timezone.utc)
                    ),
                    analyzed_at=datetime.fromisoformat(row["analyzed_at"]) if row["analyzed_at"] else None,
                    file_size_bytes=row["file_size_bytes"],
                    total_packets=row["total_packets"],
                    health_score=row["health_score"],
                    report_html_url=f"/api/reports/{row['task_id']}/html" if row["report_html_path"] else None,
                    report_json_url=f"/api/reports/{row['task_id']}/json" if row["report_json_path"] else None,
                    error_message=row["error_message"],
                    owner_id=row["owner_id"],
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
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=retention_hours)

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

    async def update_heartbeat(
        self,
        task_id: str,
        progress_percent: Optional[int] = None,
        current_phase: Optional[str] = None,
    ):
        """
        Met à jour le timestamp de heartbeat pour une tâche.

        Args:
            task_id: ID de la tâche
            progress_percent: Pourcentage de progression à mettre à jour (optionnel)
            current_phase: Phase actuelle à mettre à jour (optionnel)
        """
        timestamp = datetime.now(timezone.utc)

        async with aiosqlite.connect(self.db_path) as db:
            if progress_percent is not None and current_phase is not None:
                await db.execute(
                    """
                    UPDATE tasks
                    SET last_heartbeat = ?, progress_percent = ?, current_phase = ?
                    WHERE task_id = ?
                    """,
                    (timestamp, progress_percent, current_phase, task_id),
                )
            elif progress_percent is not None:
                await db.execute(
                    """
                    UPDATE tasks
                    SET last_heartbeat = ?, progress_percent = ?
                    WHERE task_id = ?
                    """,
                    (timestamp, progress_percent, task_id),
                )
            elif current_phase is not None:
                await db.execute(
                    """
                    UPDATE tasks
                    SET last_heartbeat = ?, current_phase = ?
                    WHERE task_id = ?
                    """,
                    (timestamp, current_phase, task_id),
                )
            else:
                await db.execute(
                    "UPDATE tasks SET last_heartbeat = ? WHERE task_id = ?",
                    (timestamp, task_id),
                )
            await db.commit()

        logger.debug(f"Heartbeat updated for task {task_id}")

    async def create_progress_snapshot(
        self,
        task_id: str,
        phase: str,
        progress_percent: int,
        packets_processed: Optional[int] = None,
        total_packets: Optional[int] = None,
        current_analyzer: Optional[str] = None,
        message: Optional[str] = None,
    ):
        """
        Crée un snapshot de progression pour une tâche.

        Args:
            task_id: ID de la tâche
            phase: Phase actuelle (parsing, analysis, report)
            progress_percent: Pourcentage de progression (0-100)
            packets_processed: Nombre de paquets traités
            total_packets: Nombre total de paquets
            current_analyzer: Nom de l'analyseur en cours
            message: Message additionnel
        """
        timestamp = datetime.now(timezone.utc)

        async with aiosqlite.connect(self.db_path) as db:
            # Sauvegarder dans progress_snapshots
            await db.execute(
                """
                INSERT INTO progress_snapshots (
                    task_id, phase, progress_percent, packets_processed,
                    total_packets, current_analyzer, message, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    phase,
                    progress_percent,
                    packets_processed,
                    total_packets,
                    current_analyzer,
                    message,
                    timestamp,
                ),
            )

            # Mettre à jour les champs de progression dans tasks
            await db.execute(
                """
                UPDATE tasks
                SET progress_percent = ?, current_phase = ?
                WHERE task_id = ?
                """,
                (progress_percent, phase, task_id),
            )

            await db.commit()

        logger.debug(f"Progress snapshot created for task {task_id}: {phase} {progress_percent}%")

    async def get_progress_history(self, task_id: str, limit: int = 50) -> list[dict]:
        """
        Récupère l'historique des snapshots de progression pour une tâche.

        Args:
            task_id: ID de la tâche
            limit: Nombre maximum de snapshots à retourner

        Returns:
            Liste de dictionnaires contenant les snapshots de progression
        """
        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT id, task_id, phase, progress_percent, packets_processed,
                       total_packets, current_analyzer, message, timestamp
                FROM progress_snapshots
                WHERE task_id = ?
                ORDER BY timestamp DESC
                LIMIT ?
                """,
                (task_id, limit),
            ) as cursor:
                rows = await cursor.fetchall()

        snapshots = []
        for row in rows:
            snapshots.append(
                {
                    "id": row["id"],
                    "task_id": row["task_id"],
                    "phase": row["phase"],
                    "progress_percent": row["progress_percent"],
                    "packets_processed": row["packets_processed"],
                    "total_packets": row["total_packets"],
                    "current_analyzer": row["current_analyzer"],
                    "message": row["message"],
                    "timestamp": datetime.fromisoformat(row["timestamp"]) if row["timestamp"] else None,
                }
            )

        return snapshots

    async def find_orphaned_tasks(self, heartbeat_timeout_minutes: int = 5) -> list[str]:
        """
        Trouve les tâches marquées PROCESSING mais avec un heartbeat ancien.

        Args:
            heartbeat_timeout_minutes: Minutes depuis le dernier heartbeat pour considérer une tâche orpheline

        Returns:
            Liste des task_ids orphelins
        """
        cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=heartbeat_timeout_minutes)

        async with aiosqlite.connect(self.db_path) as db:
            db.row_factory = aiosqlite.Row
            async with db.execute(
                """
                SELECT task_id
                FROM tasks
                WHERE status = ?
                  AND (last_heartbeat IS NULL OR last_heartbeat < ?)
                """,
                (TaskStatus.PROCESSING.value, cutoff_time),
            ) as cursor:
                rows = await cursor.fetchall()

        orphaned_task_ids = [row["task_id"] for row in rows]

        if orphaned_task_ids:
            logger.warning(f"Found {len(orphaned_task_ids)} orphaned tasks: {orphaned_task_ids}")

        return orphaned_task_ids

    async def mark_task_as_failed_orphan(self, task_id: str):
        """
        Marque une tâche orpheline comme FAILED avec un message d'erreur approprié.

        Args:
            task_id: ID de la tâche à marquer comme orpheline
        """
        error_message = "Task processing failed: worker died or was killed (orphaned task)"
        analyzed_at = datetime.now(timezone.utc)

        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE tasks
                SET status = ?, analyzed_at = ?, error_message = ?
                WHERE task_id = ?
                """,
                (TaskStatus.FAILED.value, analyzed_at, error_message, task_id),
            )
            await db.commit()

        logger.info(f"Marked orphaned task {task_id} as FAILED")


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
