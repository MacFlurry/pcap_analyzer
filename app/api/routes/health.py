"""
Health check endpoint pour monitoring
"""

import logging
import os
import time
from pathlib import Path

import psutil
from fastapi import APIRouter

from app.models.schemas import HealthCheck
from app.services.database import get_db_service
from app.services.worker import get_worker
from src.__version__ import __version__

logger = logging.getLogger(__name__)
router = APIRouter()

# Temps de démarrage pour calcul uptime
start_time = time.time()

# Configuration
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))


@router.get("/health", response_model=HealthCheck)
async def health_check():
    """
    Health check endpoint pour monitoring de l'application.

    Retourne:
    - Statut de l'application
    - Uptime
    - Statistiques mémoire
    - Espace disque disponible
    - Nombre d'analyses actives
    """
    try:
        # Uptime
        uptime = time.time() - start_time

        # Statistiques mémoire
        memory = psutil.virtual_memory()

        # Espace disque (répertoire DATA_DIR)
        if DATA_DIR.exists():
            disk = psutil.disk_usage(str(DATA_DIR))
            disk_available_gb = disk.free / (1024**3)
        else:
            disk_available_gb = 0.0

        # Récupérer stats depuis worker et database
        worker = get_worker()
        db_service = get_db_service()
        stats = await db_service.get_stats()

        return HealthCheck(
            status="healthy",
            version=__version__,
            uptime_seconds=uptime,
            active_analyses=stats.get("processing", 0),
            queue_size=worker.get_queue_size(),
            disk_space_gb_available=disk_available_gb,
            memory_usage_percent=memory.percent,
            total_tasks_completed=stats.get("completed", 0),
            total_tasks_failed=stats.get("failed", 0),
        )

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return HealthCheck(
            status="unhealthy",
            version=__version__,
            uptime_seconds=time.time() - start_time,
            active_analyses=0,
            queue_size=0,
            disk_space_gb_available=0.0,
            memory_usage_percent=0.0,
        )
