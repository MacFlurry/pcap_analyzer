"""
PCAP Analyzer Web API - Main FastAPI Application
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import health, progress, reports, upload, views
from app.services.cleanup import CleanupScheduler
from app.services.database import get_db_service
from app.services.worker import get_worker

# Configuration logging
logging.basicConfig(
    level=logging.INFO,
    format='{"timestamp": "%(asctime)s", "level": "%(levelname)s", "message": "%(message)s"}',
)
logger = logging.getLogger(__name__)

# Démarrage/arrêt cleanup scheduler
data_dir = os.getenv("DATA_DIR", "/data")
retention_hours = int(os.getenv("REPORT_TTL_HOURS", "24"))
cleanup_scheduler = CleanupScheduler(data_dir=data_dir, retention_hours=retention_hours)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Lifespan context manager pour démarrage/arrêt de l'application.
    Démarre le scheduler de cleanup au démarrage, l'arrête à la fin.
    """
    logger.info("Starting PCAP Analyzer Web API")

    # Initialiser la base de données
    db_service = get_db_service()
    await db_service.init_db()
    logger.info("Database initialized")

    # Démarrer le worker d'analyse
    worker = get_worker()
    await worker.start()
    logger.info("Analysis worker started")

    # Démarrer cleanup scheduler
    cleanup_scheduler.start()
    logger.info("Cleanup scheduler started")

    yield

    # Arrêter le worker
    await worker.stop()
    logger.info("Analysis worker stopped")

    # Arrêter cleanup scheduler
    cleanup_scheduler.stop()
    logger.info("Cleanup scheduler stopped")
    logger.info("PCAP Analyzer Web API shutdown complete")


# Création application FastAPI
app = FastAPI(
    title="PCAP Analyzer Web API",
    description="Interface web pour l'analyse automatisée de fichiers PCAP",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS middleware (à configurer selon environnement)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # TODO: Restreindre en production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Montage fichiers statiques
static_path = Path(__file__).parent / "static"
if static_path.exists():
    app.mount("/static", StaticFiles(directory=str(static_path)), name="static")

# Inclusion des routes API
app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(upload.router, prefix="/api", tags=["upload"])
app.include_router(progress.router, prefix="/api", tags=["progress"])
app.include_router(reports.router, prefix="/api", tags=["reports"])

# Inclusion des routes views (HTML templates)
app.include_router(views.router, tags=["views"])


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Dev uniquement
        log_level="info",
    )
