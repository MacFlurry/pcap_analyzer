"""
Route pour servir les rapports d'analyse (HTML et JSON).
"""

import logging
import os
from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse

from app.services.database import get_db_service

logger = logging.getLogger(__name__)

router = APIRouter()

# Configuration
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
REPORTS_DIR = DATA_DIR / "reports"


@router.get("/reports/{task_id}/html")
async def get_html_report(task_id: str):
    """
    Récupère le rapport HTML d'une analyse.

    Args:
        task_id: ID de la tâche

    Returns:
        Fichier HTML du rapport

    Raises:
        HTTPException: Si la tâche ou le rapport n'existe pas
    """
    db_service = get_db_service()
    task_info = await db_service.get_task(task_id)

    if not task_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id} not found",
        )

    # Vérifier que le rapport existe
    html_path = REPORTS_DIR / f"{task_id}.html"

    if not html_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rapport HTML non trouvé. L'analyse est peut-être en cours.",
        )

    logger.info(f"Serving HTML report for task {task_id}: {html_path}")

    return FileResponse(
        path=html_path,
        media_type="text/html",
        headers={"Content-Disposition": f'inline; filename="pcap_analysis_{task_id}.html"'},
    )


@router.get("/reports/{task_id}/json")
async def get_json_report(task_id: str):
    """
    Récupère le rapport JSON d'une analyse.

    Args:
        task_id: ID de la tâche

    Returns:
        Données JSON du rapport

    Raises:
        HTTPException: Si la tâche ou le rapport n'existe pas
    """
    db_service = get_db_service()
    task_info = await db_service.get_task(task_id)

    if not task_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id} not found",
        )

    # Vérifier que le rapport existe
    json_path = REPORTS_DIR / f"{task_id}.json"

    if not json_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rapport JSON non trouvé. L'analyse est peut-être en cours.",
        )

    logger.info(f"Serving JSON report for task {task_id}: {json_path}")

    return FileResponse(
        path=json_path,
        media_type="application/json",
        filename=f"pcap_analysis_{task_id}.json",
    )


@router.delete("/reports/{task_id}")
async def delete_report(task_id: str):
    """
    Supprime les rapports d'une tâche (HTML et JSON).

    Args:
        task_id: ID de la tâche

    Returns:
        Message de confirmation

    Raises:
        HTTPException: Si la tâche n'existe pas
    """
    db_service = get_db_service()
    task_info = await db_service.get_task(task_id)

    if not task_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id} not found",
        )

    # Supprimer les fichiers
    html_path = REPORTS_DIR / f"{task_id}.html"
    json_path = REPORTS_DIR / f"{task_id}.json"

    deleted_files = []

    if html_path.exists():
        html_path.unlink()
        deleted_files.append("HTML")
        logger.info(f"Deleted HTML report: {html_path}")

    if json_path.exists():
        json_path.unlink()
        deleted_files.append("JSON")
        logger.info(f"Deleted JSON report: {json_path}")

    # Marquer la tâche comme expirée
    from app.models.schemas import TaskStatus

    await db_service.update_status(task_id, TaskStatus.EXPIRED)

    return {
        "message": f"Reports deleted for task {task_id}",
        "deleted_files": deleted_files,
        "task_id": task_id,
    }
