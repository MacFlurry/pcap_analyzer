"""
Route pour servir les rapports d'analyse (HTML et JSON).
"""

import logging
import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse

from app.auth import get_current_user, get_current_user_sse, verify_ownership
from app.models.user import User
from app.services.database import get_db_service
from app.utils.path_validator import validate_task_id, validate_path_in_directory

logger = logging.getLogger(__name__)

router = APIRouter()

# Configuration
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
REPORTS_DIR = DATA_DIR / "reports"


@router.get("/reports/{task_id}/html")
async def get_html_report(task_id: str, current_user: User = Depends(get_current_user_sse)):
    """
    Récupère le rapport HTML d'une analyse.

    **Authentification requise**: Bearer token in query param ?token=xxx OR Authorization header
    **Multi-tenant**: Users can only access their own reports (admins can access all)

    Args:
        task_id: ID de la tâche
        current_user: Current authenticated user

    Returns:
        Fichier HTML du rapport

    Raises:
        HTTPException 401: If not authenticated
        HTTPException 403: If user doesn't own the task
        HTTPException 404: Si la tâche ou le rapport n'existe pas

    Note:
        Token can be passed via query param for browser navigation compatibility.
    """
    # Validate task_id format (UUID v4) to prevent path traversal
    task_id = validate_task_id(task_id)

    db_service = get_db_service()
    task_info = await db_service.get_task(task_id)

    if not task_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id} not found",
        )

    # Vérifier ownership (multi-tenant: users see only own tasks, admin sees all)
    if not verify_ownership(current_user, task_info.owner_id):
        logger.warning(f"User {current_user.username} attempted to access task {task_id} (owner: {task_info.owner_id})")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you can only access your own reports",
        )

    # Vérifier que le rapport existe
    html_path = REPORTS_DIR / f"{task_id}.html"

    # Defense-in-depth: Verify resolved path is within REPORTS_DIR
    html_path = validate_path_in_directory(html_path, REPORTS_DIR)

    if not html_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rapport HTML non trouvé. L'analyse est peut-être en cours.",
        )

    logger.info(f"User {current_user.username} serving HTML report for task {task_id}: {html_path}")

    return FileResponse(
        path=html_path,
        media_type="text/html",
        headers={"Content-Disposition": f'inline; filename="pcap_analysis_{task_id}.html"'},
    )


@router.get("/reports/{task_id}/json")
async def get_json_report(task_id: str, current_user: User = Depends(get_current_user_sse)):
    """
    Récupère le rapport JSON d'une analyse.

    **Authentification requise**: Bearer token in query param ?token=xxx OR Authorization header
    **Multi-tenant**: Users can only access their own reports (admins can access all)

    Args:
        task_id: ID de la tâche
        current_user: Current authenticated user

    Returns:
        Données JSON du rapport

    Raises:
        HTTPException 401: If not authenticated
        HTTPException 403: If user doesn't own the task
        HTTPException 404: Si la tâche ou le rapport n'existe pas
    """
    # Validate task_id format (UUID v4) to prevent path traversal
    task_id = validate_task_id(task_id)

    db_service = get_db_service()
    task_info = await db_service.get_task(task_id)

    if not task_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id} not found",
        )

    # Vérifier ownership (multi-tenant)
    if not verify_ownership(current_user, task_info.owner_id):
        logger.warning(f"User {current_user.username} attempted to access task {task_id} (owner: {task_info.owner_id})")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you can only access your own reports",
        )

    # Vérifier que le rapport existe
    json_path = REPORTS_DIR / f"{task_id}.json"

    # Defense-in-depth: Verify resolved path is within REPORTS_DIR
    json_path = validate_path_in_directory(json_path, REPORTS_DIR)

    if not json_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Rapport JSON non trouvé. L'analyse est peut-être en cours.",
        )

    logger.info(f"User {current_user.username} serving JSON report for task {task_id}: {json_path}")

    return FileResponse(
        path=json_path,
        media_type="application/json",
        filename=f"pcap_analysis_{task_id}.json",
    )


@router.delete("/reports/{task_id}")
async def delete_report(task_id: str, current_user: User = Depends(get_current_user)):
    """
    Supprime les rapports d'une tâche (HTML et JSON).

    **Authentification requise**: Bearer token dans Authorization header
    **Multi-tenant**: Users can only delete their own reports (admins can delete all)

    Args:
        task_id: ID de la tâche
        current_user: Current authenticated user

    Returns:
        Message de confirmation

    Raises:
        HTTPException 401: If not authenticated
        HTTPException 403: If user doesn't own the task
        HTTPException 404: Si la tâche n'existe pas
    """
    # Validate task_id format (UUID v4) to prevent path traversal
    task_id = validate_task_id(task_id)

    db_service = get_db_service()
    task_info = await db_service.get_task(task_id)

    if not task_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id} not found",
        )

    # Vérifier ownership (multi-tenant)
    if not verify_ownership(current_user, task_info.owner_id):
        logger.warning(f"User {current_user.username} attempted to delete task {task_id} (owner: {task_info.owner_id})")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: you can only delete your own reports",
        )

    # Supprimer les fichiers
    html_path = REPORTS_DIR / f"{task_id}.html"
    json_path = REPORTS_DIR / f"{task_id}.json"

    # Defense-in-depth: Verify resolved paths are within REPORTS_DIR
    html_path = validate_path_in_directory(html_path, REPORTS_DIR)
    json_path = validate_path_in_directory(json_path, REPORTS_DIR)

    deleted_files = []

    if html_path.exists():
        html_path.unlink()
        deleted_files.append("HTML")
        logger.info(f"User {current_user.username} deleted HTML report: {html_path}")

    if json_path.exists():
        json_path.unlink()
        deleted_files.append("JSON")
        logger.info(f"User {current_user.username} deleted JSON report: {json_path}")

    # Marquer la tâche comme expirée
    from app.models.schemas import TaskStatus

    await db_service.update_status(task_id, TaskStatus.EXPIRED)

    return {
        "message": f"Reports deleted for task {task_id}",
        "deleted_files": deleted_files,
        "task_id": task_id,
    }
