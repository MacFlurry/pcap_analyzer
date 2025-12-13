"""
Route pour suivre la progression d'une analyse via Server-Sent Events (SSE).
"""

import asyncio
import json
import logging
from collections.abc import AsyncGenerator

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import StreamingResponse

from app.models.schemas import TaskStatus
from app.services.database import get_db_service
from app.services.worker import get_worker

logger = logging.getLogger(__name__)

router = APIRouter()


async def progress_event_generator(task_id: str) -> AsyncGenerator[str, None]:
    r"""
    Générateur d'événements SSE pour la progression d'une tâche.

    Format SSE:
        data: {"task_id": "...", "phase": "metadata", "progress": 45, ...}\n\n

    Args:
        task_id: ID de la tâche à suivre

    Yields:
        Événements SSE formatés
    """
    db_service = get_db_service()
    worker = get_worker()

    # Vérifier que la tâche existe
    task_info = await db_service.get_task(task_id)
    if not task_info:
        yield f"data: {json.dumps({'error': 'Task not found'})}\n\n"
        return

    logger.info(f"SSE connection established for task {task_id}")

    # Index pour tracking des updates déjà envoyés
    last_update_index = 0

    try:
        while True:
            # Récupérer le statut actuel
            task_info = await db_service.get_task(task_id)

            if not task_info:
                yield f"data: {json.dumps({'error': 'Task not found'})}\n\n"
                break

            # Récupérer les nouveaux updates du worker
            updates = worker.get_progress_updates(task_id)

            # Envoyer les nouveaux updates
            if len(updates) > last_update_index:
                for update in updates[last_update_index:]:
                    event_data = {
                        "task_id": update.task_id,
                        "status": task_info.status.value,
                        "phase": update.phase,
                        "progress_percent": update.progress_percent,
                        "packets_processed": update.packets_processed,
                        "total_packets": update.total_packets,
                        "current_analyzer": update.current_analyzer,
                        "message": update.message,
                        "timestamp": update.timestamp.isoformat(),
                    }
                    yield f"data: {json.dumps(event_data)}\n\n"

                last_update_index = len(updates)

            # Si la tâche est terminée (COMPLETED, FAILED, EXPIRED), envoyer un événement final et fermer
            if task_info.status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.EXPIRED]:
                final_event = {
                    "task_id": task_id,
                    "status": task_info.status.value,
                    "phase": "completed" if task_info.status == TaskStatus.COMPLETED else "failed",
                    "progress_percent": 100 if task_info.status == TaskStatus.COMPLETED else 0,
                    "total_packets": task_info.total_packets,
                    "health_score": task_info.health_score,
                    "report_html_url": task_info.report_html_url,
                    "report_json_url": task_info.report_json_url,
                    "message": (
                        "Analyse terminée avec succès"
                        if task_info.status == TaskStatus.COMPLETED
                        else (task_info.error_message or "Analyse échouée")
                    ),
                }

                # Ajouter l'URL du rapport si disponible
                if task_info.status == TaskStatus.COMPLETED:
                    final_event["report_html_url"] = task_info.report_html_url
                    final_event["report_json_url"] = task_info.report_json_url

                yield f"data: {json.dumps(final_event)}\n\n"

                # Nettoyer les updates du worker
                worker.clear_progress_updates(task_id)

                logger.info(f"SSE connection closed for task {task_id} (status: {task_info.status.value})")
                break

            # Attendre 500ms avant le prochain check
            await asyncio.sleep(0.5)

    except asyncio.CancelledError:
        logger.info(f"SSE connection cancelled for task {task_id}")
        raise
    except Exception as e:
        logger.error(f"Error in SSE stream for task {task_id}: {e}", exc_info=True)
        yield f"data: {json.dumps({'error': str(e)})}\n\n"


@router.get("/progress/{task_id}")
async def get_progress(task_id: str):
    """
    Stream de progression en temps réel via Server-Sent Events.

    Args:
        task_id: ID de la tâche à suivre

    Returns:
        StreamingResponse avec événements SSE

    Raises:
        HTTPException: Si la tâche n'existe pas
    """
    # Vérifier que la tâche existe
    db_service = get_db_service()
    task_info = await db_service.get_task(task_id)

    if not task_info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id} not found",
        )

    logger.info(f"Starting SSE stream for task {task_id}")

    return StreamingResponse(
        progress_event_generator(task_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx buffering
        },
    )


@router.get("/status/{task_id}")
async def get_task_status(task_id: str):
    """
    Récupère le statut actuel d'une tâche (sans SSE).

    Args:
        task_id: ID de la tâche

    Returns:
        Informations sur la tâche

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

    return task_info


@router.get("/history")
async def get_task_history(limit: int = 20):
    """
    Récupère l'historique des tâches récentes.

    Args:
        limit: Nombre maximum de tâches à retourner (défaut: 20)

    Returns:
        Liste des tâches récentes
    """
    db_service = get_db_service()
    tasks = await db_service.get_recent_tasks(limit=limit)

    return {
        "tasks": tasks,
        "count": len(tasks),
    }
