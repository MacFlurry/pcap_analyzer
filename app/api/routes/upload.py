"""
Route pour upload de fichiers PCAP et démarrage d'analyse.
"""

import logging
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from fastapi.responses import JSONResponse

from app.auth import get_current_user
from app.models.schemas import UploadResponse
from app.models.user import User
from app.security.csrf import validate_csrf_token
from app.services.database import get_db_service
from app.services.worker import get_worker
from app.services.pcap_validator import validate_pcap
from app.utils import file_validator as _file_validator
from app.utils.config import get_uploads_dir
from app.utils.path_validator import validate_filename, validate_path_in_directory
from app.utils.file_validator import validate_pcap_upload_complete
from app.utils.rate_limiter import get_upload_rate_limiter

logger = logging.getLogger(__name__)

router = APIRouter()
# Backward-compat alias used by tests monkeypatching upload size limit.
MAX_UPLOAD_SIZE_MB = _file_validator.MAX_UPLOAD_SIZE_MB


async def enforce_upload_rate_limit(request: Request):
    """
    Enforce upload rate limiting before CSRF/auth checks.
    """
    client_ip = request.client.host if request.client else "unknown"
    limiter = get_upload_rate_limiter()
    allowed, retry_after = limiter.check(client_ip)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Upload rate limit exceeded. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )

@router.post(
    "/upload",
    response_model=UploadResponse,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(enforce_upload_rate_limit), Depends(validate_csrf_token)],
)
async def upload_pcap(
    file: UploadFile = File(...),  # noqa: B008
    current_user: User = Depends(get_current_user),
):
    """
    Upload un fichier PCAP et démarre l'analyse en arrière-plan.

    **Authentification requise**: Bearer token dans Authorization header

    Args:
        file: Fichier PCAP uploadé (multipart/form-data)
        current_user: Current authenticated user (from JWT token)

    Returns:
        UploadResponse avec task_id et URL de progression

    Raises:
        HTTPException 401: If not authenticated
        HTTPException 400: Si la validation échoue
        HTTPException 503: Si la queue est pleine
    """
    logger.info(f"Upload request received: {file.filename} ({file.content_type})")

    # Validation Step 1: Sanitize filename (path traversal protection)
    sanitized_filename = validate_filename(file.filename)

    # Validation Step 2: Stream-based validation (size + magic + decompression bomb)
    # This replaces the old vulnerable pattern of reading entire file then validating
    try:
        content, pcap_type = await validate_pcap_upload_complete(file)
        file_size = len(content)
        logger.info(f"Upload validated: {sanitized_filename}, size: {file_size} bytes, type: {pcap_type}")
    except HTTPException:
        # Re-raise validation errors (400, 413)
        raise
    except Exception as e:
        logger.error(f"Error during upload validation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la validation du fichier",
        )

    # Générer un task_id unique
    task_id = str(uuid.uuid4())

    # Récupérer les répertoires dynamiquement (pour supporter les tests)
    uploads_dir = get_uploads_dir()

    # Créer le répertoire uploads si nécessaire
    uploads_dir.mkdir(parents=True, exist_ok=True)

    # Sauvegarder le fichier dans uploads/
    upload_path = uploads_dir / f"{task_id}{Path(sanitized_filename).suffix}"

    # Defense-in-depth: Verify resolved path is within uploads_dir
    upload_path = validate_path_in_directory(upload_path, uploads_dir)

    try:
        with open(upload_path, "wb") as f:
            f.write(content)
        logger.info(f"File saved: {upload_path} ({file_size} bytes)")
    except Exception as e:
        logger.error(f"Error saving file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la sauvegarde du fichier",
        )

    # NEW: Validate PCAP before queuing analysis
    is_valid, validation_error = validate_pcap(str(upload_path))

    if not is_valid:
        # Delete the uploaded file
        upload_path.unlink(missing_ok=True)
        logger.warning(f"PCAP validation failed for {file.filename}: {validation_error.error_type}")

        # Return structured error response
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": "PCAP validation failed",
                "validation_details": validation_error.to_dict()
            }
        )

    # Créer l'entrée dans la base de données (with owner_id for multi-tenant)
    db_service = get_db_service()
    try:
        task_info = await db_service.create_task(
            task_id=task_id,
            filename=file.filename,
            file_size_bytes=file_size,
            owner_id=current_user.id,
        )
    except Exception as e:
        logger.error(f"Error creating task in database: {e}")
        # Nettoyer le fichier uploadé
        upload_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la création de la tâche",
        )

    # Ajouter à la queue du worker
    worker = get_worker()
    enqueued = await worker.enqueue(task_id, str(upload_path))

    if not enqueued:
        # Queue pleine
        logger.warning(f"Queue full, cannot process task {task_id}")
        await db_service.update_status(task_id, "failed", error_message="Queue pleine, réessayez plus tard")
        upload_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Serveur occupé. Queue pleine ({worker.get_queue_size()}/{5}). Réessayez plus tard.",
        )

    logger.info(f"Task {task_id} enqueued successfully")

    # Retourner la réponse
    return UploadResponse(
        task_id=task_id,
        filename=file.filename,
        file_size_bytes=file_size,
        status=task_info.status,
        progress_url=f"/api/progress/{task_id}",
    )


@router.get("/queue/status")
async def get_queue_status(current_user: User = Depends(get_current_user)):
    """
    Retourne le statut de la queue de traitement.

    **Authentification requise**: Bearer token dans Authorization header

    Args:
        current_user: Current authenticated user

    Returns:
        Informations sur la queue et statistiques globales
    """
    worker = get_worker()
    db_service = get_db_service()

    stats = await db_service.get_stats()

    return {
        "queue_size": worker.get_queue_size(),
        "max_queue_size": 5,
        "queue_available": 5 - worker.get_queue_size(),
        "total_tasks": stats["total"],
        "tasks_pending": stats["pending"],
        "tasks_processing": stats["processing"],
        "tasks_completed": stats["completed"],
        "tasks_failed": stats["failed"],
    }
