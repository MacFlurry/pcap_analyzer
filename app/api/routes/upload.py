"""
Route pour upload de fichiers PCAP et démarrage d'analyse.
"""

import logging
import os
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from fastapi.responses import JSONResponse

from app.auth import get_current_user
from app.models.schemas import UploadResponse
from app.models.user import User
from app.services.database import get_db_service
from app.services.worker import get_worker
from app.utils.path_validator import validate_filename, validate_path_in_directory

logger = logging.getLogger(__name__)

router = APIRouter()

# Configuration via variables d'environnement
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "500"))
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
UPLOADS_DIR = DATA_DIR / "uploads"


def validate_pcap_file(filename: str, file_size: int) -> None:
    """
    Valide un fichier PCAP uploadé.

    Args:
        filename: Nom du fichier
        file_size: Taille du fichier en octets

    Raises:
        HTTPException: Si la validation échoue
    """
    # Validation 1: Extension
    file_ext = Path(filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Extension non autorisée. Extensions valides: {', '.join(ALLOWED_EXTENSIONS)}",
        )

    # Validation 2: Taille
    max_size_bytes = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if file_size > max_size_bytes:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Fichier trop volumineux. Taille maximale: {MAX_UPLOAD_SIZE_MB} MB",
        )

    if file_size == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Fichier vide",
        )


def validate_pcap_magic_bytes(file_content: bytes) -> None:
    """
    Valide les magic bytes d'un fichier PCAP/PCAPNG.

    Args:
        file_content: Contenu du fichier (premiers octets)

    Raises:
        HTTPException: Si les magic bytes ne correspondent pas
    """
    # Magic bytes PCAP (little-endian et big-endian)
    PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"  # Little-endian
    PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"  # Big-endian

    # Magic bytes PCAPNG
    PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

    if file_content[:4] not in [PCAP_MAGIC_LE, PCAP_MAGIC_BE, PCAPNG_MAGIC]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Format de fichier invalide. Le fichier n'est pas un PCAP/PCAPNG valide.",
        )


@router.post("/upload", response_model=UploadResponse, status_code=status.HTTP_202_ACCEPTED)
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

    # Lire le contenu du fichier
    try:
        content = await file.read()
        file_size = len(content)
    except Exception as e:
        logger.error(f"Error reading uploaded file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la lecture du fichier",
        )

    # Validation: Sanitize filename (path traversal protection)
    sanitized_filename = validate_filename(file.filename)

    # Validation: Size and format
    validate_pcap_file(sanitized_filename, file_size)
    validate_pcap_magic_bytes(content)

    # Générer un task_id unique
    task_id = str(uuid.uuid4())

    # Créer le répertoire uploads si nécessaire
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

    # Sauvegarder le fichier dans uploads/
    upload_path = UPLOADS_DIR / f"{task_id}{Path(sanitized_filename).suffix}"

    # Defense-in-depth: Verify resolved path is within UPLOADS_DIR
    upload_path = validate_path_in_directory(upload_path, UPLOADS_DIR)

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
