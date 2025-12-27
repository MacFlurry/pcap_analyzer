"""
Pydantic schemas pour validation et sérialisation
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, validator


class TaskStatus(str, Enum):
    """Statut d'une tâche d'analyse"""

    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"


class UploadResponse(BaseModel):
    """Réponse après upload de fichier PCAP"""

    task_id: str = Field(..., description="ID unique de la tâche d'analyse")
    filename: str = Field(..., description="Nom du fichier uploadé")
    file_size_bytes: int = Field(..., description="Taille du fichier en octets")
    status: TaskStatus = Field(TaskStatus.PENDING, description="Statut initial")
    progress_url: str = Field(..., description="URL pour suivre la progression (SSE)")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ProgressUpdate(BaseModel):
    """Mise à jour de progression (envoyé via SSE)"""

    task_id: str
    status: TaskStatus
    phase: Optional[str] = None  # "metadata", "analysis", "finalize"
    progress_percent: int = Field(0, ge=0, le=100)
    packets_processed: Optional[int] = None
    total_packets: Optional[int] = None
    current_analyzer: Optional[str] = None
    message: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TaskInfo(BaseModel):
    """Informations sur une tâche (pour historique)"""

    task_id: str
    filename: str
    status: TaskStatus
    uploaded_at: datetime
    analyzed_at: Optional[datetime] = None
    file_size_bytes: int
    total_packets: Optional[int] = None
    health_score: Optional[float] = None
    report_html_url: Optional[str] = None
    report_json_url: Optional[str] = None
    error_message: Optional[str] = None  # Message d'erreur si échec
    expires_at: Optional[datetime] = None  # Date d'expiration (uploaded_at + 24h)
    owner_id: Optional[str] = None  # User ID (multi-tenant)
    owner_username: Optional[str] = None  # Username du propriétaire (pour admins)

    @validator("expires_at", always=True)
    def calculate_expiry(cls, v, values):
        """Calcule la date d'expiration si non fournie"""
        if v is None and "uploaded_at" in values:
            from datetime import timedelta

            return values["uploaded_at"] + timedelta(hours=24)
        return v


class HealthCheck(BaseModel):
    """Réponse du health check endpoint"""

    status: str = "healthy"
    version: str = "1.0.0"
    uptime_seconds: float
    active_analyses: int = 0
    queue_size: int = 0
    disk_space_gb_available: float
    memory_usage_percent: float
    total_tasks_completed: int = 0
    total_tasks_failed: int = 0


class PCAPValidationErrorDetail(BaseModel):
    """Detailed PCAP validation error"""

    error_type: str  # "INVALID_TIMESTAMPS", "DUPLICATE_PACKETS", etc.
    title: str  # "Timestamps incohérents détectés"
    description: str  # Detailed explanation
    detected_issues: list[str]  # Bullet points of specific issues
    suggestions: list[str]  # What user should do
    wireshark_link: str = "https://www.wireshark.org/download.html"


class UploadErrorResponse(BaseModel):
    """Upload error response"""

    success: bool = False
    error: str  # Short error message
    validation_details: Optional[PCAPValidationErrorDetail] = None
