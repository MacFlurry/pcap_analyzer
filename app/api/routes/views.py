"""
Routes pour servir les pages HTML (templates Jinja2)
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

logger = logging.getLogger(__name__)

router = APIRouter()

# Configure Jinja2 templates
templates_dir = Path(__file__).parent.parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """
    Page d'accueil - Upload PCAP
    """
    return templates.TemplateResponse("upload.html", {"request": request})


@router.get("/progress/{task_id}", response_class=HTMLResponse)
async def progress(request: Request, task_id: str):
    """
    Page de progression d'analyse
    """
    return templates.TemplateResponse("progress.html", {"request": request, "task_id": task_id})


@router.get("/history", response_class=HTMLResponse)
async def history(request: Request):
    """
    Page d'historique des analyses
    """
    return templates.TemplateResponse("history.html", {"request": request})


@router.get("/test-loading", response_class=HTMLResponse)
async def test_loading(request: Request):
    """
    Page de test pour l'overlay de chargement
    """
    return templates.TemplateResponse("test_loading.html", {"request": request})


@router.get("/loading-showcase", response_class=HTMLResponse)
async def loading_showcase(request: Request):
    """
    Showcase du design de l'overlay de chargement
    """
    return templates.TemplateResponse("loading_showcase.html", {"request": request})
