"""
Routes pour servir les pages HTML (templates Jinja2)
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from app.auth import get_current_user_cookie_or_redirect
from src.__version__ import __version__

logger = logging.getLogger(__name__)

router = APIRouter()

# Configure Jinja2 templates
templates_dir = Path(__file__).parent.parent.parent / "templates"
templates = Jinja2Templates(directory=str(templates_dir))


@router.get("/", response_class=HTMLResponse)
async def index(request: Request, user=Depends(get_current_user_cookie_or_redirect)):
    """
    Page d'accueil - Upload PCAP
    """
    return templates.TemplateResponse("upload.html", {"request": request, "version": __version__})


@router.get("/progress/{task_id}", response_class=HTMLResponse)
async def progress(request: Request, task_id: str, user=Depends(get_current_user_cookie_or_redirect)):
    """
    Page de progression d'analyse
    """
    return templates.TemplateResponse("progress.html", {"request": request, "task_id": task_id, "version": __version__})


@router.get("/history", response_class=HTMLResponse)
async def history(request: Request, user=Depends(get_current_user_cookie_or_redirect)):
    """
    Page d'historique des analyses
    """
    return templates.TemplateResponse("history.html", {"request": request, "version": __version__})


@router.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    """
    Page de connexion
    """
    return templates.TemplateResponse("login.html", {"request": request, "version": __version__})


@router.get("/logout", response_class=HTMLResponse)
async def logout(request: Request):
    """
    Page de déconnexion (efface le localStorage)
    """
    return templates.TemplateResponse("logout.html", {"request": request, "version": __version__})


@router.get("/admin", response_class=HTMLResponse)
async def admin(request: Request, user=Depends(get_current_user_cookie_or_redirect)):
    """
    Page d'administration (admin only)
    Gestion des utilisateurs et permissions
    """
    return templates.TemplateResponse("admin.html", {"request": request, "version": __version__})


@router.get("/change-password", response_class=HTMLResponse)
async def change_password(request: Request, user=Depends(get_current_user_cookie_or_redirect)):
    """
    Page de changement de mot de passe obligatoire
    Affichée quand password_must_change=True
    """
    return templates.TemplateResponse("change-password.html", {"request": request, "version": __version__})


@router.get("/register", response_class=HTMLResponse)
async def register(request: Request):
    """
    Page d'inscription (user registration)
    """
    return templates.TemplateResponse("register.html", {"request": request, "version": __version__})


@router.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, user=Depends(get_current_user_cookie_or_redirect)):
    """
    Page de profil utilisateur (2FA, etc.)
    """
    return templates.TemplateResponse("profile.html", {"request": request, "version": __version__})

