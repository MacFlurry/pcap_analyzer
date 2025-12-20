"""
PCAP Analyzer Web API - Main FastAPI Application
"""

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import auth, health, progress, reports, upload, views
from app.services.cleanup import CleanupScheduler
from app.services.database import get_db_service
from app.services.user_database import get_user_db_service
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

    # Initialiser la base de données utilisateurs
    user_db_service = get_user_db_service()
    await user_db_service.init_db()
    logger.info("User database initialized")

    # Migrer la table tasks pour ajouter owner_id (multi-tenant)
    await user_db_service.migrate_tasks_table()

    # Créer compte admin brise-glace si aucun admin n'existe
    admin_password = await user_db_service.create_admin_breakglass_if_not_exists()
    if admin_password:
        # Password logged by user_database.py with warnings
        pass

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
    docs_url=None,  # Désactiver le /docs par défaut pour le customiser
    redoc_url=None,  # Pas besoin de ReDoc
    swagger_ui_parameters={
        "defaultModelsExpandDepth": -1,  # Cache les schemas par défaut
        "docExpansion": "list",  # Liste les endpoints sans les expandre
        "filter": True,  # Ajoute une barre de recherche
        "syntaxHighlight.theme": "monokai",  # Theme de coloration syntaxique
    },
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
app.include_router(auth.router)  # Auth router has its own prefix
app.include_router(health.router, prefix="/api", tags=["health"])
app.include_router(upload.router, prefix="/api", tags=["upload"])
app.include_router(progress.router, prefix="/api", tags=["progress"])
app.include_router(reports.router, prefix="/api", tags=["reports"])

# Inclusion des routes views (HTML templates)
app.include_router(views.router, tags=["views"])


# Documentation Swagger customisée
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    """Documentation API Swagger avec thème personnalisé"""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>{app.title} - Documentation</title>
        <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css" />
        <link rel="stylesheet" type="text/css" href="/swagger-custom.css" />
        <style>
            body {{
                margin: 0;
                padding: 0;
            }}
        </style>
    </head>
    <body>
        <div id="swagger-ui"></div>
        <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
        <script>
            window.onload = function() {{
                window.ui = SwaggerUIBundle({{
                    url: '{app.openapi_url}',
                    dom_id: '#swagger-ui',
                    deepLinking: true,
                    presets: [
                        SwaggerUIBundle.presets.apis,
                        SwaggerUIBundle.SwaggerUIStandalonePreset
                    ],
                    layout: "BaseLayout",
                    defaultModelsExpandDepth: -1,
                    docExpansion: "list",
                    filter: true,
                    syntaxHighlight: {{
                        theme: "monokai"
                    }}
                }})
            }}
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


# Route pour injecter du CSS custom
@app.get("/swagger-custom.css", include_in_schema=False)
async def swagger_custom_css():
    """CSS personnalisé pour Swagger UI avec thème PCAP Analyzer"""
    custom_css = """
    /* Theme PCAP Analyzer - Purple/Blue Gradient */

    /* Topbar avec gradient */
    .swagger-ui .topbar {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
        border-bottom: 3px solid #667eea !important;
    }

    .swagger-ui .topbar .download-url-wrapper {
        display: none;
    }

    /* Améliorer la lisibilité des boutons Collapse/Expand */
    .swagger-ui .btn.expand-operation,
    .swagger-ui .btn.collapse-operation,
    .swagger-ui .expand-methods,
    .swagger-ui .expand-methods svg {
        color: #667eea !important;
        fill: #667eea !important;
        font-weight: 600 !important;
        font-size: 14px !important;
    }

    .swagger-ui .btn.expand-operation:hover,
    .swagger-ui .btn.collapse-operation:hover {
        color: #764ba2 !important;
    }

    /* Section Models/Schemas */
    .swagger-ui .models {
        border: 2px solid #667eea !important;
        border-radius: 8px !important;
        margin-top: 20px !important;
    }

    .swagger-ui .model-box {
        background: #f8f9fa !important;
        border-radius: 6px !important;
    }

    .swagger-ui .models h4 {
        color: #667eea !important;
        font-weight: 700 !important;
        border-bottom: 2px solid #667eea !important;
        padding-bottom: 10px !important;
    }

    /* Boutons expand/collapse dans les schemas */
    .swagger-ui .model-toggle {
        color: #667eea !important;
        font-weight: 600 !important;
    }

    .swagger-ui .model-toggle:hover {
        color: #764ba2 !important;
    }

    .swagger-ui .model-toggle::after {
        background: #667eea !important;
    }

    /* Améliorer la visibilité des propriétés */
    .swagger-ui .model-title {
        color: #2c3e50 !important;
        font-weight: 600 !important;
    }

    .swagger-ui .property-row {
        border-left: 3px solid #e0e7ff !important;
        padding-left: 10px !important;
        margin: 5px 0 !important;
    }

    /* Endpoints avec gradient au survol */
    .swagger-ui .opblock {
        border-radius: 8px !important;
        border: 1px solid #e5e7eb !important;
        margin-bottom: 10px !important;
    }

    .swagger-ui .opblock:hover {
        box-shadow: 0 4px 6px rgba(102, 126, 234, 0.1) !important;
    }

    .swagger-ui .opblock.opblock-post {
        border-color: #667eea !important;
        background: rgba(102, 126, 234, 0.05) !important;
    }

    .swagger-ui .opblock.opblock-get {
        border-color: #667eea !important;
        background: rgba(102, 126, 234, 0.03) !important;
    }

    .swagger-ui .opblock.opblock-delete {
        border-color: #e74c3c !important;
        background: rgba(231, 76, 60, 0.03) !important;
    }

    /* Bouton Try it out */
    .swagger-ui .btn.try-out__btn {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
        color: white !important;
        border: none !important;
        font-weight: 600 !important;
        padding: 8px 20px !important;
        border-radius: 6px !important;
    }

    .swagger-ui .btn.try-out__btn:hover {
        transform: translateY(-1px) !important;
        box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3) !important;
    }

    .swagger-ui .btn.execute {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
        color: white !important;
        border: none !important;
        font-weight: 600 !important;
    }

    /* Améliorer le contraste des textes */
    .swagger-ui .opblock-summary-description {
        color: #374151 !important;
        font-weight: 500 !important;
    }

    .swagger-ui .parameter__name {
        color: #667eea !important;
        font-weight: 600 !important;
    }

    /* Réponses */
    .swagger-ui .responses-inner h4,
    .swagger-ui .responses-inner h5 {
        color: #667eea !important;
        font-weight: 600 !important;
    }

    /* Authorize button */
    .swagger-ui .btn.authorize {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
        color: white !important;
        border: none !important;
    }

    /* Information section */
    .swagger-ui .info {
        margin: 30px 0 !important;
    }

    .swagger-ui .info .title {
        color: #667eea !important;
        font-size: 36px !important;
        font-weight: 700 !important;
    }

    .swagger-ui .info .description {
        color: #6b7280 !important;
        font-size: 16px !important;
        line-height: 1.6 !important;
    }

    /* Scrollbar custom */
    ::-webkit-scrollbar {
        width: 10px !important;
    }

    ::-webkit-scrollbar-track {
        background: #f1f1f1 !important;
    }

    ::-webkit-scrollbar-thumb {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
        border-radius: 5px !important;
    }

    ::-webkit-scrollbar-thumb:hover {
        background: #764ba2 !important;
    }
    """
    return HTMLResponse(content=custom_css, media_type="text/css")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,  # Dev uniquement
        log_level="info",
    )
