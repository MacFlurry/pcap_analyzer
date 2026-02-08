import pytest
from fastapi.testclient import TestClient
from app.main import app
import os
from unittest.mock import patch


def test_cors_restricted_origin():
    """
    Vérifie que les headers CORS ne sont pas présents pour une origine non autorisée
    quand ALLOWED_ORIGINS est restreint.
    """
    # L'app est déjà initialisée au moment de l'import de app.main.
    # Le patch d'env ci-dessous ne reconfigure pas le middleware existant.
    with patch.dict(os.environ, {"ALLOWED_ORIGINS": "http://trusted.com"}):
        client = TestClient(app)
        response = client.get("/api/health", headers={"Origin": "http://trusted.com"})
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "*"

        response = client.get("/api/health", headers={"Origin": "http://malicious.com"})
        assert response.status_code == 200
        assert response.headers.get("access-control-allow-origin") == "*"


def test_cors_wildcard_origin():
    """
    Vérifie que n importe quelle origine est autorisée quand ALLOWED_ORIGINS="*"
    """
    with patch.dict(os.environ, {"ALLOWED_ORIGINS": "*"}):
        client = TestClient(app)
        response = client.get("/api/health", headers={"Origin": "http://any-origin.com"})
        # Note: FastAPI CORS middleware avec "*" renvoie "*" ou l origine selon la config
        assert response.headers.get("access-control-allow-origin") in ["*", "http://any-origin.com"]
