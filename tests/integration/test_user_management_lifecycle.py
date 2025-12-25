import pytest
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, ANY
from fastapi import status
from app.models.user import UserRole

@pytest.mark.asyncio
async def test_user_lifecycle_with_files_and_emails(
    api_client, user_db, tmp_path
):
    """
    Test complet du cycle de vie utilisateur:
    1. Inscription (vérifie email)
    2. Approbation (vérifie email)
    3. Création de fichiers fictifs pour l'utilisateur
    4. Suppression de l'utilisateur (vérifie suppression fichiers)
    """
    from app.auth import create_access_token
    from app.models.user import UserCreate
    from app.main import app
    from app.services.email_service import get_email_service
    
    # Create admin user for the headers
    admin_data = UserCreate(username="admin_test", email="admin@example.com", password="AdminPassword123!")
    admin_user = await user_db.create_user(admin_data, role=UserRole.ADMIN, auto_approve=True)
    token = create_access_token(admin_user)
    admin_headers = {"Authorization": f"Bearer {token}"}
    
    # Mock EmailService and BackgroundTasks
    mock_email_service = MagicMock()
    app.dependency_overrides[get_email_service] = lambda: mock_email_service
    
    try:
        with patch("app.api.routes.auth.BackgroundTasks.add_task") as mock_add_task:
            # 1. Registration
            reg_data = {
                "username": "lifecycle_user",
                "email": "lifecycle@example.com",
                "password": "SecurePassword123!"
            }
            resp = await api_client.post("/api/register", json=reg_data)
            assert resp.status_code == status.HTTP_201_CREATED
            user_id = resp.json()["id"]
            
            # Vérifie que l'email d'inscription a été planifié
            mock_add_task.assert_any_call(mock_email_service.send_registration_email, ANY)
            
            # 2. Approval
            resp = await api_client.put(f"/api/admin/users/{user_id}/approve", headers=admin_headers)
            assert resp.status_code == status.HTTP_200_OK
            
            # Vérifie que l'email d'approbation a été planifié
            mock_add_task.assert_any_call(mock_email_service.send_approval_email, ANY, "admin_test")
            
            # 3. Simuler des fichiers sur le disque
            data_dir = tmp_path / "data"
            uploads_dir = data_dir / "uploads"
            reports_dir = data_dir / "reports"
            uploads_dir.mkdir(parents=True)
            reports_dir.mkdir(parents=True)
            
            task_id = "mock-task-uuid"
            pcap_file = uploads_dir / f"{task_id}.pcap"
            pcap_file.write_text("fake pcap")
            
            html_report = reports_dir / f"{task_id}.html"
            html_report.write_text("fake report")
            
            # Injecter DATA_DIR dans l'environnement pour le test
            with patch.dict(os.environ, {"DATA_DIR": str(data_dir)}):
                # On doit aussi s'assurer que db_service.get_recent_tasks retourne notre mock-task-uuid
                with patch("app.api.routes.auth.get_db_service") as mock_get_db:
                    mock_db = MagicMock()
                    mock_task = MagicMock()
                    mock_task.task_id = task_id
                    mock_db.get_recent_tasks = AsyncMock(return_value=[mock_task])
                    mock_get_db.return_value = mock_db
                    
                    # 4. Suppression de l'utilisateur
                    resp = await api_client.delete(f"/api/admin/users/{user_id}", headers=admin_headers)
                    assert resp.status_code == status.HTTP_200_OK
                    
                    # Vérifier que les fichiers ont été supprimés
                    assert not pcap_file.exists()
                    assert not html_report.exists()
                    
                    # Vérifier les stats dans la réponse
                    data = resp.json()
                    assert data["files_deleted"]["uploads"] == 1
                    assert data["files_deleted"]["reports"] == 1
    finally:
        app.dependency_overrides.clear()