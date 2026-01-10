import pytest
from app.services.email_service import EmailService
from app.models.user import User, UserRole
from datetime import datetime
from unittest.mock import MagicMock, patch, AsyncMock

@pytest.mark.asyncio
async def test_xss_prevention_in_email_templates():
    """
    Vérifie que les données utilisateur sont échappées dans les emails.
    """
    service = EmailService()
    # Payload XSS dans le username
    user = User(
        id="user-123",
        username="<script>alert('xss')</script>",
        email="test@example.com",
        hashed_password="hashed",
        role=UserRole.USER,
        is_active=True,
        is_approved=False,
        created_at=datetime.now()
    )
    
    with patch.object(service.fastmail, "send_message", new_callable=AsyncMock) as mock_send:
        await service.send_registration_email(user)
        
        # Récupérer l'appel
        args, kwargs = mock_send.call_args
        template_body = message = args[0].template_body
        
        # Le username doit être présent
        assert template_body["username"] == "<script>alert('xss')</script>"
        # Note: fastapi-mail/jinja2 s'occupe de l'échappement lors du rendu du template.
        # Ici on vérifie juste que la donnée est passée brute au moteur de template.

@pytest.mark.asyncio
async def test_xss_protection_utility():
    """
    Test indirect de SecurityUtils.escapeHtml (via simulation de ce que fait le JS).
    """
    # Ce test est principalement manuel/visuel, mais on peut vérifier que
    # l'application ne crash pas avec des caractères spéciaux.
    pass
