import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path
from app.services.email_service import EmailService
from app.models.user import User, UserRole
from datetime import datetime

@pytest.fixture
def mock_user():
    return User(
        id="user-123",
        username="testuser",
        email="test@example.com",
        hashed_password="hashed",
        role=UserRole.USER,
        is_active=True,
        is_approved=False,
        created_at=datetime.now()
    )

@pytest.fixture
def email_service():
    with patch("app.services.email_service.FastMail") as mock_fastmail:
        service = EmailService()
        service.mail_enabled = True
        return service

@pytest.mark.asyncio
async def test_send_registration_email(email_service, mock_user):
    with patch.object(email_service.fastmail, "send_message", new_callable=AsyncMock) as mock_send:
        await email_service.send_registration_email(mock_user)
        
        assert mock_send.called
        args, kwargs = mock_send.call_args
        message = args[0]
        template_name = kwargs["template_name"]
        
        assert message.subject == "Welcome to PCAP Analyzer - Registration Pending"
        assert message.recipients[0].email == "test@example.com"
        assert template_name == "registration_confirmation.html"
        assert message.template_body["username"] == "testuser"

@pytest.mark.asyncio
async def test_send_approval_email(email_service, mock_user):
    with patch.object(email_service.fastmail, "send_message", new_callable=AsyncMock) as mock_send:
        await email_service.send_approval_email(mock_user, approved_by="admin")
        
        assert mock_send.called
        args, kwargs = mock_send.call_args
        message = args[0]
        template_name = kwargs["template_name"]
        
        assert message.subject == "Your PCAP Analyzer Account Has Been Approved!"
        assert message.recipients[0].email == "test@example.com"
        assert template_name == "account_approved.html"
        assert message.template_body["approved_by"] == "admin"

@pytest.mark.asyncio
async def test_email_service_disabled(mock_user):
    with patch("app.services.email_service.FastMail") as mock_fastmail:
        service = EmailService()
        service.mail_enabled = False
        
        with patch.object(service.fastmail, "send_message", new_callable=AsyncMock) as mock_send:
            await service.send_registration_email(mock_user)
            assert not mock_send.called
