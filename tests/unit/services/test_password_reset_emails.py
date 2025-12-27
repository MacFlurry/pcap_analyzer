"""
Unit tests for password reset email templates.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
from app.services.email_service import EmailService
from app.models.user import User

@pytest.fixture
def email_service():
    with patch("app.services.email_service.ConnectionConfig"), \
         patch("app.services.email_service.FastMail") as mock_fastmail, \
         patch.dict("os.environ", {"MAIL_ENABLED": "true"}):
        service = EmailService()
        service.fastmail = mock_fastmail.return_value
        service.fastmail.send_message = AsyncMock()
        return service

@pytest.mark.asyncio
async def test_send_password_reset_request_email(email_service):
    user = User(
        id="123", username="testuser", email="test@example.com", 
        hashed_password="...", created_at="2023-01-01"
    )
    
    await email_service.send_password_reset_request_email(
        user, "http://reset-link", "127.0.0.1", "2023-01-01 12:00:00"
    )
    
    assert email_service.fastmail.send_message.called
    args, kwargs = email_service.fastmail.send_message.call_args
    message = args[0]
    template_name = kwargs["template_name"]
    
    assert template_name == "password_reset_request.html"
    assert message.subject == "Password Reset Request - PCAP Analyzer"
    # fastapi-mail might convert recipients to objects
    recipients = [r.email if hasattr(r, "email") else r for r in message.recipients]
    assert recipients == [user.email]
    assert message.template_body["username"] == user.username
    assert message.template_body["reset_link"] == "http://reset-link"

@pytest.mark.asyncio
async def test_send_password_reset_success_email(email_service):
    user = User(
        id="123", username="testuser", email="test@example.com", 
        hashed_password="...", created_at="2023-01-01"
    )
    
    await email_service.send_password_reset_success_email(
        user, "127.0.0.1", "2023-01-01 12:00:00"
    )
    
    assert email_service.fastmail.send_message.called
    _, kwargs = email_service.fastmail.send_message.call_args
    assert kwargs["template_name"] == "password_reset_success.html"

@pytest.mark.asyncio
async def test_send_admin_password_reset_email(email_service):
    user = User(
        id="123", username="testuser", email="test@example.com", 
        hashed_password="...", created_at="2023-01-01"
    )
    
    await email_service.send_admin_password_reset_email(
        user, "temp-pass-123", "admin_bob"
    )
    
    assert email_service.fastmail.send_message.called
    args, kwargs = email_service.fastmail.send_message.call_args
    message = args[0]
    
    assert kwargs["template_name"] == "admin_password_reset.html"
    assert message.template_body["temporary_password"] == "temp-pass-123"
    assert message.template_body["admin_username"] == "admin_bob"
