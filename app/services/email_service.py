"""
Email service for sending notifications using fastapi-mail.
Supports registration confirmation and account approval notifications.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from pydantic import EmailStr

from app.models.user import User

logger = logging.getLogger(__name__)


class EmailService:
    """
    Service for sending email notifications.
    Uses Jinja2 templates for HTML emails.
    """

    def __init__(self):
        # Email configuration from environment variables
        self.mail_enabled = os.getenv("MAIL_ENABLED", "false").lower() == "true"

        # SMTP Configuration
        self.conf = ConnectionConfig(
            MAIL_USERNAME=os.getenv("SMTP_USERNAME", ""),
            MAIL_PASSWORD=os.getenv("SMTP_PASSWORD", ""),
            MAIL_FROM=os.getenv("MAIL_FROM", "noreply@pcap-analyzer.com"),
            MAIL_PORT=int(os.getenv("SMTP_PORT", "1025")),
            MAIL_SERVER=os.getenv("SMTP_HOST", "localhost"),
            MAIL_FROM_NAME=os.getenv("MAIL_FROM_NAME", "PCAP Analyzer"),
            MAIL_STARTTLS=os.getenv("SMTP_TLS", "false").lower() == "true",
            MAIL_SSL_TLS=os.getenv("SMTP_SSL", "false").lower() == "true",
            USE_CREDENTIALS=bool(os.getenv("SMTP_USERNAME")),
            VALIDATE_CERTS=os.getenv("VALIDATE_CERTS", "true").lower() == "true",
            TEMPLATE_FOLDER=Path(__file__).parent.parent / "templates" / "emails",
        )

        self.fastmail = FastMail(self.conf)
        self.support_email = os.getenv("SUPPORT_EMAIL", "support@pcaplab.com")
        self.app_base_url = os.getenv("APP_BASE_URL", "http://pcaplab.com")

    async def _send_email(
        self, recipients: List[EmailStr], subject: str, template_name: str, template_body: Dict[str, Any]
    ):
        """Internal helper to send email using FastMail."""
        if not self.mail_enabled:
            logger.info(f"Email service disabled. Would have sent '{subject}' to {recipients}")
            return

        message = MessageSchema(
            subject=subject,
            recipients=recipients,
            template_body=template_body,
            subtype=MessageType.html,
        )

        try:
            await self.fastmail.send_message(message, template_name=template_name)
            logger.info(f"Email '{subject}' sent to {recipients}")
        except Exception as e:
            logger.error(f"Failed to send email '{subject}' to {recipients}: {e}")
            # Do not raise exception to avoid breaking the calling flow

    async def send_registration_email(self, user: User):
        """Send registration confirmation email."""
        await self._send_email(
            recipients=[user.email],
            subject="Welcome to PCAP Analyzer - Registration Pending",
            template_name="registration_confirmation.html",
            template_body={
                "username": user.username,
                "email": user.email,
                "created_at": user.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                "support_email": self.support_email,
            },
        )

    async def send_approval_email(self, user: User, approved_by: str):
        """Send account approval email."""
        await self._send_email(
            recipients=[user.email],
            subject="Your PCAP Analyzer Account Has Been Approved!",
            template_name="account_approved.html",
            template_body={
                "username": user.username,
                "email": user.email,
                "approved_by": approved_by,
                "login_url": f"{self.app_base_url}/login",
                "support_email": self.support_email,
            },
        )

    async def send_password_reset_request_email(self, user: User, reset_link: str, ip: str, timestamp: str):
        """Send password reset request email."""
        await self._send_email(
            recipients=[user.email],
            subject="Password Reset Request - PCAP Analyzer",
            template_name="password_reset_request.html",
            template_body={
                "username": user.username,
                "reset_link": reset_link,
                "ip_address": ip,
                "timestamp": timestamp,
                "support_email": self.support_email,
                "validity_minutes": 60,  # 1 hour
            },
        )

    async def send_password_reset_success_email(self, user: User, ip: str, timestamp: str):
        """Send password reset success confirmation."""
        await self._send_email(
            recipients=[user.email],
            subject="Password Successfully Reset - PCAP Analyzer",
            template_name="password_reset_success.html",
            template_body={
                "username": user.username,
                "ip_address": ip,
                "timestamp": timestamp,
                "login_url": f"{self.app_base_url}/login",
                "support_email": self.support_email,
            },
        )

    async def send_admin_password_reset_email(self, user: User, temp_password: str, admin_username: str):
        """Send admin password reset notification with temporary password."""
        await self._send_email(
            recipients=[user.email],
            subject="Administrator Password Reset - PCAP Analyzer",
            template_name="admin_password_reset.html",
            template_body={
                "username": user.username,
                "temporary_password": temp_password,
                "admin_username": admin_username,
                "login_url": f"{self.app_base_url}/login",
                "support_email": self.support_email,
            },
        )


# Singleton instance
_email_service: Optional[EmailService] = None


def get_email_service() -> EmailService:
    """Returns the singleton instance of EmailService."""
    global _email_service
    if _email_service is None:
        _email_service = EmailService()
    return _email_service
