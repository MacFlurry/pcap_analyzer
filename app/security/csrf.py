"""
CSRF Protection Configuration
Implements Double Submit Cookie Pattern (OWASP ASVS 4.2.2)

References:
- OWASP ASVS 4.2.2: Anti-CSRF mechanism for authenticated functionality
- CWE-352: Cross-Site Request Forgery
- fastapi-csrf-protect: https://github.com/aekasitt/fastapi-csrf-protect
"""

import os
from typing import Optional

from fastapi import Depends, Request
from fastapi_csrf_protect import CsrfProtect
from pydantic import BaseModel


class CsrfSettings(BaseModel):
    """
    CSRF Protection Settings (Pydantic BaseSettings)

    IMPORTANT: Set CSRF_SECRET_KEY environment variable in production!
    Generate with: python3 -c "import secrets; print(secrets.token_urlsafe(32))"
    """

    # Secret key for signing CSRF tokens (MUST be set via environment variable)
    # Falls back to JWT SECRET_KEY if not set, but separate key is recommended
    secret_key: str = os.getenv("CSRF_SECRET_KEY", os.getenv("SECRET_KEY", ""))

    # Cookie name for CSRF token
    cookie_name: str = "fastapi-csrf-token"

    # Header name where JavaScript sends token
    header_name: str = "X-CSRF-Token"

    # Cookie security settings
    cookie_samesite: str = "lax"  # "lax" allows top-level navigation (GET)
    cookie_secure: bool = os.getenv("ENVIRONMENT", "development") == "production"
    cookie_httponly: bool = True
    cookie_domain: Optional[str] = None  # None = current domain only

    # Token expiration (in seconds) - align with JWT expiration
    token_expiration: int = 1800  # 30 minutes (same as JWT)

    # Methods that require CSRF protection
    protected_methods: list = ["POST", "PUT", "PATCH", "DELETE"]

    # Exempt paths (public endpoints that don't need CSRF)
    exempt_paths: list = [
        "/api/health",
        "/api/token",  # Login endpoint (initial auth)
        "/api/register",  # Registration (no prior session)
        "/docs",
        "/openapi.json",
        "/swagger-custom.css",
    ]


# Global settings instance
csrf_settings = CsrfSettings()


@CsrfProtect.load_config
def get_csrf_config():
    """Load CSRF configuration for fastapi-csrf-protect"""
    return csrf_settings


def is_csrf_exempt(request: Request) -> bool:
    """
    Check if request path is exempt from CSRF protection.

    Args:
        request: FastAPI request object

    Returns:
        True if path is exempt, False otherwise
    """
    path = request.url.path

    # Exact match
    if path in csrf_settings.exempt_paths:
        return True

    # Prefix match (e.g., /static/*)
    for exempt_path in csrf_settings.exempt_paths:
        if path.startswith(exempt_path.rstrip("*")):
            return True

    return False


def requires_csrf_protection(request: Request) -> bool:
    """
    Determine if request requires CSRF protection.

    Args:
        request: FastAPI request object

    Returns:
        True if CSRF check needed, False otherwise
    """
    # Only protect state-changing methods
    if request.method not in csrf_settings.protected_methods:
        return False

    # Check if path is exempt
    if is_csrf_exempt(request):
        return False

    return True


async def validate_csrf_token(
    request: Request,
    csrf_protect: CsrfProtect = Depends(),
) -> None:
    """
    FastAPI dependency to validate CSRF token for protected endpoints.

    Usage:
        @router.post("/upload", dependencies=[Depends(validate_csrf_token)])
        async def upload_file(...):
            ...

    Raises:
        CsrfProtectError: If CSRF validation fails
    """
    # Only validate if this endpoint requires CSRF protection
    if requires_csrf_protection(request):
        await csrf_protect.validate_csrf(request, secret_key=csrf_settings.secret_key)
