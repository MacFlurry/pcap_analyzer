"""
CSRF Token Endpoint
Provides CSRF tokens to authenticated clients for protected operations.

References:
- OWASP ASVS 4.2.2: Anti-CSRF tokens must be unpredictable
- Double Submit Cookie Pattern: Token sent both as cookie AND in custom header
"""

import logging
from typing import Dict

from fastapi import APIRouter, Depends, Request
from fastapi_csrf_protect import CsrfProtect

from app.auth import get_current_user
from app.security.csrf import csrf_settings
from app.services.user_database import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/csrf", tags=["csrf"])


@router.get("/token")
async def get_csrf_token(
    request: Request,
    csrf_protect: CsrfProtect = Depends(),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Get CSRF token for authenticated user.

    Security Requirements:
    - User MUST be authenticated (JWT token required)
    - Returns unpredictable CSRF token
    - Token is set as HttpOnly cookie AND returned in response

    Returns:
        Dictionary containing:
        - csrf_token: Token value to send in X-CSRF-Token header
        - header_name: Name of the header where token should be sent
        - expires_in: Token expiration in seconds

    Example Usage:
        ```javascript
        const response = await fetch('/api/csrf/token', {
            headers: { 'Authorization': 'Bearer <jwt_token>' }
        });
        const data = await response.json();
        // Use data.csrf_token in subsequent requests
        ```
    """
    # Generate new CSRF tokens (returns tuple: token, signed_token)
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens(secret_key=csrf_settings.secret_key)

    # Set signed token as cookie (HttpOnly)
    # Note: fastapi-csrf-protect automatically sets the cookie via middleware

    logger.debug(
        f"CSRF token generated for user: {current_user.username} "
        f"(token_length={len(csrf_token)})"
    )

    return {
        "csrf_token": csrf_token,
        "header_name": csrf_settings.header_name,
        "cookie_name": csrf_settings.cookie_name,
        "expires_in": str(csrf_settings.token_expiration),
    }


@router.post("/refresh")
async def refresh_csrf_token(
    request: Request,
    csrf_protect: CsrfProtect = Depends(),
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """
    Refresh CSRF token for authenticated user.

    Use this endpoint to rotate CSRF tokens periodically (recommended every 25-30 min).

    Security Requirements:
    - User MUST be authenticated
    - Old token is invalidated
    - New token is generated and set

    Returns:
        Dictionary containing new CSRF token details
    """
    # Generate new CSRF tokens (invalidates old one)
    csrf_token, signed_token = csrf_protect.generate_csrf_tokens(secret_key=csrf_settings.secret_key)

    # Note: fastapi-csrf-protect automatically sets the cookie via middleware

    logger.debug(
        f"CSRF token refreshed for user: {current_user.username} "
        f"(token_length={len(csrf_token)})"
    )

    return {
        "csrf_token": csrf_token,
        "header_name": csrf_settings.header_name,
        "cookie_name": csrf_settings.cookie_name,
        "expires_in": str(csrf_settings.token_expiration),
    }
