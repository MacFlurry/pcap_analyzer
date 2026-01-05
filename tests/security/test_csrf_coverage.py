"""
Security tests for CSRF protection (CWE-352, OWASP ASVS 4.2.2).

Tests:
- CSRF exemption logic
- CSRF protection requirement logic
- CSRF token generation
- CSRF token validation
"""

import pytest
from unittest.mock import AsyncMock
from fastapi import Request
from fastapi_csrf_protect import CsrfProtect
from app.security.csrf import (
    csrf_settings,
    is_csrf_exempt,
    requires_csrf_protection,
    validate_csrf_token,
)

class TestCSRFLogic:
    """Test the logic for CSRF protection requirements and exemptions."""

    def test_is_csrf_exempt_exact_match(self):
        """Test exact match for exempt paths."""
        mock_request = Request(scope={
            "type": "http",
            "path": "/api/health",
            "method": "GET",
            "headers": []
        })
        assert is_csrf_exempt(mock_request) is True

    def test_is_csrf_exempt_prefix_match(self):
        """Test prefix match for exempt paths."""
        mock_request = Request(scope={
            "type": "http",
            "path": "/api/health/status",
            "method": "GET",
            "headers": []
        })
        assert is_csrf_exempt(mock_request) is True

    def test_is_csrf_not_exempt(self):
        """Test paths that are not exempt."""
        mock_request = Request(scope={
            "type": "http",
            "path": "/api/upload",
            "method": "POST",
            "headers": []
        })
        assert is_csrf_exempt(mock_request) is False

    def test_requires_csrf_protection_get_is_false(self):
        """GET requests should not require CSRF protection."""
        mock_request = Request(scope={
            "type": "http",
            "path": "/api/upload",
            "method": "GET",
            "headers": []
        })
        assert requires_csrf_protection(mock_request) is False

    def test_requires_csrf_protection_post_is_true(self):
        """POST requests to non-exempt paths should require CSRF protection."""
        mock_request = Request(scope={
            "type": "http",
            "path": "/api/upload",
            "method": "POST",
            "headers": []
        })
        assert requires_csrf_protection(mock_request) is True

    def test_requires_csrf_protection_exempt_path_is_false(self):
        """POST requests to exempt paths should not require CSRF protection."""
        mock_request = Request(scope={
            "type": "http",
            "path": "/api/token",
            "method": "POST",
            "headers": []
        })
        assert requires_csrf_protection(mock_request) is False

class TestCSRFTokenGeneration:
    """Test CSRF token generation behavior."""

    def test_generate_csrf_tokens(self):
        """Test that CsrfProtect generates valid tokens."""
        csrf_protect = CsrfProtect()
        csrf_token, signed_token = csrf_protect.generate_csrf_tokens(
            secret_key=csrf_settings.secret_key
        )
        assert csrf_token is not None
        assert signed_token is not None
        assert len(csrf_token) > 0
        assert len(signed_token) > 0
        assert csrf_token != signed_token

class TestCSRFValidation:
    """Test the CSRF token validation logic."""

    @pytest.mark.asyncio
    async def test_validate_csrf_token_protected_method(self):
        """Test that validate_csrf is called for protected methods."""
        mock_request = Request(scope={
            "type": "http",
            "path": "/api/upload",
            "method": "POST",
            "headers": []
        })
        
        mock_csrf_protect = AsyncMock(spec=CsrfProtect)
        
        await validate_csrf_token(mock_request, mock_csrf_protect)
        
        mock_csrf_protect.validate_csrf.assert_awaited_once_with(
            mock_request, secret_key=csrf_settings.secret_key
        )

    @pytest.mark.asyncio
    async def test_validate_csrf_token_exempt_method(self):
        """Test that validate_csrf is NOT called for exempt methods (GET)."""
        mock_request = Request(scope={
            "type": "http",
            "path": "/api/upload",
            "method": "GET",
            "headers": []
        })
        
        mock_csrf_protect = AsyncMock(spec=CsrfProtect)
        
        await validate_csrf_token(mock_request, mock_csrf_protect)
        
        mock_csrf_protect.validate_csrf.assert_not_called()

    @pytest.mark.asyncio
    async def test_validate_csrf_token_exempt_path(self):
        """Test that validate_csrf is NOT called for exempt paths."""
        mock_request = Request(scope={
            "type": "http",
            "path": "/api/token",
            "method": "POST",
            "headers": []
        })
        
        mock_csrf_protect = AsyncMock(spec=CsrfProtect)
        
        await validate_csrf_token(mock_request, mock_csrf_protect)
        
        mock_csrf_protect.validate_csrf.assert_not_called()

    @pytest.mark.asyncio
    async def test_validate_csrf_token_invalid_raises_error(self):
        """Test that validate_csrf_token propagates CsrfProtectError."""
        from fastapi_csrf_protect.exceptions import CsrfProtectError
        
        mock_request = Request(scope={
            "type": "http",
            "path": "/api/upload",
            "method": "POST",
            "headers": []
        })
        
        mock_csrf_protect = AsyncMock(spec=CsrfProtect)
        mock_csrf_protect.validate_csrf.side_effect = CsrfProtectError(
            status_code=403, message="CSRF validation failed"
        )
        
        with pytest.raises(CsrfProtectError) as excinfo:
            await validate_csrf_token(mock_request, mock_csrf_protect)
        
        assert excinfo.value.message == "CSRF validation failed"
        assert excinfo.value.status_code == 403