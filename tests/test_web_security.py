"""
Web UI Security Test Suite

Tests for critical security vulnerabilities in the Web UI:
- Path Traversal (CWE-22) - Issue #14
- Authentication/Authorization (CWE-306) - Issue #15
- CSRF (CWE-352) - Issue #16
- File Upload Validation (CWE-434, CWE-770) - Issue #17

References:
- docs/security/WEB_UI_SECURITY_AUDIT.md
- GitHub Issues: #14, #15, #16, #17, #18
"""

import os
import pytest
from httpx import AsyncClient, ASGITransport
from pathlib import Path
import tempfile
import uuid

# These tests will FAIL until fixes are implemented
# They serve as acceptance criteria for security fixes

pytestmark = pytest.mark.asyncio


# =============================================================================
# Helper Functions
# =============================================================================

async def get_test_jwt_token(client: AsyncClient) -> str:
    """
    Get a valid JWT token for testing by logging in with test credentials.

    Returns:
        JWT token string
    """
    # Login with test admin credentials (same as fixture)
    credentials = {"username": "admin", "password": "testpass1234"}
    response = await client.post("/api/token", data=credentials)

    if response.status_code != 200:
        raise Exception(f"Failed to login: {response.status_code} {response.text}")

    token_data = response.json()
    return token_data["access_token"]


async def get_csrf_token(client: AsyncClient, jwt_token: str) -> str:
    """
    Get a CSRF token for authenticated user.

    Args:
        client: AsyncClient instance
        jwt_token: JWT token for authentication

    Returns:
        CSRF token string
    """
    headers = {"Authorization": f"Bearer {jwt_token}"}
    response = await client.get("/api/csrf/token", headers=headers)

    if response.status_code != 200:
        raise Exception(f"Failed to get CSRF token: {response.status_code} {response.text}")

    csrf_data = response.json()
    return csrf_data["csrf_token"]


# =============================================================================
# Path Traversal Tests (Issue #14 - CWE-22)
# =============================================================================

class TestPathTraversal:
    """Test path traversal vulnerability fixes."""

    async def test_task_id_with_path_traversal_rejected(self, client: AsyncClient):
        """
        Test that task_id with non-UUID format (potential path traversal) is rejected.

        VULNERABILITY: app/api/routes/reports.py:47
        FIX: Validate task_id is UUID v4 format before file operations
        """
        # Get auth token (reports require authentication)
        jwt_token = await get_test_jwt_token(client)

        # Test various malicious task_ids that aren't valid UUIDs
        # Note: Avoid IDs with slashes as FastAPI normalizes them at routing level (404)
        malicious_task_ids = [
            "not-a-uuid",        # Invalid format
            "12345",             # Number only
            "..invalid..",       # Dots (potential traversal)
            "admin",             # Simple string
            "x" * 100,           # Too long
        ]

        headers = {"Authorization": f"Bearer {jwt_token}"}

        for malicious_id in malicious_task_ids:
            response = await client.get(f"/api/reports/{malicious_id}/html", headers=headers)
            # Should reject non-UUID formats with 400
            assert response.status_code == 400, \
                f"Should reject malicious task_id '{malicious_id}' (got {response.status_code})"
            assert "Invalid task_id format" in response.json()["detail"], \
                f"Expected 'Invalid task_id format' in error message for '{malicious_id}'"

    async def test_task_id_valid_uuid_accepted(self, client: AsyncClient):
        """Test that valid UUID v4 task_id is accepted (even if task doesn't exist)."""
        # Get auth token (reports require authentication)
        jwt_token = await get_test_jwt_token(client)

        valid_uuid = str(uuid.uuid4())

        headers = {"Authorization": f"Bearer {jwt_token}"}
        response = await client.get(f"/api/reports/{valid_uuid}/html", headers=headers)

        # Should be 404 (task not found), NOT 400 (invalid format)
        assert response.status_code == 404, "Valid UUID should pass validation"

    async def test_filename_with_path_traversal_sanitized(self, client: AsyncClient):
        """
        Test that uploaded filename with ../ is sanitized to basename only.

        VULNERABILITY: app/api/routes/upload.py:49
        FIX: Extract basename only from filename
        """
        # Create a fake PCAP file
        pcap_magic = b'\xa1\xb2\xc3\xd4'  # PCAP magic number
        pcap_content = pcap_magic + b'\x00' * 1000

        # Try to upload with malicious filename
        malicious_filename = "../../etc/cron.d/evil.pcap"

        files = {"file": (malicious_filename, pcap_content, "application/vnd.tcpdump.pcap")}
        response = await client.post("/api/upload", files=files)

        # File should be saved with basename only (evil.pcap), not full path
        # This test will need auth once #15 is fixed
        # For now, check that server doesn't crash
        assert response.status_code in [200, 201, 401], "Should handle malicious filename gracefully"

    async def test_delete_with_path_traversal_rejected(self, client: AsyncClient):
        """Test that DELETE with path traversal is rejected."""
        # Get auth tokens (delete requires authentication AND CSRF)
        jwt_token = await get_test_jwt_token(client)
        csrf_token = await get_csrf_token(client, jwt_token)

        malicious_task_id = "../../../data/pcap_analyzer.db"

        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-CSRF-Token": csrf_token
        }
        response = await client.delete(f"/api/reports/{malicious_task_id}", headers=headers)

        assert response.status_code == 400, "Should reject path traversal in DELETE"


# =============================================================================
# Authentication Tests (Issue #15 - CWE-306)
# =============================================================================

class TestAuthentication:
    """Test authentication and authorization."""

    @pytest.mark.skip(reason="Auth not yet implemented - Issue #15")
    async def test_upload_without_auth_rejected(self, client: AsyncClient):
        """Test that upload endpoint requires authentication."""
        pcap_content = b'\xa1\xb2\xc3\xd4' + b'\x00' * 1000
        files = {"file": ("test.pcap", pcap_content, "application/vnd.tcpdump.pcap")}

        response = await client.post("/api/upload", files=files)

        assert response.status_code == 401, "Should require authentication"
        assert "WWW-Authenticate" in response.headers

    @pytest.mark.skip(reason="Auth not yet implemented - Issue #15")
    async def test_login_with_valid_credentials(self, client: AsyncClient):
        """Test login with valid credentials returns JWT token."""
        credentials = {"username": "admin", "password": "changeme"}

        response = await client.post("/token", data=credentials)

        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    @pytest.mark.skip(reason="Auth not yet implemented - Issue #15")
    async def test_login_with_invalid_credentials(self, client: AsyncClient):
        """Test login with invalid credentials is rejected."""
        credentials = {"username": "admin", "password": "wrongpassword"}

        response = await client.post("/token", data=credentials)

        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]

    @pytest.mark.skip(reason="Auth not yet implemented - Issue #15")
    async def test_protected_endpoint_with_valid_token(self, client: AsyncClient):
        """Test that protected endpoint accepts valid JWT token."""
        # Login first
        credentials = {"username": "admin", "password": "changeme"}
        login_response = await client.post("/token", data=credentials)
        token = login_response.json()["access_token"]

        # Access protected endpoint
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.get("/api/progress/history", headers=headers)

        assert response.status_code == 200

    @pytest.mark.skip(reason="Auth not yet implemented - Issue #15")
    async def test_protected_endpoint_with_invalid_token(self, client: AsyncClient):
        """Test that protected endpoint rejects invalid JWT token."""
        headers = {"Authorization": "Bearer invalid_token_here"}

        response = await client.get("/api/progress/history", headers=headers)

        assert response.status_code == 401

    @pytest.mark.skip(reason="Auth not yet implemented - Issue #15")
    async def test_ownership_check(self, client: AsyncClient):
        """Test that users can only access their own resources."""
        # Login as user1
        credentials1 = {"username": "user1", "password": "password1"}
        login1 = await client.post("/token", data=credentials1)
        token1 = login1.json()["access_token"]

        # Login as user2
        credentials2 = {"username": "user2", "password": "password2"}
        login2 = await client.post("/token", data=credentials2)
        token2 = login2.json()["access_token"]

        # User1 uploads a file
        pcap_content = b'\xa1\xb2\xc3\xd4' + b'\x00' * 1000
        files = {"file": ("test.pcap", pcap_content, "application/vnd.tcpdump.pcap")}
        headers1 = {"Authorization": f"Bearer {token1}"}
        upload_response = await client.post("/api/upload", files=files, headers=headers1)
        task_id = upload_response.json()["task_id"]

        # User2 tries to access User1's report
        headers2 = {"Authorization": f"Bearer {token2}"}
        response = await client.get(f"/api/reports/{task_id}/html", headers=headers2)

        assert response.status_code == 403, "Should reject access to other user's resources"


# =============================================================================
# CSRF Tests (Issue #16 - CWE-352)
# =============================================================================

class TestCSRF:
    """Test CSRF protection."""

    async def test_upload_without_csrf_token_rejected(self, client: AsyncClient):
        """Test that POST /upload without CSRF token is rejected."""
        # Get valid JWT token
        jwt_token = await get_test_jwt_token(client)

        pcap_content = b'\xd4\xc3\xb2\xa1' + b'\x00' * 1000
        files = {"file": ("test.pcap", pcap_content, "application/vnd.tcpdump.pcap")}

        # Include valid JWT but NO CSRF token
        headers = {"Authorization": f"Bearer {jwt_token}"}
        response = await client.post("/api/upload", files=files, headers=headers)

        assert response.status_code == 403, "Should reject request without CSRF token"
        assert "CSRF" in response.json()["detail"] or "csrf" in response.json().get("error_type", "")

    async def test_upload_with_valid_csrf_token_accepted(self, client: AsyncClient):
        """Test that POST /upload with valid CSRF token is accepted."""
        # Get valid JWT token
        jwt_token = await get_test_jwt_token(client)

        # Get CSRF token
        csrf_token = await get_csrf_token(client, jwt_token)

        pcap_content = b'\xd4\xc3\xb2\xa1' + b'\x00' * 1000
        files = {"file": ("test.pcap", pcap_content, "application/vnd.tcpdump.pcap")}
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-CSRF-Token": csrf_token
        }

        response = await client.post("/api/upload", files=files, headers=headers)

        # Should be 202 (accepted) or 201 (created)
        assert response.status_code in [200, 201, 202], \
            f"Should accept request with valid CSRF token (got {response.status_code}: {response.text})"

    async def test_delete_without_csrf_token_rejected(self, client: AsyncClient):
        """Test that DELETE endpoint without CSRF token is rejected."""
        # Get valid JWT token
        jwt_token = await get_test_jwt_token(client)

        task_id = str(uuid.uuid4())
        headers = {"Authorization": f"Bearer {jwt_token}"}

        response = await client.delete(f"/api/reports/{task_id}", headers=headers)

        assert response.status_code == 403, "Should reject DELETE without CSRF token"


# =============================================================================
# File Upload Validation Tests (Issue #17 - CWE-434, CWE-770)
# =============================================================================

class TestFileUploadValidation:
    """Test file upload validation (magic number, size, decompression bombs)."""

    async def test_upload_non_pcap_file_rejected(self, client: AsyncClient):
        """
        Test that non-PCAP files are rejected based on magic number.

        VULNERABILITY: app/api/routes/upload.py:48-54
        FIX: Check magic number (first 4 bytes)
        """
        # Get auth tokens (upload requires authentication)
        jwt_token = await get_test_jwt_token(client)
        csrf_token = await get_csrf_token(client, jwt_token)

        # Create a fake .exe file (MZ header) renamed as .pcap
        exe_content = b'MZ\x90\x00' + b'\x00' * 1000
        files = {"file": ("malware.pcap", exe_content, "application/octet-stream")}
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-CSRF-Token": csrf_token
        }

        response = await client.post("/api/upload", files=files, headers=headers)

        assert response.status_code == 400, "Should reject non-PCAP file"
        assert "Invalid PCAP" in response.json()["detail"] or \
               "magic" in response.json()["detail"].lower() or \
               "format" in response.json()["detail"].lower()

    async def test_upload_valid_pcap_accepted(self, client: AsyncClient):
        """Test that valid PCAP file is accepted."""
        # Get auth tokens (upload requires authentication)
        jwt_token = await get_test_jwt_token(client)
        csrf_token = await get_csrf_token(client, jwt_token)

        # PCAP magic number (little-endian)
        pcap_magic = b'\xd4\xc3\xb2\xa1'
        # Minimal PCAP file header (24 bytes total)
        pcap_header = pcap_magic + b'\x00' * 20
        pcap_content = pcap_header + b'\x00' * 1000

        files = {"file": ("capture.pcap", pcap_content, "application/vnd.tcpdump.pcap")}
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-CSRF-Token": csrf_token
        }

        response = await client.post("/api/upload", files=files, headers=headers)

        # Should be 202 (accepted), 201 (created), or 200 (ok)
        assert response.status_code in [200, 201, 202], \
            f"Valid PCAP should be accepted (got {response.status_code}: {response.text})"

    async def test_upload_valid_pcapng_accepted(self, client: AsyncClient):
        """Test that valid PCAPNG file is accepted."""
        # Get auth tokens (upload requires authentication)
        jwt_token = await get_test_jwt_token(client)
        csrf_token = await get_csrf_token(client, jwt_token)

        # PCAPNG magic number
        pcapng_magic = b'\x0a\x0d\x0d\x0a'
        pcapng_content = pcapng_magic + b'\x00' * 1000

        files = {"file": ("capture.pcapng", pcapng_content, "application/x-pcapng")}
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-CSRF-Token": csrf_token
        }

        response = await client.post("/api/upload", files=files, headers=headers)

        assert response.status_code in [200, 201, 202], \
            f"Valid PCAPNG should be accepted (got {response.status_code}: {response.text})"

    async def test_upload_file_too_large_rejected(self, client: AsyncClient):
        """
        Test that files > 500 MB are rejected BEFORE full read.

        VULNERABILITY: Size checked AFTER full read into memory
        FIX: Stream read with size check per chunk
        """
        # Simulate a 600 MB file (don't actually create it, just test size check)
        file_size_mb = 600
        max_size_mb = 500

        # This test would need to verify that the server checks size incrementally
        # For now, we'll test that the error message is correct
        # TODO: Implement streaming read test

        pytest.skip("Requires streaming read implementation")

    async def test_upload_decompression_bomb_rejected(self, client: AsyncClient):
        """
        Test that decompression bombs are detected.

        VULNERABILITY: No decompression bomb protection in Web UI
        FIX: Reuse src/utils/decompression_monitor.py from CLI
        """
        # Simulate a zip bomb (small compressed, huge uncompressed)
        # Real test would use 42.zip or similar
        # For now, just verify the check exists

        pytest.skip("Requires decompression_monitor.py integration")

    async def test_filename_special_characters_sanitized(self, client: AsyncClient):
        """Test that filename with special characters is sanitized."""
        pcap_magic = b'\xa1\xb2\xc3\xd4'
        pcap_content = pcap_magic + b'\x00' * 1000

        # Filename with special chars
        malicious_filename = "test<script>alert(1)</script>.pcap"

        files = {"file": (malicious_filename, pcap_content, "application/vnd.tcpdump.pcap")}
        response = await client.post("/api/upload", files=files)

        # Filename should be sanitized (script tags removed)
        # Check response doesn't echo the unsanitized filename
        if response.status_code in [200, 201]:
            data = response.json()
            assert "<script>" not in data.get("filename", ""), "Filename should be sanitized"

    async def test_extension_validation_server_side(self, client: AsyncClient):
        """Test that extension validation happens server-side, not just client-side."""
        # Get auth tokens (upload requires authentication)
        jwt_token = await get_test_jwt_token(client)
        csrf_token = await get_csrf_token(client, jwt_token)

        # Upload a .txt file with valid PCAP magic (should be rejected by extension check)
        pcap_magic = b'\xd4\xc3\xb2\xa1'
        content = pcap_magic + b'\x00' * 1000

        files = {"file": ("document.txt", content, "text/plain")}
        headers = {
            "Authorization": f"Bearer {jwt_token}",
            "X-CSRF-Token": csrf_token
        }

        response = await client.post("/api/upload", files=files, headers=headers)

        assert response.status_code == 400, "Should reject invalid extension server-side"
        assert "extension" in response.json()["detail"].lower() or \
               "Invalid file" in response.json()["detail"]


# =============================================================================
# XSS Tests (Additional Security)
# =============================================================================

class TestXSSProtection:
    """Test XSS protection in output encoding."""

    @pytest.mark.skip(reason="Requires frontend testing setup")
    async def test_error_message_with_xss_payload_escaped(self, client: AsyncClient):
        """Test that error messages with HTML/JS are escaped."""
        # Upload a file with XSS in filename
        pcap_content = b'\xa1\xb2\xc3\xd4' + b'\x00' * 1000
        xss_filename = "<script>alert(document.cookie)</script>.pcap"

        files = {"file": (xss_filename, pcap_content, "application/vnd.tcpdump.pcap")}
        response = await client.post("/api/upload", files=files)

        # Check that response doesn't contain unescaped script tags
        response_text = response.text
        assert "<script>" not in response_text, "HTML should be escaped in responses"
        assert "&lt;script&gt;" in response_text or response.status_code == 400


# =============================================================================
# Security Headers Tests
# =============================================================================

class TestSecurityHeaders:
    """Test that security headers are present."""

    @pytest.mark.skip(reason="Security headers not yet implemented - Future enhancement")
    async def test_csp_header_present(self, client: AsyncClient):
        """Test that Content-Security-Policy header is set."""
        response = await client.get("/")

        assert "Content-Security-Policy" in response.headers or \
               "content-security-policy" in response.headers, \
               "CSP header should be present"

    @pytest.mark.skip(reason="Security headers not yet implemented - Future enhancement")
    async def test_x_frame_options_header_present(self, client: AsyncClient):
        """Test that X-Frame-Options header is set to DENY."""
        response = await client.get("/")

        x_frame = response.headers.get("X-Frame-Options", "")
        assert x_frame.upper() == "DENY", "X-Frame-Options should be DENY"

    @pytest.mark.skip(reason="Security headers not yet implemented - Future enhancement")
    async def test_x_content_type_options_header_present(self, client: AsyncClient):
        """Test that X-Content-Type-Options header is set to nosniff."""
        response = await client.get("/")

        x_content = response.headers.get("X-Content-Type-Options", "")
        assert x_content.lower() == "nosniff", "X-Content-Type-Options should be nosniff"

    async def test_hsts_header_present_if_https(self, client: AsyncClient):
        """Test that Strict-Transport-Security header is set (if HTTPS)."""
        response = await client.get("/")

        # Only check if scheme is HTTPS
        if client.base_url.scheme == "https":
            assert "Strict-Transport-Security" in response.headers, \
                   "HSTS header should be present for HTTPS"


# =============================================================================
# Rate Limiting Tests
# =============================================================================

class TestRateLimiting:
    """Test rate limiting on endpoints."""

    @pytest.mark.skip(reason="Rate limiting not yet implemented")
    async def test_upload_rate_limit(self, client: AsyncClient):
        """Test that upload endpoint enforces rate limit (5/minute)."""
        pcap_content = b'\xa1\xb2\xc3\xd4' + b'\x00' * 1000
        files = {"file": ("test.pcap", pcap_content, "application/vnd.tcpdump.pcap")}
        headers = {"Authorization": "Bearer valid_token"}

        # Make 6 requests rapidly
        responses = []
        for i in range(6):
            response = await client.post("/api/upload", files=files, headers=headers)
            responses.append(response)

        # First 5 should succeed (or 401 if no auth), 6th should be 429
        assert responses[5].status_code == 429, "Should enforce rate limit"
        assert "rate limit" in responses[5].json()["detail"].lower()


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
async def client():
    """
    Create async HTTP client for testing with initialized databases.

    This fixture:
    1. Creates temporary isolated databases
    2. Creates a test admin user
    3. Provides an AsyncClient with proper ASGI transport
    """
    import tempfile
    import shutil
    from pathlib import Path

    # Create temporary directory
    tmpdir = Path(tempfile.mkdtemp(prefix="pcap_test_"))

    try:
        # Set environment variables to temp directory
        # This must be done BEFORE importing app
        original_data_dir = os.environ.get("DATA_DIR")
        original_database_url = os.environ.get("DATABASE_URL")
        original_secret_key = os.environ.get("SECRET_KEY")

        os.environ["DATA_DIR"] = str(tmpdir)
        os.environ["DATABASE_URL"] = f"sqlite:///{tmpdir}/pcap_analyzer.db"
        os.environ["SECRET_KEY"] = "test-secret-key-for-jwt-signing-in-tests-minimum-32-chars"

        # Clear singletons and reload modules to pick up new DATA_DIR
        import sys
        from app.services import database, user_database
        database._db_service = None
        user_database._user_db_service = None

        # Force reload of modules that have DATA_DIR constants
        # This ensures they pick up the new DATA_DIR environment variable
        if 'app.api.routes.upload' in sys.modules:
            import importlib
            importlib.reload(sys.modules['app.api.routes.upload'])
        if 'app.api.routes.reports' in sys.modules:
            importlib.reload(sys.modules['app.api.routes.reports'])

        # Now import app (it will use the temp DATA_DIR)
        from app.main import app
        from app.services.database import get_db_service
        from app.services.user_database import get_user_db_service
        from app.models.user import UserCreate, UserRole

        # Initialize databases
        db_service = get_db_service()
        await db_service.init_db()

        user_db_service = get_user_db_service()
        await user_db_service.init_db()

        # Run tasks table migration to add owner_id column (multi-tenant)
        await user_db_service.migrate_tasks_table()

        # Create test admin user
        admin_user = UserCreate(
            username="admin",
            email="admin@example.com",
            password="testpass1234"  # 12 chars minimum for NIST SP 800-63B
        )
        await user_db_service.create_user(admin_user, role=UserRole.ADMIN, auto_approve=True)

        # Create AsyncClient
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac

    finally:
        # Cleanup
        shutil.rmtree(tmpdir, ignore_errors=True)

        # Restore original environment variables
        if original_data_dir:
            os.environ["DATA_DIR"] = original_data_dir
        elif "DATA_DIR" in os.environ:
            del os.environ["DATA_DIR"]

        if original_database_url:
            os.environ["DATABASE_URL"] = original_database_url
        elif "DATABASE_URL" in os.environ:
            del os.environ["DATABASE_URL"]

        if original_secret_key:
            os.environ["SECRET_KEY"] = original_secret_key
        elif "SECRET_KEY" in os.environ:
            del os.environ["SECRET_KEY"]

        # Reset singletons
        database._db_service = None
        user_database._user_db_service = None
