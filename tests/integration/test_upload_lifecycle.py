"""
Tests d'intégration du cycle de vie de l'upload et de la validation des fichiers.
"""

import os
import io
import pytest
import uuid
from fastapi import status
from pathlib import Path
from app.models.schemas import TaskStatus

# =============================================================================
# Fixtures for PCAP simulation
# =============================================================================

@pytest.fixture
def valid_pcap_content() -> bytes:
    """Known-good PCAP fixture bytes used by other integration tests."""
    fixture_path = Path("tests/test_data/test_bidirectional.pcap")
    return fixture_path.read_bytes()

@pytest.fixture
def corrupted_pcap_content() -> bytes:
    """Malformed PCAP content (invalid magic number)."""
    return b"NOT_A_PCAP_FILE_AT_ALL"

# =============================================================================
# Tests
# =============================================================================

@pytest.mark.integration
@pytest.mark.asyncio
async def test_upload_lifecycle_success(api_client, auth_with_csrf, valid_pcap_content):
    """
    Test successful upload of a valid PCAP.
    Expected: 202 Accepted + Task creation with pending status.
    """
    files = {"file": ("test.pcap", io.BytesIO(valid_pcap_content), "application/octet-stream")}
    
    response = await api_client.post(
        "/api/upload", 
        headers=auth_with_csrf,
        files=files
    )
    
    assert response.status_code == status.HTTP_202_ACCEPTED
    data = response.json()
    assert "task_id" in data
    assert data["status"] == "pending"
    assert data["filename"] == "test.pcap"

@pytest.mark.integration
@pytest.mark.asyncio
async def test_upload_non_pcap_rejected(api_client, auth_with_csrf, corrupted_pcap_content):
    """
    Test upload of a file with invalid magic bytes.
    Expected: 400 Bad Request.
    """
    # Use .pcap extension but with corrupted content to bypass extension check 
    # and hit the magic number check.
    files = {"file": ("test.pcap", io.BytesIO(corrupted_pcap_content), "application/octet-stream")}
    
    response = await api_client.post(
        "/api/upload",
        headers=auth_with_csrf,
        files=files
    )
    
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "magic number" in response.json()["detail"].lower()

@pytest.mark.integration
@pytest.mark.asyncio
async def test_upload_oversized_rejected(api_client, auth_with_csrf):
    """
    Test upload of a file exceeding size limits.
    Expected: 413 Payload Too Large.
    """
    # 10MB to exceed a simulated 5MB limit
    huge_data = b"\x00" * (1024 * 1024 * 10) 
    
    # Patch the correct module where the constant is defined
    from unittest.mock import patch
    with patch("app.utils.file_validator.MAX_UPLOAD_SIZE_MB", 5): # 5MB limit
        files = {"file": ("large.pcap", io.BytesIO(huge_data), "application/octet-stream")}
        response = await api_client.post(
            "/api/upload",
            headers=auth_with_csrf,
            files=files
        )
        assert response.status_code == status.HTTP_413_CONTENT_TOO_LARGE
        assert "too large" in response.json()["detail"].lower()

@pytest.mark.integration
@pytest.mark.asyncio
async def test_upload_unauthenticated_rejected(api_client, valid_pcap_content):
    """
    Test upload without authentication or CSRF.
    Expected: 403 Forbidden.
    """
    files = {"file": ("test.pcap", io.BytesIO(valid_pcap_content), "application/octet-stream")}
    
    response = await api_client.post("/api/upload", files=files)
    assert response.status_code == status.HTTP_403_FORBIDDEN
