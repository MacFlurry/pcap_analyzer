"""
Tests unitaires pour la route health check
"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.unit
def test_health_check(client: TestClient):
    """Test health check endpoint"""
    response = client.get("/api/health")

    assert response.status_code == 200
    data = response.json()

    # Required fields
    assert "status" in data
    assert "version" in data
    assert "uptime_seconds" in data
    assert "memory_usage_percent" in data
    assert "disk_space_gb_available" in data

    # Values
    assert data["status"] == "healthy"
    assert data["version"] == "4.28.3"
    assert data["uptime_seconds"] >= 0
    assert 0 <= data["memory_usage_percent"] <= 100
