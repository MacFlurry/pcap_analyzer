"""
Tests unitaires pour les routes de rapports
"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.unit
def test_get_html_report_nonexistent(client: TestClient):
    """Test getting HTML report for non-existent task"""
    response = client.get("/api/reports/550e8400-e29b-41d4-a716-446655440000/html")

    assert response.status_code == 404


@pytest.mark.unit
def test_get_json_report_nonexistent(client: TestClient):
    """Test getting JSON report for non-existent task"""
    response = client.get("/api/reports/550e8400-e29b-41d4-a716-446655440000/json")

    assert response.status_code == 404


@pytest.mark.unit
def test_delete_report_nonexistent(client: TestClient):
    """Test deleting report for non-existent task"""
    response = client.delete("/api/reports/550e8400-e29b-41d4-a716-446655440000")

    assert response.status_code == 404
