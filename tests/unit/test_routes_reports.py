"""
Tests unitaires pour les routes de rapports
"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.unit
def test_get_html_report_nonexistent(client: TestClient):
    """Test getting HTML report for non-existent task"""
    response = client.get("/api/reports/nonexistent/html")

    assert response.status_code == 404


@pytest.mark.unit
def test_get_json_report_nonexistent(client: TestClient):
    """Test getting JSON report for non-existent task"""
    response = client.get("/api/reports/nonexistent/json")

    assert response.status_code == 404


@pytest.mark.unit
def test_delete_report_nonexistent(client: TestClient):
    """Test deleting report for non-existent task"""
    response = client.delete("/api/reports/nonexistent")

    assert response.status_code == 404


@pytest.mark.unit
def test_list_reports(client: TestClient):
    """Test listing available reports"""
    response = client.get("/api/reports")

    assert response.status_code == 200
    data = response.json()

    assert "reports" in data
    assert "count" in data
    assert isinstance(data["reports"], list)
