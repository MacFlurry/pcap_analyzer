"""
Tests unitaires pour les routes de progression
"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.unit
def test_get_progress_nonexistent_task(client: TestClient):
    """Test getting progress for non-existent task"""
    response = client.get("/api/progress/nonexistent-task")

    # Should return 404 or start SSE stream with error
    assert response.status_code in [200, 404]


@pytest.mark.unit
def test_get_task_status_nonexistent(client: TestClient):
    """Test getting status for non-existent task"""
    response = client.get("/api/status/nonexistent-task")

    assert response.status_code == 404


@pytest.mark.unit
def test_get_history_empty(client: TestClient):
    """Test getting history when no tasks exist"""
    response = client.get("/api/history")

    assert response.status_code == 200
    data = response.json()

    assert "tasks" in data
    assert "count" in data
    assert isinstance(data["tasks"], list)


@pytest.mark.unit
def test_get_history_with_limit(client: TestClient):
    """Test getting history with limit parameter"""
    response = client.get("/api/history?limit=10")

    assert response.status_code == 200
    data = response.json()

    assert len(data["tasks"]) <= 10
