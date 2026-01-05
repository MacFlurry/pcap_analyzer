"""
Tests unitaires pour les routes d'upload
"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.unit
def test_upload_valid_pcap(client: TestClient, sample_pcap_file):
    """Test uploading a valid PCAP file"""
    with open(sample_pcap_file, "rb") as f:
        response = client.post("/api/upload", files={"file": ("test.pcap", f, "application/vnd.tcpdump.pcap")})

    assert response.status_code == 202  # Accepted
    data = response.json()

    assert "task_id" in data
    assert data["filename"] == "test.pcap"
    assert data["status"] == "pending"
    assert "progress_url" in data


@pytest.mark.unit
def test_upload_invalid_extension(client: TestClient, test_data_dir):
    """Test uploading file with invalid extension"""
    invalid_file = test_data_dir / "test.txt"
    invalid_file.write_text("not a pcap")

    with open(invalid_file, "rb") as f:
        response = client.post("/api/upload", files={"file": ("test.txt", f, "text/plain")})

    assert response.status_code == 400
    assert "Invalid file extension" in response.json()["detail"]


@pytest.mark.unit
def test_upload_invalid_magic_bytes(client: TestClient, invalid_pcap_file):
    """Test uploading file with invalid PCAP magic bytes"""
    with open(invalid_pcap_file, "rb") as f:
        response = client.post("/api/upload", files={"file": ("invalid.pcap", f, "application/vnd.tcpdump.pcap")})

    assert response.status_code == 400
    assert "invalid" in response.json()["detail"].lower()


@pytest.mark.unit
@pytest.mark.slow
def test_upload_file_too_large(client: TestClient, large_file):
    """Test uploading a file that exceeds size limit"""
    with open(large_file, "rb") as f:
        response = client.post("/api/upload", files={"file": ("large.pcap", f, "application/vnd.tcpdump.pcap")})

    assert response.status_code in [400, 413]  # Bad Request or Payload Too Large


@pytest.mark.unit
def test_upload_empty_file(client: TestClient, test_data_dir):
    """Test uploading an empty file"""
    empty_file = test_data_dir / "empty.pcap"
    empty_file.write_bytes(b"")

    with open(empty_file, "rb") as f:
        response = client.post("/api/upload", files={"file": ("empty.pcap", f, "application/vnd.tcpdump.pcap")})

    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


@pytest.mark.unit
def test_get_queue_status(client: TestClient):
    """Test getting queue status"""
    response = client.get("/api/queue/status")

    assert response.status_code == 200
    data = response.json()

    assert "queue_size" in data
    assert "max_queue_size" in data
    assert "tasks_completed" in data
    assert data["max_queue_size"] == 5
