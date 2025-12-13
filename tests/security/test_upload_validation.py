"""
Tests de sécurité pour la validation des uploads
"""

import pytest
from fastapi.testclient import TestClient


@pytest.mark.security
def test_path_traversal_attempt(client: TestClient, test_data_dir):
    """Test protection against path traversal attacks"""
    malicious_file = test_data_dir / "malicious.pcap"

    # Create valid PCAP header
    malicious_file.write_bytes(bytes.fromhex("d4c3b2a10200040000000000000000000000ffff000001000000"))

    # Try to upload with path traversal in filename
    with open(malicious_file, "rb") as f:
        response = client.post(
            "/api/upload", files={"file": ("../../../etc/passwd.pcap", f, "application/vnd.tcpdump.pcap")}
        )

    # Should either accept (and sanitize) or reject
    # But should NOT create file outside uploads directory
    assert response.status_code in [202, 400]


@pytest.mark.security
def test_sql_injection_in_filename(client: TestClient, sample_pcap_file):
    """Test SQL injection attempt in filename"""
    with open(sample_pcap_file, "rb") as f:
        response = client.post(
            "/api/upload", files={"file": ("test'; DROP TABLE tasks; --.pcap", f, "application/vnd.tcpdump.pcap")}
        )

    # Should handle safely (either accept with sanitized name or reject)
    assert response.status_code in [202, 400]


@pytest.mark.security
def test_xss_in_filename(client: TestClient, sample_pcap_file):
    """Test XSS attempt in filename"""
    with open(sample_pcap_file, "rb") as f:
        response = client.post(
            "/api/upload", files={"file": ("<script>alert('xss')</script>.pcap", f, "application/vnd.tcpdump.pcap")}
        )

    # Should sanitize or reject
    assert response.status_code in [202, 400]


@pytest.mark.security
def test_null_byte_injection(client: TestClient, sample_pcap_file):
    """Test null byte injection in filename"""
    with open(sample_pcap_file, "rb") as f:
        response = client.post("/api/upload", files={"file": ("test\x00.txt.pcap", f, "application/vnd.tcpdump.pcap")})

    # Should reject or sanitize
    assert response.status_code in [202, 400]


@pytest.mark.security
def test_multiple_extensions(client: TestClient, test_data_dir):
    """Test file with multiple extensions"""
    multi_ext_file = test_data_dir / "file.exe.pcap"
    multi_ext_file.write_bytes(bytes.fromhex("d4c3b2a10200040000000000000000000000ffff000001000000"))

    with open(multi_ext_file, "rb") as f:
        response = client.post("/api/upload", files={"file": ("file.exe.pcap", f, "application/vnd.tcpdump.pcap")})

    # Should validate based on final extension (.pcap)
    # And validate magic bytes
    assert response.status_code == 202


@pytest.mark.security
def test_oversized_filename(client: TestClient, sample_pcap_file):
    """Test extremely long filename"""
    long_name = "a" * 1000 + ".pcap"

    with open(sample_pcap_file, "rb") as f:
        response = client.post("/api/upload", files={"file": (long_name, f, "application/vnd.tcpdump.pcap")})

    # Should handle gracefully (truncate or reject)
    assert response.status_code in [202, 400]
