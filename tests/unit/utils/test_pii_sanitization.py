"""
Tests unitaires pour la sanitization des PII et des erreurs.
"""

import pytest
import os
from src.utils.pii_redactor import (
    PIIRedactor, RedactionLevel, redact_for_logging, 
    redact_ip_addresses, redact_credentials, redact_file_paths
)
from src.utils.error_sanitizer import sanitize_error_message, sanitize_error_for_display

def test_ip_redaction_production():
    """Test IP redaction in PRODUCTION mode (with prefix preservation)."""
    text = "Connection from 192.168.1.100 to 10.0.0.1"
    # Default is PRODUCTION with prefix preservation
    redacted = redact_ip_addresses(text, preserve_prefix=True)
    assert "192.168.XXX.XXX" in redacted
    assert "10.0.XXX.XXX" in redacted
    assert "1.100" not in redacted

def test_ipv6_redaction():
    """Test IPv6 redaction."""
    text = "IPv6 address: 2001:db8:85a3:0000:0000:8a2e:0370:7334"
    redacted = redact_for_logging(text, level='PRODUCTION')
    assert "2001:db8::[REDACTED]" in redacted
    assert "7334" not in redacted

def test_credential_redaction():
    """Test redaction of various credential types."""
    credentials = [
        "password=mysecret123",
        "api_key: sk-123456789",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "postgresql://user:pass123@localhost:5432/db"
    ]
    
    for cred in credentials:
        redacted = redact_credentials(cred)
        assert "[CREDENTIAL_REDACTED]" in redacted
        assert "mysecret123" not in redacted
        assert "pass123" not in redacted

def test_path_redaction():
    """Test redaction of usernames in file paths."""
    paths = [
        "/home/john_doe/capture.pcap",
        "/Users/alice/Documents/test.pcap",
        "C:\\Users\\Bob\\Desktop\\logs.txt"
    ]
    
    for path in paths:
        redacted = redact_file_paths(path)
        assert "[USER]" in redacted
        assert "john_doe" not in redacted
        assert "alice" not in redacted
        assert "Bob" not in redacted

def test_redaction_levels(monkeypatch):
    """Test master redaction function across different levels."""
    text = "IP 1.2.3.4 and password=secret"
    
    # PRODUCTION: Redact everything
    assert "1.2.XXX.XXX" in redact_for_logging(text, level='PRODUCTION')
    assert "[CREDENTIAL_REDACTED]" in redact_for_logging(text, level='PRODUCTION')
    
    # DEVELOPMENT: Keep IP, redact credentials
    dev_redacted = redact_for_logging(text, level='DEVELOPMENT')
    assert "1.2.3.4" in dev_redacted
    assert "[CREDENTIAL_REDACTED]" in dev_redacted
    
    # DEBUG: No redaction
    assert redact_for_logging(text, level='DEBUG') == text

def test_error_message_sanitization():
    """Test general error message sanitization (CWE-209)."""
    msg = "Failed to open /home/user/data.pcap: Permission denied in Python 3.11.2"
    sanitized = sanitize_error_message(msg)
    
    assert "[USER]" in sanitized
    assert "john_doe" not in sanitized
    assert "[VERSION_REDACTED]" in sanitized
    assert "3.11.2" not in sanitized

def test_exception_to_safe_message():
    """Test converting real exceptions to safe user-facing messages."""
    # FileNotFoundError
    err = FileNotFoundError("/etc/shadow")
    safe = sanitize_error_for_display(err, "Configuration")
    assert "Configuration: File not found" == safe
    assert "/etc/shadow" not in safe
    
    # Generic Exception
    err = RuntimeError("Database connection timed out with pool_size=20")
    safe = sanitize_error_for_display(err)
    assert safe == "Runtime error occurred"
    assert "pool_size" not in safe
