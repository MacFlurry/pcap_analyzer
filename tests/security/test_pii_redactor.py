"""
Security tests for PII redaction (GDPR Article 5(1)(c), CWE-532).

Tests:
- IPv4/IPv6 address redaction
- MAC address redaction
- File path username removal
- Credential redaction
- GDPR compliance modes
"""

import pytest

from src.utils.pii_redactor import (
    redact_ip_addresses,
    redact_mac_addresses,
    redact_file_paths,
    redact_credentials,
    PIIRedactor,
    RedactionLevel,
)


class TestIPAddressRedaction:
    """Test IP address redaction (GDPR Article 5(1)(c))."""

    def test_ipv4_redacted_with_prefix_preservation(self):
        """IPv4 addresses are redacted while preserving network prefix."""
        text = "Connection from 192.168.1.100 to 10.0.0.50"
        redacted = redact_ip_addresses(text, preserve_prefix=True)

        assert "192.168.XXX.XXX" in redacted
        assert "10.0.XXX.XXX" in redacted
        assert "192.168.1.100" not in redacted
        assert "10.0.0.50" not in redacted

    def test_ipv4_full_redaction(self):
        """IPv4 addresses are fully redacted without prefix."""
        text = "Server 172.16.254.1 responded"
        redacted = redact_ip_addresses(text, preserve_prefix=False)

        assert "[IP_REDACTED]" in redacted
        assert "172.16.254.1" not in redacted

    def test_ipv6_redacted_with_prefix(self):
        """IPv6 addresses are redacted with prefix preservation."""
        text = "IPv6 connection: 2001:0db8:85a3::8a2e:0370:7334"
        redacted = redact_ip_addresses(text, preserve_prefix=True)

        assert "2001:0db8::[REDACTED]" in redacted or "2001:db8::[REDACTED]" in redacted
        assert "8a2e:0370:7334" not in redacted

    def test_ipv6_full_redaction(self):
        """IPv6 addresses are fully redacted."""
        text = "Source: fe80::1"
        redacted = redact_ip_addresses(text, preserve_prefix=False)

        assert "[IP_REDACTED]" in redacted
        assert "fe80::1" not in redacted

    def test_multiple_ips_redacted(self):
        """Multiple IP addresses in same text are all redacted."""
        text = "Traffic: 192.168.1.10 -> 8.8.8.8, 10.1.1.1 -> 1.1.1.1"
        redacted = redact_ip_addresses(text, preserve_prefix=True)

        assert "192.168.1.10" not in redacted
        assert "8.8.8.8" not in redacted
        assert "10.1.1.1" not in redacted
        assert "1.1.1.1" not in redacted
        assert "XXX.XXX" in redacted

    def test_localhost_preserved_for_debugging(self):
        """Localhost (127.0.0.1, ::1) may be preserved as non-PII."""
        text = "Listening on 127.0.0.1:8080"
        redacted = redact_ip_addresses(text, preserve_prefix=True)

        # Implementation decision: localhost is not PII
        # This test documents expected behavior (may vary)
        assert "127.0.XXX.XXX" in redacted or "127.0.0.1" in redacted


class TestMACAddressRedaction:
    """Test MAC address redaction (GDPR)."""

    def test_mac_address_redacted(self):
        """MAC addresses are fully redacted."""
        text = "Device MAC: 00:11:22:33:44:55"
        redacted = redact_mac_addresses(text)

        assert "[MAC_REDACTED]" in redacted
        assert "00:11:22:33:44:55" not in redacted

    def test_mac_address_various_formats(self):
        """MAC addresses in various formats are redacted."""
        formats = [
            "00:11:22:33:44:55",  # Colon-separated
            "00-11-22-33-44-55",  # Dash-separated
            "0011.2233.4455",      # Cisco format
        ]

        for mac in formats:
            text = f"Interface: {mac}"
            redacted = redact_mac_addresses(text)
            assert mac not in redacted
            assert "[MAC_REDACTED]" in redacted

    def test_multiple_mac_addresses_redacted(self):
        """Multiple MAC addresses are all redacted."""
        text = "ARP: 00:11:22:33:44:55 -> aa:bb:cc:dd:ee:ff"
        redacted = redact_mac_addresses(text)

        assert "00:11:22:33:44:55" not in redacted
        assert "aa:bb:cc:dd:ee:ff" not in redacted
        assert redacted.count("[MAC_REDACTED]") == 2


class TestFilePathRedaction:
    """Test file path username redaction (GDPR)."""

    def test_unix_username_redacted(self):
        """Unix file paths have usernames redacted."""
        text = "Reading /home/alice/Documents/file.pcap"
        redacted = redact_file_paths(text)

        assert "/home/alice" not in redacted
        assert "/[USER]/" in redacted

    def test_macos_username_redacted(self):
        """macOS /Users paths have usernames redacted."""
        text = "Output: /Users/bob/Desktop/report.html"
        redacted = redact_file_paths(text)

        assert "/Users/bob" not in redacted
        assert "/[USER]/" in redacted

    def test_windows_username_redacted(self):
        """Windows paths have usernames redacted."""
        text = "File: C:\\Users\\charlie\\Downloads\\capture.pcap"
        redacted = redact_file_paths(text)

        assert "charlie" not in redacted
        assert "[USER]" in redacted

    def test_system_paths_preserved(self):
        """System paths without usernames are preserved."""
        system_paths = [
            "/var/log/pcap_analyzer/app.log",
            "/tmp/capture_temp.pcap",
            "C:\\Program Files\\PCAP Analyzer\\config.yaml",
        ]

        for path in system_paths:
            text = f"Using {path}"
            redacted = redact_file_paths(text)
            # System paths should remain (no user-specific PII)
            assert path in redacted or "/var/log" in redacted or "/tmp" in redacted


class TestCredentialRedaction:
    """Test credential redaction (CWE-532)."""

    def test_password_field_redacted(self):
        """Password fields are redacted."""
        text = "Config: username=admin password=Secret123"
        redacted = redact_credentials(text)

        assert "Secret123" not in redacted
        assert "[CREDENTIAL_REDACTED]" in redacted

    def test_api_key_redacted(self):
        """API keys are redacted."""
        text = "Using API key: test_api_1234567890abcdefghijklmnop"
        redacted = redact_credentials(text)

        assert "test_api_1234567890abcdefghijklmnop" not in redacted
        assert "[CREDENTIAL_REDACTED]" in redacted

    def test_bearer_token_redacted(self):
        """Bearer tokens are redacted."""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        redacted = redact_credentials(text)

        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
        assert "[CREDENTIAL_REDACTED]" in redacted

    def test_connection_string_credentials_redacted(self):
        """Database connection strings have credentials redacted."""
        text = "DB: postgresql://dbuser:dbpass@localhost:5432/mydb"
        redacted = redact_credentials(text)

        assert "dbuser" not in redacted or "[CREDENTIAL_REDACTED]" in redacted
        assert "dbpass" not in redacted


class TestPIIRedactorIntegration:
    """Test integrated PII redaction with different modes."""

    def test_production_mode_redacts_all_pii(self):
        """PRODUCTION mode redacts all PII."""
        redactor = PIIRedactor(level=RedactionLevel.PRODUCTION, preserve_network_prefixes=True)

        text = """
        Connection from 192.168.1.100:54321 to 10.0.0.50:22
        Device MAC: 00:11:22:33:44:55
        User: /home/alice/capture.pcap
        Password: secret123
        """

        redacted = redactor.redact(text)

        # All PII should be redacted
        assert "192.168.1.100" not in redacted
        assert "00:11:22:33:44:55" not in redacted
        assert "alice" not in redacted
        assert "secret123" not in redacted

    def test_development_mode_preserves_ips(self):
        """DEVELOPMENT mode preserves IPs but redacts credentials."""
        redactor = PIIRedactor(level=RedactionLevel.DEVELOPMENT)

        text = "Server 192.168.1.1 auth failed: password=wrong"

        redacted = redactor.redact(text)

        # IPs preserved in dev mode
        assert "192.168" in redacted
        # Credentials still redacted
        assert "wrong" not in redacted or "[CREDENTIAL_REDACTED]" in redacted

    def test_debug_mode_no_redaction(self):
        """DEBUG mode does not redact (WARNING: NOT GDPR-COMPLIANT)."""
        redactor = PIIRedactor(level=RedactionLevel.DEBUG)

        text = "IP: 192.168.1.1, MAC: 00:11:22:33:44:55, password=test"

        redacted = redactor.redact(text)

        # Nothing redacted in debug mode
        assert redacted == text

    def test_network_prefix_preservation_configurable(self):
        """Network prefix preservation is configurable."""
        redactor_with_prefix = PIIRedactor(
            level=RedactionLevel.PRODUCTION,
            preserve_network_prefixes=True
        )
        redactor_without_prefix = PIIRedactor(
            level=RedactionLevel.PRODUCTION,
            preserve_network_prefixes=False
        )

        text = "IP: 192.168.1.100"

        with_prefix = redactor_with_prefix.redact(text)
        without_prefix = redactor_without_prefix.redact(text)

        assert "192.168" in with_prefix
        assert "192.168" not in without_prefix
        assert "[IP_REDACTED]" in without_prefix


class TestGDPRCompliance:
    """Test GDPR compliance requirements."""

    def test_redaction_is_irreversible(self):
        """Redaction is one-way (cannot recover original data)."""
        redactor = PIIRedactor(level=RedactionLevel.PRODUCTION)

        original = "User at 192.168.1.100 accessed file"
        redacted = redactor.redact(original)

        # Cannot reverse redaction
        assert "192.168.1.100" not in redacted
        # Verify no encoding/encryption used (truly removed)
        assert len(redacted) < len(original) or "[REDACTED]" in redacted or "XXX" in redacted

    def test_redaction_logs_documented_legal_basis(self):
        """Redaction configuration documents legal basis (GDPR Art. 6)."""
        # This test verifies documentation exists
        # Actual legal basis: "legitimate_interest_security_monitoring" in config.yaml
        import yaml
        from pathlib import Path

        config_path = Path(__file__).parents[2] / "config.yaml"
        if config_path.exists():
            with open(config_path) as f:
                config = yaml.safe_load(f)

            legal_basis = config.get("logging", {}).get("pii_redaction", {}).get("legal_basis")
            assert legal_basis is not None
            assert "legitimate_interest" in legal_basis or "security" in legal_basis

    def test_retention_policy_documented(self):
        """Data retention policy is documented (GDPR Art. 5(1)(e))."""
        import yaml
        from pathlib import Path

        config_path = Path(__file__).parents[2] / "config.yaml"
        if config_path.exists():
            with open(config_path) as f:
                config = yaml.safe_load(f)

            retention_days = config.get("logging", {}).get("pii_redaction", {}).get("retention_days")
            assert retention_days is not None
            assert isinstance(retention_days, int)
            assert retention_days > 0  # Must have defined retention period


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
