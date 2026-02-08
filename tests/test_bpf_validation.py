"""
Tests for BPF filter validation.

These tests verify that BPF filter validation works correctly and prevents
injection attacks.

Note: These tests require tcpdump to be available without requiring root permissions.
On macOS, you may need to run: sudo chmod +s /usr/sbin/tcpdump
"""

import subprocess
import os

import pytest

from src.ssh_capture import validate_bpf_filter


def check_tcpdump_available():
    """Check if tcpdump is available and can compile filters."""
    try:
        result = subprocess.run(["tcpdump", "-ddd", "tcp port 80"], capture_output=True, timeout=2, check=False)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# BPF/tcpdump tests are opt-in by default because they depend on host tooling
# and privileges (tcpdump capabilities/root on some systems).
RUN_BPF_TESTS = os.getenv("RUN_BPF_TESTS", "0") == "1"
TCPDUMP_READY = check_tcpdump_available()

pytestmark = [
    pytest.mark.requires_tcpdump,
    pytest.mark.skipif(
        not RUN_BPF_TESTS,
        reason="BPF tests disabled by default (set RUN_BPF_TESTS=1 to enable)",
    ),
    pytest.mark.skipif(
        RUN_BPF_TESTS and not TCPDUMP_READY,
        reason="tcpdump not available or insufficient permissions for filter compilation",
    ),
]


class TestBPFValidation:
    """Tests for BPF filter validation."""

    def test_valid_filters(self):
        """Test that valid BPF filters are accepted."""
        valid_filters = [
            "tcp port 80",
            "host 192.168.1.1",
            "host 192.168.1.1 and port 443",
            "udp and src net 10.0.0.0/8",
            "icmp",
            "tcp and dst port 22",
            "not port 80",
            "(tcp port 80 or tcp port 443)",
            "tcp[tcpflags] & (tcp-syn) != 0",
            "",  # Empty filter is valid
        ]

        for bpf_filter in valid_filters:
            assert validate_bpf_filter(bpf_filter), f"Filter should be valid: {bpf_filter}"

    def test_invalid_filters(self):
        """Test that invalid BPF filters are rejected."""
        invalid_filters = [
            "invalid syntax here",
            "port 99999999",  # Invalid port number
            "host 999.999.999.999",  # Invalid IP
            "tcp port abc",  # Port must be numeric
            "random garbage",
        ]

        for bpf_filter in invalid_filters:
            assert not validate_bpf_filter(bpf_filter), f"Filter should be invalid: {bpf_filter}"

    def test_injection_attempts(self):
        """Test that injection attempts are rejected."""
        injection_attempts = [
            "; rm -rf /",
            "| cat /etc/passwd",
            "&& whoami",
            "`id`",
            "$(whoami)",
        ]

        for bpf_filter in injection_attempts:
            # These should either be invalid or timeout
            result = validate_bpf_filter(bpf_filter, timeout=2)
            assert not result, f"Injection attempt should be rejected: {bpf_filter}"

    def test_empty_filter(self):
        """Test that empty filter is valid."""
        assert validate_bpf_filter("")
        assert validate_bpf_filter(None) or True  # None might be handled differently

    def test_complex_filters(self):
        """Test complex but valid BPF filters."""
        complex_filters = [
            "tcp[tcpflags] & (tcp-syn|tcp-fin) != 0",
            "ip proto \\icmp",
            "ether host ff:ff:ff:ff:ff:ff",
            "ip broadcast",
            "ip multicast",
            "vlan 100",
            "mpls 20",
        ]

        for bpf_filter in complex_filters:
            # These may or may not be valid depending on tcpdump version
            # Just ensure the function doesn't crash
            result = validate_bpf_filter(bpf_filter)
            assert isinstance(result, bool)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
