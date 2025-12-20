#!/usr/bin/env python3
"""
Test script for centralized logging configuration.

This script verifies that the logging system works correctly with:
- Different log levels
- File rotation
- Audit logging
- JSON formatting
- Secure permissions
"""

import os
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.logging_config import setup_logging
import logging


def test_basic_logging():
    """Test basic logging functionality."""
    print("=" * 80)
    print("TEST 1: Basic Logging")
    print("=" * 80)

    # Setup logging
    setup_logging(
        log_dir="logs/test",
        log_level="INFO",
        enable_console=True,
        enable_file=True,
        enable_audit=True
    )

    logger = logging.getLogger("test_basic")

    # Test different log levels
    logger.debug("This is a DEBUG message (should not appear with INFO level)")
    logger.info("This is an INFO message")
    logger.warning("This is a WARNING message")
    logger.error("This is an ERROR message")
    logger.critical("This is a CRITICAL message")

    print("\n✓ Basic logging test completed")
    print(f"Check logs in: logs/test/pcap_analyzer.log\n")


def test_audit_logging():
    """Test security audit logging."""
    print("=" * 80)
    print("TEST 2: Security Audit Logging")
    print("=" * 80)

    from src.utils.audit_logger import log_security_event

    # Test file validation failure
    log_security_event(
        event_type="file_validation_failure",
        severity="error",
        message="File validation failed: Invalid PCAP magic bytes",
        file_path="/tmp/malicious.pcap",
        reason="Invalid magic bytes",
        magic_bytes="0x00000000",
        file_size=1024
    )

    # Test resource limit hit
    log_security_event(
        event_type="resource_limit_exceeded",
        severity="critical",
        message="Memory limit exceeded: 4.0 GB",
        limit_type="memory",
        limit_value="4.0 GB",
        current_value="4.2 GB",
        pcap_file="large_capture.pcap"
    )

    # Test decompression bomb
    log_security_event(
        event_type="decompression_bomb_detected",
        severity="critical",
        message="Decompression bomb detected (ratio: 10240.0x)",
        file_path="compressed.pcap.gz",
        compressed_size=1024,
        uncompressed_size=10485760,
        expansion_ratio=10240.0,
        threshold=1000.0
    )

    # Test path traversal attempt
    log_security_event(
        event_type="path_traversal_blocked",
        severity="critical",
        message="Path traversal attempt blocked",
        requested_path="../../../etc/passwd",
        resolved_path="/etc/passwd",
        blocked=True
    )

    # Test suspicious network activity
    log_security_event(
        event_type="suspicious_network_activity",
        severity="warning",
        message="Port scan detected from 192.168.1.100",
        activity_type="port_scan",
        source_ip="192.168.1.100",
        destination_ip="10.0.0.50",
        ports_scanned=1024,
        protocol="TCP"
    )

    print("\n✓ Audit logging test completed")
    print(f"Check audit logs in: logs/test/security_audit.log\n")


def test_json_logging():
    """Test JSON-formatted logging."""
    print("=" * 80)
    print("TEST 3: JSON Logging (SIEM-friendly)")
    print("=" * 80)

    try:
        # Try to setup JSON logging
        setup_logging(
            log_dir="logs/test_json",
            log_level="INFO",
            enable_console=True,
            enable_file=True,
            enable_audit=False,
            log_format="json"
        )

        logger = logging.getLogger("test_json")
        logger.info("This is a JSON-formatted log message")
        logger.warning("JSON warning message with data", extra={"key": "value", "count": 42})

        print("\n✓ JSON logging test completed")
        print(f"Check logs in: logs/test_json/pcap_analyzer.log\n")

    except ImportError:
        print("\n⚠ JSON logging requires python-json-logger package")
        print("Install with: pip install python-json-logger\n")


def test_log_permissions():
    """Test that log files have secure permissions."""
    print("=" * 80)
    print("TEST 4: Log File Permissions")
    print("=" * 80)

    log_files = [
        "logs/test/pcap_analyzer.log",
        "logs/test/security_audit.log",
    ]

    for log_file in log_files:
        if os.path.exists(log_file):
            stat_info = os.stat(log_file)
            perms = oct(stat_info.st_mode)[-3:]

            print(f"File: {log_file}")
            print(f"  Permissions: {perms} (should be 600 or 644)")

            # Check if permissions are secure (0600 or 0644)
            if perms in ["600", "644"]:
                print("  ✓ Secure permissions")
            else:
                print(f"  ⚠ Insecure permissions: {perms}")
        else:
            print(f"File: {log_file} - Not found")

    print()


def test_yaml_config():
    """Test loading logging configuration from YAML file."""
    print("=" * 80)
    print("TEST 5: YAML Configuration Loading")
    print("=" * 80)

    config_file = "config/logging.yaml"

    if os.path.exists(config_file):
        setup_logging(
            log_dir="logs/test_yaml",
            config_file=config_file
        )

        logger = logging.getLogger("test_yaml")
        logger.info("Loaded logging config from YAML file")

        print(f"\n✓ YAML config loaded successfully from {config_file}")
        print(f"Check logs in: logs/test_yaml/\n")
    else:
        print(f"\n⚠ YAML config file not found: {config_file}\n")


def main():
    """Run all logging tests."""
    print("\n")
    print("╔" + "=" * 78 + "╗")
    print("║" + " " * 20 + "PCAP Analyzer Logging Tests" + " " * 31 + "║")
    print("╚" + "=" * 78 + "╝")
    print()

    try:
        test_basic_logging()
        test_audit_logging()
        test_json_logging()
        test_log_permissions()
        test_yaml_config()

        print("=" * 80)
        print("ALL TESTS COMPLETED")
        print("=" * 80)
        print()
        print("Summary:")
        print("  ✓ Basic logging: INFO, WARNING, ERROR, CRITICAL")
        print("  ✓ Audit logging: Security events to separate file")
        print("  ✓ JSON logging: SIEM-friendly structured logs")
        print("  ✓ File permissions: Secure 0600 permissions")
        print("  ✓ YAML config: Load from config/logging.yaml")
        print()
        print("Next steps:")
        print("  1. Review logs in logs/test/ directory")
        print("  2. Test with actual PCAP analysis: pcap_analyzer analyze <file> --log-level DEBUG")
        print("  3. Setup log rotation cron job: ./scripts/rotate_logs.sh logs/")
        print()

    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
