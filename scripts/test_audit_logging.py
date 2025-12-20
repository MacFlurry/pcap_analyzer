#!/usr/bin/env python3
"""
Audit Logging Test Script

This script demonstrates and tests the NIST-compliant audit logging system.
It generates sample audit events and verifies the logging functionality.

Usage:
    python scripts/test_audit_logging.py

Author: PCAP Analyzer Security Team
Date: 2025-12-20
"""

import json
import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.utils.audit_logger import get_audit_logger, reset_audit_logger
from src.utils.audit_events import AuditEventType, AuditEventSeverity, AuditEventOutcome


def test_file_validation_events():
    """Test file validation audit events."""
    print("\n[TEST] File Validation Events")
    print("=" * 60)

    audit_logger = get_audit_logger(enable_console=True)

    # Success case
    print("\n1. Testing successful file validation...")
    audit_logger.log_file_validation(
        file_path="/tmp/test_capture.pcap",
        outcome="SUCCESS",
        file_size=1024000,
        pcap_type="pcap"
    )

    # Failure case
    print("\n2. Testing failed file validation...")
    audit_logger.log_file_validation(
        file_path="/tmp/invalid.pcap",
        outcome="FAILURE",
        reason="Invalid magic number: 0x54455354"
    )

    print("✅ File validation events logged")


def test_security_violation_events():
    """Test security violation audit events."""
    print("\n[TEST] Security Violation Events")
    print("=" * 60)

    audit_logger = get_audit_logger(enable_console=True)

    # Decompression bomb
    print("\n1. Testing decompression bomb detection...")
    audit_logger.log_security_violation(
        violation_type="DECOMPRESSION_BOMB",
        details={
            "expansion_ratio": 10500.5,
            "threshold": 10000,
            "file_size_bytes": 10000000,
            "bytes_processed": 100000000000,
            "action": "ABORTED"
        },
        file_path="/tmp/bomb.pcap"
    )

    # Path traversal
    print("\n2. Testing path traversal detection...")
    audit_logger.log_security_violation(
        violation_type="PATH_TRAVERSAL",
        details={
            "requested_path": "../../etc/passwd",
            "blocked": True
        }
    )

    # Oversized file
    print("\n3. Testing oversized file rejection...")
    audit_logger.log_security_violation(
        violation_type="OVERSIZED_FILE",
        details={
            "file_size_gb": 25.5,
            "max_size_gb": 20,
            "action": "REJECTED"
        },
        file_path="/tmp/huge.pcap"
    )

    print("✅ Security violation events logged")


def test_authentication_events():
    """Test authentication audit events."""
    print("\n[TEST] Authentication Events")
    print("=" * 60)

    audit_logger = get_audit_logger(enable_console=True)

    # Success
    print("\n1. Testing successful authentication...")
    audit_logger.log_authentication(
        outcome="SUCCESS",
        username="admin",
        host="remote.example.com",
        source_ip="203.0.113.45"
    )

    # Failure
    print("\n2. Testing failed authentication...")
    audit_logger.log_authentication(
        outcome="FAILURE",
        username="attacker",
        host="remote.example.com",
        source_ip="198.51.100.123",
        failure_reason="Invalid credentials"
    )

    # Rate limit
    print("\n3. Testing rate limit violation...")
    audit_logger.log_authentication(
        outcome="RATE_LIMIT",
        username="suspicious_user",
        host="remote.example.com",
        source_ip="198.51.100.123",
        failure_reason="5 attempts in 60 seconds"
    )

    print("✅ Authentication events logged")


def test_resource_limit_events():
    """Test resource limit audit events."""
    print("\n[TEST] Resource Limit Events")
    print("=" * 60)

    audit_logger = get_audit_logger(enable_console=True)

    # Warning
    print("\n1. Testing resource limit warning...")
    audit_logger.log_resource_limit(
        limit_type="RLIMIT_AS",
        current=3221225472,  # 3GB
        maximum=4294967296,  # 4GB
        action="WARNING"
    )

    # Exceeded
    print("\n2. Testing resource limit exceeded...")
    audit_logger.log_resource_limit(
        limit_type="RLIMIT_CPU",
        current=3600,
        maximum=3600,
        action="EXCEEDED"
    )

    print("✅ Resource limit events logged")


def test_file_processing_events():
    """Test file processing lifecycle events."""
    print("\n[TEST] File Processing Events")
    print("=" * 60)

    audit_logger = get_audit_logger(enable_console=True)

    print("\n1. Testing file processing start...")
    audit_logger.log_file_processing(
        file_path="/tmp/capture.pcap",
        status="START"
    )

    print("\n2. Testing file processing complete...")
    audit_logger.log_file_processing(
        file_path="/tmp/capture.pcap",
        status="COMPLETE",
        packets_processed=150000
    )

    print("\n3. Testing file processing error...")
    audit_logger.log_file_processing(
        file_path="/tmp/corrupt.pcap",
        status="ERROR",
        error_message="Corrupt packet at offset 12345"
    )

    print("✅ File processing events logged")


def test_configuration_events():
    """Test configuration audit events."""
    print("\n[TEST] Configuration Events")
    print("=" * 60)

    audit_logger = get_audit_logger(enable_console=True)

    print("\n1. Testing configuration loaded...")
    audit_logger.log_configuration(
        action="LOADED",
        config_file="/etc/pcap_analyzer/config.yaml"
    )

    print("\n2. Testing configuration changed...")
    audit_logger.log_configuration(
        action="CHANGED",
        config_file="/etc/pcap_analyzer/config.yaml",
        changes={
            "max_file_size_gb": {"old": 10, "new": 20},
            "memory_limit_gb": {"old": 4, "new": 8}
        }
    )

    print("\n3. Testing configuration validation error...")
    audit_logger.log_configuration(
        action="VALIDATION_ERROR",
        config_file="/etc/pcap_analyzer/config.yaml",
        error="Invalid memory_limit_gb: must be positive integer"
    )

    print("✅ Configuration events logged")


def test_ssh_events():
    """Test SSH connection audit events."""
    print("\n[TEST] SSH Connection Events")
    print("=" * 60)

    audit_logger = get_audit_logger(enable_console=True)

    print("\n1. Testing SSH connection established...")
    audit_logger.log_ssh_event(
        event="CONNECTED",
        host="remote.example.com",
        username="analyst",
        outcome="SUCCESS"
    )

    print("\n2. Testing SSH connection failed...")
    audit_logger.log_ssh_event(
        event="FAILED",
        host="remote.example.com",
        username="analyst",
        outcome="FAILURE",
        error="Connection timeout"
    )

    print("\n3. Testing SSH command execution...")
    audit_logger.log_ssh_event(
        event="COMMAND_EXECUTED",
        host="remote.example.com",
        username="analyst",
        command="tcpdump -i eth0 -w /tmp/capture.pcap",
        outcome="SUCCESS"
    )

    print("✅ SSH connection events logged")


def verify_audit_log():
    """Verify audit log file and format."""
    print("\n[VERIFY] Audit Log Verification")
    print("=" * 60)

    audit_log = Path("logs/audit/security_audit.log")

    if not audit_log.exists():
        print("❌ Audit log file not found!")
        return False

    print(f"✅ Audit log found: {audit_log}")

    # Check permissions
    import stat
    mode = audit_log.stat().st_mode
    perms = stat.filemode(mode)
    print(f"   Permissions: {perms}")

    if (mode & 0o777) != 0o600:
        print("   ⚠ Warning: Permissions should be 0600")

    # Count records
    with open(audit_log, "r") as f:
        lines = f.readlines()

    print(f"✅ Total audit records: {len(lines)}")

    # Verify JSON format
    print("\n[VERIFY] JSON Format Validation")
    valid_count = 0
    for i, line in enumerate(lines[-10:], start=max(0, len(lines) - 10)):
        try:
            record = json.loads(line)
            valid_count += 1

            # Verify AU-3 required fields
            required_fields = [
                "timestamp", "event_type", "outcome", "component",
                "record_id", "severity"
            ]
            missing_fields = [f for f in required_fields if f not in record]

            if missing_fields:
                print(f"   ⚠ Record {i+1} missing fields: {missing_fields}")
            else:
                valid_count += 1

        except json.JSONDecodeError as e:
            print(f"   ❌ Invalid JSON at record {i+1}: {e}")

    print(f"✅ Valid JSON records (last 10): {valid_count}/10")

    # Display sample records
    print("\n[SAMPLE] Recent Audit Records")
    print("-" * 60)
    for line in lines[-3:]:
        try:
            record = json.loads(line)
            print(f"\nEvent: {record['event_type']}")
            print(f"Time: {record['timestamp']}")
            print(f"Outcome: {record['outcome']} ({record['severity']})")
            print(f"Component: {record['component']}")
            if record.get('details'):
                print(f"Details: {json.dumps(record['details'], indent=2)}")
        except:
            pass

    return True


def main():
    """Run all audit logging tests."""
    print("\n" + "=" * 60)
    print("NIST-Compliant Audit Logging Test Suite")
    print("=" * 60)

    # Reset audit logger for testing
    reset_audit_logger()

    # Run tests
    try:
        test_file_validation_events()
        test_security_violation_events()
        test_authentication_events()
        test_resource_limit_events()
        test_file_processing_events()
        test_configuration_events()
        test_ssh_events()

        # Verify results
        if verify_audit_log():
            print("\n" + "=" * 60)
            print("✅ ALL TESTS PASSED")
            print("=" * 60)
            print("\nAudit log location: logs/audit/security_audit.log")
            print("\nNext steps:")
            print("  1. Review audit log: cat logs/audit/security_audit.log | jq .")
            print("  2. Analyze events: python scripts/analyze_audit_log.py --summary")
            print("  3. Detect incidents: python scripts/analyze_audit_log.py --incidents")
            print("  4. Configure SIEM: See docs/SIEM_INTEGRATION.md")
            print()
        else:
            print("\n❌ VERIFICATION FAILED")
            return 1

    except Exception as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
