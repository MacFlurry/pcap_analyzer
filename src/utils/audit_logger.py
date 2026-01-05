"""
Centralized audit logger integrated with logging_config.

This module provides audit logging capabilities using the existing
audit_events framework and integrates with the centralized logging system.

NOTE: This is a simplified integration layer. The full NIST-compliant
audit logging system uses audit_events.py for event definitions.
"""

import logging
from typing import Any, Optional


def get_audit_logger(name: str = "audit") -> logging.Logger:
    """
    Get logger for security audit events.

    This logger writes to the security_audit.log file configured by
    the centralized logging system (logging_config.py).

    Args:
        name: Logger name (default: "audit")

    Returns:
        Logger instance configured for audit logging
    """
    return logging.getLogger(f"src.utils.audit_logger.{name}")


# Convenience logger instance
_audit_logger = get_audit_logger()


def log_security_event(event_type: str, severity: str, message: str, **details) -> None:
    """
    Log a security-relevant event to the audit log.

    Args:
        event_type: Type of security event
        severity: Severity level (info, warning, error, critical)
        message: Human-readable message
        **details: Additional structured data
    """
    # Build structured log entry
    log_parts = [f"event_type='{event_type}'", f"severity='{severity}'", f"message='{message}'"]

    if details:
        details_str = " | ".join([f"{k}='{v}'" for k, v in details.items()])
        log_parts.append(f"details={{{details_str}}}")

    log_message = " | ".join(log_parts)

    # Log at appropriate level
    if severity == "critical":
        _audit_logger.critical(log_message)
    elif severity == "error":
        _audit_logger.error(log_message)
    elif severity == "warning":
        _audit_logger.warning(log_message)
    else:
        _audit_logger.info(log_message)
