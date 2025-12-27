"""
NIST-Compliant Audit Event Definitions

This module defines audit event types according to NIST SP 800-53 AU-2 requirements.

STANDARDS COMPLIANCE:
- NIST SP 800-53 AU-2: Audit Events - Event identification and documentation
- NIST SP 800-53 AU-3: Content of Audit Records - Audit record requirements
- NIST SP 800-92: Guide to Computer Security Log Management
- ISO 27001 A.12.4.1: Event Logging
- PCI-DSS 10.2: Audit Trail Requirements

NIST AU-2 AUDITABLE EVENTS:
- Successful and unsuccessful account logon events
- Account management events
- Object access events (file validation, processing)
- Policy change events (configuration changes)
- Privilege functions (resource limit enforcement)
- Process tracking (analysis start/complete)
- System events (resource exhaustion, errors)

Author: PCAP Analyzer Security Team
Date: 2025-12-20
Version: 1.0.0
"""

from enum import Enum
from typing import Dict, Any


class AuditEventType(Enum):
    """
    Audit event types categorized according to NIST AU-2 requirements.

    Each event type represents a security-relevant event that must be logged
    for compliance, incident response, and security monitoring.

    Event naming convention: <category>.<subcategory>.<outcome>
    Example: file.validation.success
    """

    # ========================================================================
    # FILE OPERATIONS (NIST AU-2: Object Access)
    # ========================================================================

    # File validation events
    FILE_VALIDATION_SUCCESS = "file.validation.success"
    """Valid PCAP file passed all security checks (magic number, size)"""

    FILE_VALIDATION_FAILURE = "file.validation.failure"
    """File failed validation (invalid magic number, size violation)"""

    # File processing lifecycle
    FILE_PROCESSING_START = "file.processing.start"
    """PCAP file processing initiated"""

    FILE_PROCESSING_COMPLETE = "file.processing.complete"
    """PCAP file processing completed successfully"""

    FILE_PROCESSING_ERROR = "file.processing.error"
    """Error occurred during PCAP file processing"""

    FILE_PROCESSING_ABORTED = "file.processing.aborted"
    """File processing aborted due to security violation"""

    # ========================================================================
    # SECURITY VIOLATIONS (NIST AU-2: Security Events)
    # ========================================================================

    # Path traversal attacks (CWE-22)
    PATH_TRAVERSAL_ATTEMPT = "security.path_traversal.attempt"
    """Directory traversal attack attempt detected"""

    PATH_TRAVERSAL_BLOCKED = "security.path_traversal.blocked"
    """Directory traversal attack successfully blocked"""

    # Resource exhaustion attacks (CWE-770)
    RESOURCE_LIMIT_EXCEEDED = "security.resource_limit.exceeded"
    """OS-level resource limit exceeded (memory, CPU, file descriptors)"""

    RESOURCE_LIMIT_WARNING = "security.resource_limit.warning"
    """Resource usage approaching limit threshold"""

    # Decompression bomb attacks (CWE-409)
    DECOMPRESSION_BOMB_DETECTED = "security.decompression_bomb.detected"
    """Decompression bomb detected (abnormal expansion ratio)"""

    DECOMPRESSION_BOMB_WARNING = "security.decompression_bomb.warning"
    """High expansion ratio warning (potential decompression bomb)"""

    # File type validation failures (CWE-434)
    INVALID_FILE_TYPE = "security.invalid_file_type"
    """Invalid file magic number (file type mismatch)"""

    INVALID_FILE_SIGNATURE = "security.invalid_file_signature"
    """File signature does not match expected PCAP format"""

    # File size violations (CWE-770)
    OVERSIZED_FILE_REJECTED = "security.oversized_file.rejected"
    """File exceeds maximum allowed size"""

    UNDERSIZED_FILE_REJECTED = "security.undersized_file.rejected"
    """File too small to be valid PCAP (truncated/corrupt)"""

    # Command injection attempts (CWE-78)
    COMMAND_INJECTION_ATTEMPT = "security.command_injection.attempt"
    """Command injection attack attempt detected"""

    COMMAND_INJECTION_BLOCKED = "security.command_injection.blocked"
    """Command injection attack successfully blocked"""

    # ========================================================================
    # AUTHENTICATION EVENTS (NIST AU-2: Account Logon)
    # ========================================================================

    AUTH_SUCCESS = "auth.success"
    """Successful authentication (SSH, API)"""

    AUTH_FAILURE = "auth.failure"
    """Failed authentication attempt"""

    AUTH_RATE_LIMIT = "auth.rate_limit"
    """Authentication rate limit exceeded (potential brute force)"""

    AUTH_TIMEOUT = "auth.timeout"
    """Authentication timeout occurred"""

    AUTH_INVALID_CREDENTIALS = "auth.invalid_credentials"
    """Invalid credentials provided"""

    # ========================================================================
    # ACCESS CONTROL (NIST AU-2: Privilege Functions)
    # ========================================================================

    ACCESS_GRANTED = "access.granted"
    """Access granted to protected resource"""

    ACCESS_DENIED = "access.denied"
    """Access denied to protected resource"""

    PRIVILEGE_ESCALATION_ATTEMPT = "access.privilege_escalation.attempt"
    """Privilege escalation attempt detected"""

    PRIVILEGE_ESCALATION_BLOCKED = "access.privilege_escalation.blocked"
    """Privilege escalation attempt blocked"""

    PERMISSION_ERROR = "access.permission_error"
    """Permission error accessing resource"""

    # ========================================================================
    # CONFIGURATION MANAGEMENT (NIST AU-2: Policy Changes)
    # ========================================================================

    CONFIG_LOADED = "config.loaded"
    """Configuration file loaded successfully"""

    CONFIG_VALIDATION_ERROR = "config.validation.error"
    """Configuration validation failed"""

    CONFIG_CHANGED = "config.changed"
    """Configuration setting changed"""

    CONFIG_SECURITY_VIOLATION = "config.security.violation"
    """Security policy violation in configuration"""

    # ========================================================================
    # PROCESS TRACKING (NIST AU-2: Process Tracking)
    # ========================================================================

    ANALYSIS_STARTED = "analysis.started"
    """Analysis process started"""

    ANALYSIS_COMPLETED = "analysis.completed"
    """Analysis process completed successfully"""

    ANALYSIS_FAILED = "analysis.failed"
    """Analysis process failed"""

    ANALYZER_EXECUTION = "analyzer.execution"
    """Individual analyzer execution"""

    # ========================================================================
    # SYSTEM EVENTS (NIST AU-2: System Events)
    # ========================================================================

    SYSTEM_ERROR = "system.error"
    """System-level error occurred"""

    MEMORY_ERROR = "system.memory.error"
    """Memory allocation error (OOM condition)"""

    CPU_LIMIT_EXCEEDED = "system.cpu_limit.exceeded"
    """CPU time limit exceeded"""

    FILE_DESCRIPTOR_EXHAUSTION = "system.fd.exhausted"
    """File descriptor limit exhausted"""

    DISK_FULL = "system.disk.full"
    """Disk space exhausted"""

    # ========================================================================
    # NETWORK EVENTS (Application-specific)
    # ========================================================================

    SSH_CONNECTION_ESTABLISHED = "network.ssh.connected"
    """SSH connection established"""

    SSH_CONNECTION_FAILED = "network.ssh.failed"
    """SSH connection failed"""

    SSH_HOST_KEY_UNKNOWN = "network.ssh.host_key_unknown"
    """Unknown SSH host key (potential MITM)"""

    SSH_COMMAND_EXECUTED = "network.ssh.command_executed"
    """Command executed over SSH"""

    # ========================================================================
    # DATA PROTECTION (GDPR/PII)
    # ========================================================================

    PII_REDACTION_APPLIED = "data.pii.redacted"
    """PII redacted from logs/output"""

    PII_DETECTED = "data.pii.detected"
    """PII detected in data stream"""

    SENSITIVE_DATA_ACCESS = "data.sensitive.access"
    """Sensitive data accessed"""


class AuditEventSeverity(Enum):
    """
    Severity levels for audit events.

    Based on syslog severity levels (RFC 5424) and NIST severity categorization.
    """

    DEBUG = "DEBUG"
    """Debug-level messages for troubleshooting"""

    INFO = "INFO"
    """Informational messages (normal operations)"""

    NOTICE = "NOTICE"
    """Normal but significant condition"""

    WARNING = "WARNING"
    """Warning conditions (potential issues)"""

    ERROR = "ERROR"
    """Error conditions (functionality impaired)"""

    CRITICAL = "CRITICAL"
    """Critical conditions (system functionality at risk)"""

    ALERT = "ALERT"
    """Action must be taken immediately"""

    EMERGENCY = "EMERGENCY"
    """System is unusable"""


class AuditEventOutcome(Enum):
    """
    Outcome of auditable events.

    Per NIST AU-3: Each audit record must indicate success or failure.
    """

    SUCCESS = "SUCCESS"
    """Event completed successfully"""

    FAILURE = "FAILURE"
    """Event failed"""

    PARTIAL = "PARTIAL"
    """Event partially completed"""

    BLOCKED = "BLOCKED"
    """Event was blocked by security control"""

    UNKNOWN = "UNKNOWN"
    """Outcome cannot be determined"""


# Event severity mapping (security events = higher severity)
EVENT_SEVERITY_MAP: Dict[AuditEventType, AuditEventSeverity] = {
    # File operations (INFO/WARNING)
    AuditEventType.FILE_VALIDATION_SUCCESS: AuditEventSeverity.INFO,
    AuditEventType.FILE_VALIDATION_FAILURE: AuditEventSeverity.WARNING,
    AuditEventType.FILE_PROCESSING_START: AuditEventSeverity.INFO,
    AuditEventType.FILE_PROCESSING_COMPLETE: AuditEventSeverity.INFO,
    AuditEventType.FILE_PROCESSING_ERROR: AuditEventSeverity.ERROR,
    AuditEventType.FILE_PROCESSING_ABORTED: AuditEventSeverity.CRITICAL,
    # Security violations (CRITICAL/ALERT)
    AuditEventType.PATH_TRAVERSAL_ATTEMPT: AuditEventSeverity.CRITICAL,
    AuditEventType.PATH_TRAVERSAL_BLOCKED: AuditEventSeverity.ALERT,
    AuditEventType.RESOURCE_LIMIT_EXCEEDED: AuditEventSeverity.CRITICAL,
    AuditEventType.RESOURCE_LIMIT_WARNING: AuditEventSeverity.WARNING,
    AuditEventType.DECOMPRESSION_BOMB_DETECTED: AuditEventSeverity.CRITICAL,
    AuditEventType.DECOMPRESSION_BOMB_WARNING: AuditEventSeverity.WARNING,
    AuditEventType.INVALID_FILE_TYPE: AuditEventSeverity.WARNING,
    AuditEventType.INVALID_FILE_SIGNATURE: AuditEventSeverity.WARNING,
    AuditEventType.OVERSIZED_FILE_REJECTED: AuditEventSeverity.WARNING,
    AuditEventType.UNDERSIZED_FILE_REJECTED: AuditEventSeverity.WARNING,
    AuditEventType.COMMAND_INJECTION_ATTEMPT: AuditEventSeverity.CRITICAL,
    AuditEventType.COMMAND_INJECTION_BLOCKED: AuditEventSeverity.ALERT,
    # Authentication (INFO/WARNING/CRITICAL)
    AuditEventType.AUTH_SUCCESS: AuditEventSeverity.INFO,
    AuditEventType.AUTH_FAILURE: AuditEventSeverity.WARNING,
    AuditEventType.AUTH_RATE_LIMIT: AuditEventSeverity.CRITICAL,
    AuditEventType.AUTH_TIMEOUT: AuditEventSeverity.WARNING,
    AuditEventType.AUTH_INVALID_CREDENTIALS: AuditEventSeverity.WARNING,
    # Access control (WARNING/CRITICAL)
    AuditEventType.ACCESS_GRANTED: AuditEventSeverity.INFO,
    AuditEventType.ACCESS_DENIED: AuditEventSeverity.WARNING,
    AuditEventType.PRIVILEGE_ESCALATION_ATTEMPT: AuditEventSeverity.CRITICAL,
    AuditEventType.PRIVILEGE_ESCALATION_BLOCKED: AuditEventSeverity.ALERT,
    AuditEventType.PERMISSION_ERROR: AuditEventSeverity.WARNING,
    # Configuration (INFO/WARNING)
    AuditEventType.CONFIG_LOADED: AuditEventSeverity.INFO,
    AuditEventType.CONFIG_VALIDATION_ERROR: AuditEventSeverity.WARNING,
    AuditEventType.CONFIG_CHANGED: AuditEventSeverity.NOTICE,
    AuditEventType.CONFIG_SECURITY_VIOLATION: AuditEventSeverity.CRITICAL,
    # Process tracking (INFO/ERROR)
    AuditEventType.ANALYSIS_STARTED: AuditEventSeverity.INFO,
    AuditEventType.ANALYSIS_COMPLETED: AuditEventSeverity.INFO,
    AuditEventType.ANALYSIS_FAILED: AuditEventSeverity.ERROR,
    AuditEventType.ANALYZER_EXECUTION: AuditEventSeverity.DEBUG,
    # System events (ERROR/CRITICAL)
    AuditEventType.SYSTEM_ERROR: AuditEventSeverity.ERROR,
    AuditEventType.MEMORY_ERROR: AuditEventSeverity.CRITICAL,
    AuditEventType.CPU_LIMIT_EXCEEDED: AuditEventSeverity.CRITICAL,
    AuditEventType.FILE_DESCRIPTOR_EXHAUSTION: AuditEventSeverity.CRITICAL,
    AuditEventType.DISK_FULL: AuditEventSeverity.CRITICAL,
    # Network events (INFO/WARNING)
    AuditEventType.SSH_CONNECTION_ESTABLISHED: AuditEventSeverity.INFO,
    AuditEventType.SSH_CONNECTION_FAILED: AuditEventSeverity.WARNING,
    AuditEventType.SSH_HOST_KEY_UNKNOWN: AuditEventSeverity.CRITICAL,
    AuditEventType.SSH_COMMAND_EXECUTED: AuditEventSeverity.INFO,
    # Data protection (INFO/NOTICE)
    AuditEventType.PII_REDACTION_APPLIED: AuditEventSeverity.INFO,
    AuditEventType.PII_DETECTED: AuditEventSeverity.NOTICE,
    AuditEventType.SENSITIVE_DATA_ACCESS: AuditEventSeverity.NOTICE,
}


def get_event_severity(event_type: AuditEventType) -> AuditEventSeverity:
    """
    Get the default severity for an event type.

    Args:
        event_type: The audit event type

    Returns:
        Default severity level for this event type
    """
    return EVENT_SEVERITY_MAP.get(event_type, AuditEventSeverity.INFO)


def is_security_event(event_type: AuditEventType) -> bool:
    """
    Determine if an event is security-related.

    Security events require higher priority logging and may trigger alerts.

    Args:
        event_type: The audit event type

    Returns:
        True if this is a security event, False otherwise
    """
    security_prefixes = [
        "security.",
        "auth.",
        "access.",
    ]

    return any(event_type.value.startswith(prefix) for prefix in security_prefixes)


# Compliance mapping: NIST AU-2 requirement -> Event types
NIST_AU2_COMPLIANCE_MAP: Dict[str, list] = {
    "Account Logon": [
        AuditEventType.AUTH_SUCCESS,
        AuditEventType.AUTH_FAILURE,
        AuditEventType.AUTH_RATE_LIMIT,
        AuditEventType.AUTH_INVALID_CREDENTIALS,
    ],
    "Account Management": [
        # Not applicable for this application (no user accounts)
    ],
    "Object Access": [
        AuditEventType.FILE_VALIDATION_SUCCESS,
        AuditEventType.FILE_VALIDATION_FAILURE,
        AuditEventType.FILE_PROCESSING_START,
        AuditEventType.FILE_PROCESSING_COMPLETE,
        AuditEventType.ACCESS_GRANTED,
        AuditEventType.ACCESS_DENIED,
    ],
    "Policy Changes": [
        AuditEventType.CONFIG_LOADED,
        AuditEventType.CONFIG_CHANGED,
        AuditEventType.CONFIG_VALIDATION_ERROR,
        AuditEventType.CONFIG_SECURITY_VIOLATION,
    ],
    "Privilege Functions": [
        AuditEventType.RESOURCE_LIMIT_EXCEEDED,
        AuditEventType.PRIVILEGE_ESCALATION_ATTEMPT,
        AuditEventType.SSH_COMMAND_EXECUTED,
    ],
    "Process Tracking": [
        AuditEventType.ANALYSIS_STARTED,
        AuditEventType.ANALYSIS_COMPLETED,
        AuditEventType.ANALYSIS_FAILED,
        AuditEventType.FILE_PROCESSING_START,
        AuditEventType.FILE_PROCESSING_COMPLETE,
    ],
    "System Events": [
        AuditEventType.SYSTEM_ERROR,
        AuditEventType.MEMORY_ERROR,
        AuditEventType.CPU_LIMIT_EXCEEDED,
        AuditEventType.FILE_DESCRIPTOR_EXHAUSTION,
        AuditEventType.RESOURCE_LIMIT_EXCEEDED,
    ],
}
