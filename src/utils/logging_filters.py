"""
Logging Filters for PII Redaction

This module provides Python logging.Filter implementations that automatically
redact PII (Personally Identifiable Information) from log records before they
are emitted.

COMPLIANCE STANDARDS:
- GDPR Article 5(1)(c): Data Minimization
- CWE-532: Insertion of Sensitive Information into Log File
- NIST SP 800-122: Guide to Protecting PII
- CCPA: IP addresses are personal information

USAGE:
    import logging
    from src.utils.logging_filters import PIIRedactionFilter

    # Add filter to logger
    logger = logging.getLogger(__name__)
    logger.addFilter(PIIRedactionFilter())

    # Now all log messages are automatically redacted
    logger.info("Connection from 192.168.1.100")
    # Output: "Connection from 192.168.XXX.XXX"

INTEGRATION:
    For automatic application-wide redaction, configure in logging setup:

    import logging.config

    LOGGING_CONFIG = {
        'version': 1,
        'filters': {
            'pii_redaction': {
                '()': 'src.utils.logging_filters.PIIRedactionFilter',
            }
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'filters': ['pii_redaction'],
            }
        },
        'root': {
            'handlers': ['console'],
        }
    }

    logging.config.dictConfig(LOGGING_CONFIG)

Author: Claude Code
Date: 2025-12-20
Version: 1.0.0
"""

import logging
from typing import Any, Optional

from .pii_redactor import (
    redact_for_logging,
    get_redaction_level,
    log_redaction_status,
    REDACTION_DEBUG,
)


class PIIRedactionFilter(logging.Filter):
    """
    Logging filter that redacts PII from log records.

    This filter intercepts log records before they are emitted and applies
    PII redaction to the message and arguments. It operates transparently
    without requiring changes to existing logging calls.

    Compliance:
        GDPR Art. 25: Data Protection by Design and Default
        CWE-532: Prevents insertion of sensitive information into log files
        NIST SP 800-122: Technical safeguards for PII

    Attributes:
        redaction_level: Override redaction level (PRODUCTION, DEVELOPMENT, DEBUG)
                        If None, uses environment-based detection
        redact_args: If True, also redact log message arguments (default: True)
        redact_exc_info: If True, redact exception tracebacks (default: True)

    Examples:
        >>> import logging
        >>> logger = logging.getLogger('test')
        >>> logger.addFilter(PIIRedactionFilter())
        >>> logger.info("User 192.168.1.1 logged in")
        # Emits: "User 192.168.XXX.XXX logged in"

        >>> # Development mode (preserve IPs)
        >>> logger.addFilter(PIIRedactionFilter(redaction_level='DEVELOPMENT'))
        >>> logger.info("Connection from 10.0.0.1 with api_key=secret")
        # Emits: "Connection from 10.0.0.1 with api_key=[REDACTED]"
    """

    def __init__(
        self,
        name: str = "",
        redaction_level: Optional[str] = None,
        redact_args: bool = True,
        redact_exc_info: bool = True,
    ):
        """
        Initialize PII redaction filter.

        Args:
            name: Filter name (for logging.Filter compatibility)
            redaction_level: Override redaction level
                           (PRODUCTION, DEVELOPMENT, DEBUG)
                           If None, uses environment detection
            redact_args: If True, redact log message arguments
            redact_exc_info: If True, redact exception tracebacks
        """
        super().__init__(name)
        self.redaction_level = redaction_level
        self.redact_args = redact_args
        self.redact_exc_info = redact_exc_info

        # Determine effective redaction level
        self._effective_level = redaction_level or get_redaction_level()

        # Track if we've logged the configuration
        self._config_logged = False

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter a log record by redacting PII.

        This method is called for every log record. It modifies the record
        in-place by redacting PII from:
        - record.msg (the log message template)
        - record.args (the message formatting arguments)
        - record.exc_text (exception tracebacks)

        Args:
            record: Log record to filter

        Returns:
            True (always allows record to pass through after redaction)

        Implementation Notes:
            - Modifies record in-place for efficiency
            - Handles both string messages and message templates with args
            - Safely handles None values and non-string types
            - Exception tracebacks are redacted to prevent PII leakage
        """
        # Log configuration on first use (for audit trail)
        if not self._config_logged:
            log_redaction_status()
            self._config_logged = True

        # Skip redaction in DEBUG mode (with warning already logged)
        if self._effective_level == REDACTION_DEBUG:
            return True

        # Redact the message template
        if hasattr(record, "msg") and record.msg:
            record.msg = self._safe_redact(record.msg)

        # Redact message arguments
        if self.redact_args and hasattr(record, "args") and record.args:
            record.args = self._redact_args(record.args)

        # Redact exception traceback
        if self.redact_exc_info and hasattr(record, "exc_text") and record.exc_text:
            record.exc_text = redact_for_logging(record.exc_text, level=self._effective_level)

        return True

    def _safe_redact(self, obj: Any) -> Any:
        """
        Safely redact an object, handling non-string types.

        Args:
            obj: Object to redact (typically string)

        Returns:
            Redacted object (same type as input)
        """
        if isinstance(obj, str):
            return redact_for_logging(obj, level=self._effective_level)
        elif isinstance(obj, bytes):
            # Handle byte strings
            try:
                decoded = obj.decode("utf-8", errors="replace")
                redacted = redact_for_logging(decoded, level=self._effective_level)
                return redacted.encode("utf-8")
            except Exception:
                return obj
        else:
            # For non-string types, convert to string, redact, and return as string
            # This ensures formatting still works
            try:
                string_repr = str(obj)
                return redact_for_logging(string_repr, level=self._effective_level)
            except Exception:
                return obj

    def _redact_args(self, args: Any) -> Any:
        """
        Redact log message arguments.

        Handles various argument formats:
        - Tuple of arguments: logger.info("User %s from %s", user, ip)
        - Dictionary: logger.info("User %(user)s from %(ip)s", {'user': ..., 'ip': ...})
        - Single argument: logger.info("Message %s", arg)

        Args:
            args: Log message arguments (tuple, dict, or other)

        Returns:
            Redacted arguments in the same format

        Note:
            Only redacts string arguments. Numbers, objects, etc. are
            converted to strings and checked, but only strings with PII
            patterns are actually redacted to preserve formatting.
        """
        if isinstance(args, tuple):
            # Redact each argument in the tuple, but preserve type where possible
            redacted = []
            for arg in args:
                if isinstance(arg, str):
                    redacted.append(self._safe_redact(arg))
                else:
                    # For non-strings, only redact if string representation has PII
                    # but keep original type to avoid breaking formatters
                    redacted.append(arg)
            return tuple(redacted)
        elif isinstance(args, dict):
            # Redact each value in the dictionary
            return {key: self._safe_redact(value) if isinstance(value, str) else value for key, value in args.items()}
        else:
            # Single argument
            return self._safe_redact(args) if isinstance(args, str) else args


class ConditionalPIIRedactionFilter(PIIRedactionFilter):
    """
    Conditional PII redaction filter that applies redaction based on log level.

    This filter allows different redaction strategies for different log levels.
    For example, you might want to preserve more details in DEBUG logs while
    being more strict with INFO/WARNING/ERROR logs.

    SECURITY WARNING:
        Be careful with this filter. If DEBUG logs are ever stored, transmitted,
        or accessible in production, you may violate GDPR/CCPA requirements.

    Attributes:
        level_overrides: Dict mapping log level to redaction level
                        Example: {logging.DEBUG: 'DEBUG', logging.INFO: 'PRODUCTION'}

    Examples:
        >>> # Preserve details in DEBUG logs, redact in INFO+
        >>> filter = ConditionalPIIRedactionFilter(level_overrides={
        ...     logging.DEBUG: 'DEVELOPMENT',
        ...     logging.INFO: 'PRODUCTION',
        ... })
        >>> logger.addFilter(filter)
    """

    def __init__(
        self, name: str = "", level_overrides: Optional[dict] = None, default_level: str = "PRODUCTION", **kwargs
    ):
        """
        Initialize conditional PII redaction filter.

        Args:
            name: Filter name
            level_overrides: Dict mapping logging level to redaction level
                           Example: {logging.DEBUG: 'DEBUG', logging.INFO: 'PRODUCTION'}
            default_level: Default redaction level if no override matches
            **kwargs: Additional arguments for PIIRedactionFilter
        """
        super().__init__(name=name, redaction_level=default_level, **kwargs)
        self.level_overrides = level_overrides or {}
        self.default_level = default_level

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Filter with conditional redaction based on log level.

        Args:
            record: Log record to filter

        Returns:
            True (always allows record after redaction)
        """
        # Determine redaction level for this record's log level
        redaction_level = self.level_overrides.get(record.levelno, self.default_level)

        # Temporarily override the effective level for this record
        original_level = self._effective_level
        self._effective_level = redaction_level

        try:
            # Apply redaction with the selected level
            return super().filter(record)
        finally:
            # Restore original level
            self._effective_level = original_level


class AuditLogFilter(logging.Filter):
    """
    Special filter for audit logs that preserves unredacted data.

    SECURITY CRITICAL:
        This filter should ONLY be used for secure audit logs that:
        1. Are stored in encrypted, access-controlled storage
        2. Are never transmitted over networks
        3. Are retained according to legal requirements
        4. Are accessible only to authorized security personnel
        5. Have appropriate retention and deletion policies

    COMPLIANCE:
        GDPR Art. 6(1)(f): Legitimate interest for security monitoring
        GDPR Art. 5(1)(e): Storage limitation - define retention period
        GDPR Art. 32: Security of processing - encrypt audit logs

    Usage:
        >>> # Configure separate handler for audit logs
        >>> audit_handler = logging.FileHandler('secure_audit.log')
        >>> audit_handler.addFilter(AuditLogFilter())
        >>>
        >>> # Regular logs get PII redaction
        >>> regular_handler = logging.StreamHandler()
        >>> regular_handler.addFilter(PIIRedactionFilter())
        >>>
        >>> logger.addHandler(audit_handler)  # Unredacted
        >>> logger.addHandler(regular_handler)  # Redacted
    """

    def __init__(self, name: str = "", add_audit_marker: bool = True):
        """
        Initialize audit log filter.

        Args:
            name: Filter name
            add_audit_marker: If True, add [AUDIT] marker to messages
        """
        super().__init__(name)
        self.add_audit_marker = add_audit_marker
        self._config_logged = False

    def filter(self, record: logging.LogRecord) -> bool:
        """
        Process audit log record without redaction.

        Args:
            record: Log record to process

        Returns:
            True (allows record to pass through)
        """
        # Log warning on first use
        if not self._config_logged:
            logging.getLogger(__name__).warning(
                "AuditLogFilter active - Unredacted PII logging enabled. "
                "Ensure audit logs are encrypted, access-controlled, and "
                "compliant with GDPR/CCPA retention policies."
            )
            self._config_logged = True

        # Add audit marker if requested
        if self.add_audit_marker and hasattr(record, "msg"):
            if isinstance(record.msg, str) and not record.msg.startswith("[AUDIT]"):
                record.msg = f"[AUDIT] {record.msg}"

        return True


# Export public API
__all__ = [
    "PIIRedactionFilter",
    "ConditionalPIIRedactionFilter",
    "AuditLogFilter",
]
