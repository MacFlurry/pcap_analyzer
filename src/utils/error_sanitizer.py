"""
Error Message Sanitization Utility

Security-compliant error handling that prevents information disclosure.

Implements:
- CWE-209: Information Exposure Through Error Messages
- CWE-532: Insertion of Sensitive Information into Log File
- NIST SP 800-53 SI-10(3): Predictable Behavior for Invalid Inputs
- OWASP ASVS Chapter 7: Error Handling and Logging

This module ensures that:
1. User-facing error messages are generic and helpful
2. Detailed error information is logged to files only
3. File paths, Python internals, and system details are never exposed to users
4. All exceptions are properly logged with full context for debugging

Author: PCAP Analyzer Security Team
Sprint: Security Hardening (CWE-209, NIST SI-10(3) Compliance)
"""

import logging
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


def sanitize_file_path(text: str) -> str:
    """
    Remove file paths from error messages to prevent information disclosure.

    CWE-209: File paths can reveal system structure and user information.

    Args:
        text: Error message that may contain file paths

    Returns:
        Text with file paths replaced by [PATH_REDACTED]

    Examples:
        >>> sanitize_file_path("No such file: /home/user/secret.pcap")
        'No such file: [PATH_REDACTED]'
        >>> sanitize_file_path("Error in /var/lib/app/config.py line 42")
        'Error in [PATH_REDACTED] line 42'
    """
    # Pattern matches common file path formats (Unix and Windows)
    # Matches: /path/to/file, C:\path\to\file, ./relative/path, etc.
    patterns = [
        r'(?:[A-Za-z]:)?(?:[\\/][^\\/\s:]+)+(?:\.\w+)?',  # Absolute/relative paths
        r'(?:file://)?/[^\s]+',  # file:// URLs
        r'[A-Za-z]:\\[^\s]+',  # Windows paths
    ]

    sanitized = text
    for pattern in patterns:
        sanitized = re.sub(pattern, '[PATH_REDACTED]', sanitized)

    return sanitized


def sanitize_python_internals(text: str) -> str:
    """
    Remove Python version info and internal module references.

    CWE-209: Python internals can reveal framework versions and attack surfaces.

    Args:
        text: Error message that may contain Python internals

    Returns:
        Text with Python internals sanitized

    Examples:
        >>> sanitize_python_internals("Python 3.11.2 error in module scapy.packet")
        'Python [VERSION_REDACTED] error in module [MODULE_REDACTED]'
    """
    # Remove Python version numbers
    sanitized = re.sub(r'Python\s+\d+\.\d+(?:\.\d+)?', 'Python [VERSION_REDACTED]', text)

    # Remove module paths (e.g., "scapy.layers.inet.TCP")
    sanitized = re.sub(r'\b[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*){2,}\b', '[MODULE_REDACTED]', sanitized)

    # Remove traceback line references
    sanitized = re.sub(r'File\s+"[^"]+",\s+line\s+\d+', 'File [PATH_REDACTED], line [LINE_REDACTED]', sanitized)

    return sanitized


def sanitize_error_for_display(error: Exception, context: Optional[str] = None) -> str:
    """
    Convert exception to user-safe error message.

    This is the main function for converting exceptions to user-facing messages.
    It removes all sensitive information while keeping the message helpful.

    IMPORTANT: Always log the full exception with exc_info=True before calling this.

    Args:
        error: The exception to sanitize
        context: Optional context about what operation failed (e.g., "File processing")

    Returns:
        Generic, user-friendly error message without sensitive details

    Security:
        - CWE-209: Prevents information disclosure through error messages
        - NIST SI-10(3): Provides predictable error responses

    Examples:
        >>> sanitize_error_for_display(FileNotFoundError("/secret/file.pcap"))
        'File not found'
        >>> sanitize_error_for_display(PermissionError(), "File access")
        'File access: Permission denied'
    """
    # Map exception types to user-friendly messages
    error_type = type(error).__name__

    # Common exception types with safe messages
    safe_messages = {
        'FileNotFoundError': 'File not found',
        'PermissionError': 'Permission denied',
        'IsADirectoryError': 'Expected file, found directory',
        'NotADirectoryError': 'Expected directory, found file',
        'OSError': 'System error occurred',
        'IOError': 'Input/output error',
        'TimeoutError': 'Operation timed out',
        'MemoryError': 'Insufficient memory',
        'ValueError': 'Invalid value provided',
        'TypeError': 'Invalid data type',
        'KeyError': 'Required data not found',
        'IndexError': 'Data index out of range',
        'AttributeError': 'Invalid operation',
        'ImportError': 'Module not available',
        'ModuleNotFoundError': 'Required module not found',
        'RuntimeError': 'Runtime error occurred',
        'subprocess.CalledProcessError': 'External process failed',
        'subprocess.TimeoutExpired': 'Process execution timed out',
    }

    # Get base message from mapping or generic fallback
    base_message = safe_messages.get(error_type, 'An error occurred')

    # Add context if provided
    if context:
        return f"{context}: {base_message}"

    return base_message


def sanitize_subprocess_error(error: Exception) -> str:
    """
    Sanitize subprocess errors that may contain command output.

    Subprocess errors often contain stderr/stdout which may expose:
    - File paths from the subprocess
    - Version information
    - System configuration details

    Args:
        error: CalledProcessError or TimeoutExpired exception

    Returns:
        Sanitized error message safe for display

    Security:
        - CWE-209: Prevents command output disclosure
    """
    error_type = type(error).__name__

    if 'TimeoutExpired' in error_type:
        return 'Process execution timed out'
    elif 'CalledProcessError' in error_type:
        # Extract return code if available, but not output
        if hasattr(error, 'returncode'):
            return f'External process failed (exit code: {error.returncode})'
        return 'External process failed'
    else:
        return 'Process execution error'


def log_and_sanitize(
    error: Exception,
    logger_instance: logging.Logger,
    context: str,
    user_message: Optional[str] = None
) -> str:
    """
    Combined logging and sanitization helper.

    This is the recommended way to handle exceptions:
    1. Log full details to file (with stack trace)
    2. Return sanitized message for user display

    Args:
        error: The exception that occurred
        logger_instance: Logger to use for detailed logging
        context: Context description (e.g., "PCAP file processing")
        user_message: Optional custom user message (if None, auto-generated)

    Returns:
        Sanitized message safe for user display

    Usage:
        try:
            process_file(path)
        except Exception as e:
            msg = log_and_sanitize(e, logger, "File processing")
            console.print(f"[red]{msg}[/red]")

    Security:
        - CWE-532: Ensures sensitive info only goes to log files
        - CWE-209: User sees only safe messages
        - NIST SI-10(3): Consistent error handling
    """
    # Log full details to file (exc_info=True includes stack trace)
    logger_instance.error(f"{context} failed: {error}", exc_info=True)

    # Return sanitized message for user
    if user_message:
        return user_message

    return sanitize_error_for_display(error, context)


# Example usage patterns for reference
"""
RECOMMENDED PATTERN 1: Using log_and_sanitize
--------------------------------------------
import logging
from .utils.error_sanitizer import log_and_sanitize

logger = logging.getLogger(__name__)

try:
    result = risky_operation()
except Exception as e:
    safe_msg = log_and_sanitize(e, logger, "Operation")
    console.print(f"[red]{safe_msg}[/red]")
    sys.exit(1)


RECOMMENDED PATTERN 2: Manual logging + sanitization
--------------------------------------------------
import logging
from .utils.error_sanitizer import sanitize_error_for_display

logger = logging.getLogger(__name__)

try:
    result = risky_operation()
except Exception as e:
    # Log full details (file only)
    logger.error(f"Operation failed: {e}", exc_info=True)

    # Show sanitized message to user
    safe_msg = sanitize_error_for_display(e, "Operation")
    console.print(f"[red]{safe_msg}[/red]")
    sys.exit(1)


ANTI-PATTERN (DO NOT USE):
-------------------------
try:
    result = risky_operation()
except Exception as e:
    print(f"Error: {e}")  # ❌ May expose sensitive info
    traceback.print_exc()  # ❌ CRITICAL: Exposes stack trace to user
"""
