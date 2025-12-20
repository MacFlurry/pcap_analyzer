"""
PII (Personally Identifiable Information) Redaction for Logging

This module provides GDPR-compliant and NIST-aligned redaction functions to prevent
privacy violations in log files.

COMPLIANCE STANDARDS IMPLEMENTED:
- GDPR Article 5(1)(c): Data Minimization - IP addresses are PII under EU law
- CWE-532: Insertion of Sensitive Information into Log File
- NIST SP 800-122: Guide to Protecting the Confidentiality of PII
- CCPA (California): IP addresses considered personal information

SECURITY REQUIREMENTS:
- Default is PRODUCTION mode (redaction enabled) - opt-out, not opt-in
- IP addresses MUST be redacted by default in production
- Credential patterns MUST be redacted in all modes except DEBUG
- MAC addresses redacted to preserve OUI (first 3 octets) for troubleshooting

USAGE:
    # Import redaction functions
    from src.utils.pii_redactor import redact_for_logging

    # Redact sensitive data before logging
    safe_message = redact_for_logging("User at 192.168.1.100 logged in")
    logger.info(safe_message)  # Logs: "User at 192.168.XXX.XXX logged in"

    # Development mode (keep IPs for debugging, but redact credentials)
    safe_dev_msg = redact_for_logging(
        "Connection from 10.0.0.1 with api_key=secret123",
        level='DEVELOPMENT'
    )
    # Result: "Connection from 10.0.0.1 with api_key=[REDACTED]"

LEGAL BASIS:
- Logging for security monitoring (legitimate interest under GDPR Art. 6(1)(f))
- Data minimization by default prevents unlawful processing
- Redaction ensures compliance with privacy-by-design principles

Author: Claude Code
Date: 2025-12-20
Version: 1.0.0
"""

import re
import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)


# Redaction level constants
REDACTION_PRODUCTION = "PRODUCTION"
REDACTION_DEVELOPMENT = "DEVELOPMENT"
REDACTION_DEBUG = "DEBUG"

# Environment variable for global redaction level
REDACTION_LEVEL_ENV = "PCAP_ANALYZER_REDACTION_LEVEL"


def get_redaction_level() -> str:
    """
    Get the current redaction level from environment or default to PRODUCTION.

    SECURITY: Defaults to PRODUCTION (most secure) to prevent accidental PII leaks.
    Override via environment variable PCAP_ANALYZER_REDACTION_LEVEL.

    Returns:
        Redaction level: PRODUCTION, DEVELOPMENT, or DEBUG

    Compliance:
        GDPR Art. 25: Data Protection by Design - default to maximum privacy
    """
    level = os.getenv(REDACTION_LEVEL_ENV, REDACTION_PRODUCTION).upper()

    if level not in [REDACTION_PRODUCTION, REDACTION_DEVELOPMENT, REDACTION_DEBUG]:
        logger.warning(
            f"Invalid redaction level '{level}', defaulting to PRODUCTION. "
            f"Valid levels: {REDACTION_PRODUCTION}, {REDACTION_DEVELOPMENT}, {REDACTION_DEBUG}"
        )
        return REDACTION_PRODUCTION

    # Warn if DEBUG mode is used (should never be in production)
    if level == REDACTION_DEBUG:
        logger.warning(
            "PII REDACTION DISABLED (DEBUG mode). "
            "This MUST NOT be used in production environments. "
            "GDPR violations may occur if DEBUG logs are stored or transmitted."
        )

    return level


# Compiled regex patterns for performance
# IPv4: Matches 0.0.0.0 to 255.255.255.255
IPV4_PATTERN = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)

# IPv6: Matches full and compressed IPv6 addresses
# More comprehensive pattern that handles edge cases
IPV6_PATTERN = re.compile(
    r'(?:'
    r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|'  # Full form: 8 groups
    r'(?:[0-9a-fA-F]{1,4}:){1,7}:|'  # Ending with ::
    r'::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}|'  # Starting with ::
    r'(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|'  # :: in middle
    r'::1|::'  # Loopback and all-zeros (special cases)
    r')(?=\s|$|[^0-9a-fA-F:])'  # Lookahead to ensure proper boundaries
)

# MAC address: Matches aa:bb:cc:dd:ee:ff and aa-bb-cc-dd-ee-ff
MAC_PATTERN = re.compile(
    r'\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b'
)

# Unix file paths: /home/username/file.pcap, /Users/john/capture.pcap
UNIX_PATH_PATTERN = re.compile(
    r'(/(?:home|Users)/)[^/\s]+(/[^\s]*)'
)

# Windows file paths: C:\Users\John\file.pcap
WINDOWS_PATH_PATTERN = re.compile(
    r'([A-Z]:\\Users\\)[^\\]+(\\.+)',
    re.IGNORECASE
)

# Credential patterns
# Match password/passwd/pwd followed by = or : and value (handles Unicode)
PASSWORD_PATTERN = re.compile(
    r'(password|passwd|pwd)\s*[=:]\s*\S+',
    re.IGNORECASE
)

API_KEY_PATTERN = re.compile(
    r'(api[_-]?key|apikey|token|secret)\s*[=:]\s*[^\s,;]+',
    re.IGNORECASE
)

BEARER_TOKEN_PATTERN = re.compile(
    r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
    re.IGNORECASE
)

# Basic Auth pattern (base64 in Authorization header)
BASIC_AUTH_PATTERN = re.compile(
    r'Basic\s+[A-Za-z0-9+/]+=*',
    re.IGNORECASE
)


def redact_ipv4_addresses(text: str, preserve_prefix: bool = True) -> str:
    """
    Redact IPv4 addresses in text.

    Args:
        text: Text containing IPv4 addresses
        preserve_prefix: If True, preserve first 2 octets for network debugging
                        (e.g., 192.168.1.1 -> 192.168.XXX.XXX)
                        If False, full redaction (192.168.1.1 -> [IP_REDACTED])

    Returns:
        Text with IPv4 addresses redacted

    Compliance:
        GDPR Art. 4(1): IP addresses are personal data
        NIST SP 800-122: IP addresses are PII requiring protection

    Examples:
        >>> redact_ipv4_addresses("Connection from 192.168.1.100")
        'Connection from 192.168.XXX.XXX'

        >>> redact_ipv4_addresses("Server 10.0.0.1:8080", preserve_prefix=False)
        'Server [IP_REDACTED]:8080'
    """
    def replace_ipv4(match):
        ip = match.group(0)
        if preserve_prefix:
            # Keep first 2 octets for network troubleshooting
            parts = ip.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.XXX.XXX"
        return "[IP_REDACTED]"

    return IPV4_PATTERN.sub(replace_ipv4, text)


def redact_ipv6_addresses(text: str) -> str:
    """
    Redact IPv6 addresses in text.

    Args:
        text: Text containing IPv6 addresses

    Returns:
        Text with IPv6 addresses redacted

    Compliance:
        GDPR Art. 4(1): IP addresses (including IPv6) are personal data
        NIST SP 800-122: IPv6 addresses are PII

    Examples:
        >>> redact_ipv6_addresses("Connection from 2001:db8::1")
        'Connection from [IPV6_REDACTED]'

        >>> redact_ipv6_addresses("Localhost ::1")
        'Localhost [IPV6_REDACTED]'
    """
    return IPV6_PATTERN.sub('[IPV6_REDACTED]', text)


def redact_ip_addresses(text: str, preserve_prefix: bool = True) -> str:
    """
    Redact both IPv4 and IPv6 addresses in text.

    This is the primary function for IP address redaction, handling both
    IPv4 and IPv6 formats.

    Args:
        text: Text containing IP addresses
        preserve_prefix: If True, preserve first 2 octets of IPv4 for debugging

    Returns:
        Text with all IP addresses redacted

    Compliance:
        GDPR Art. 4(1): IP addresses are personal data
        CCPA §1798.140(o)(1)(A): IP addresses are personal information
        CWE-532: Prevents insertion of sensitive information into log files

    Examples:
        >>> redact_ip_addresses("Flow: 10.0.0.1:8080 -> 192.168.1.1:443")
        'Flow: 10.0.XXX.XXX:8080 -> 192.168.XXX.XXX:443'
    """
    text = redact_ipv4_addresses(text, preserve_prefix=preserve_prefix)
    text = redact_ipv6_addresses(text)
    return text


def redact_mac_addresses(text: str) -> str:
    """
    Redact MAC addresses while preserving OUI (first 3 octets).

    The first 3 octets (OUI - Organizationally Unique Identifier) identify
    the manufacturer and are not PII. The last 3 octets are device-specific
    and are redacted.

    Args:
        text: Text containing MAC addresses

    Returns:
        Text with MAC addresses redacted

    Compliance:
        NIST SP 800-122: MAC addresses can identify devices/users
        Data minimization: Preserve manufacturer info, redact device ID

    Examples:
        >>> redact_mac_addresses("Device MAC: aa:bb:cc:dd:ee:ff")
        'Device MAC: aa:bb:cc:[REDACTED]'

        >>> redact_mac_addresses("MAC 00-11-22-33-44-55")
        'MAC 00-11-22-[REDACTED]'
    """
    def replace_mac(match):
        mac = match.group(0)
        separator = ':' if ':' in mac else '-'
        parts = mac.replace('-', ':').split(':')
        if len(parts) == 6:
            # Preserve OUI (first 3 octets), redact device ID (last 3 octets)
            return f"{parts[0]}{separator}{parts[1]}{separator}{parts[2]}{separator}[REDACTED]"
        return '[MAC_REDACTED]'

    return MAC_PATTERN.sub(replace_mac, text)


def redact_file_paths(text: str) -> str:
    """
    Redact file paths containing usernames.

    Redacts username components in file paths while preserving the directory
    structure and filename for troubleshooting.

    Args:
        text: Text containing file paths

    Returns:
        Text with usernames in file paths redacted

    Compliance:
        GDPR Art. 4(1): Usernames in paths may constitute personal data
        NIST SP 800-122: Usernames are PII
        Data minimization: Preserve path structure, redact username

    Examples:
        >>> redact_file_paths("/home/john_doe/capture.pcap")
        '/home/[USER]/capture.pcap'

        >>> redact_file_paths("C:\\Users\\Alice\\network.pcap")
        'C:\\Users\\[USER]\\network.pcap'
    """
    # Redact Unix paths
    text = UNIX_PATH_PATTERN.sub(r'\1[USER]\2', text)

    # Redact Windows paths
    text = WINDOWS_PATH_PATTERN.sub(r'\1[USER]\2', text)

    return text


def redact_credentials(text: str) -> str:
    """
    Redact credentials including passwords, API keys, and tokens.

    This function redacts various credential formats commonly found in logs:
    - password=xxx, passwd:xxx, pwd=xxx
    - api_key=xxx, apikey:xxx, token=xxx, secret=xxx
    - Bearer tokens
    - Basic authentication headers

    Args:
        text: Text containing credentials

    Returns:
        Text with credentials redacted

    Compliance:
        CWE-532: Insertion of Sensitive Information into Log File
        OWASP A01:2021: Broken Access Control
        NIST SP 800-122: Authentication credentials are sensitive PII

    Examples:
        >>> redact_credentials("Login with password=secret123")
        'Login with password=[REDACTED]'

        >>> redact_credentials("API call with api_key=abc123xyz")
        'API call with api_key=[REDACTED]'

        >>> redact_credentials("Authorization: Bearer eyJhbGc...")
        'Authorization: Bearer [REDACTED]'
    """
    # Redact password patterns
    text = PASSWORD_PATTERN.sub(r'\1=[REDACTED]', text)

    # Redact API key patterns
    text = API_KEY_PATTERN.sub(r'\1=[REDACTED]', text)

    # Redact Bearer tokens
    text = BEARER_TOKEN_PATTERN.sub('Bearer [REDACTED]', text)

    # Redact Basic Auth
    text = BASIC_AUTH_PATTERN.sub('Basic [REDACTED]', text)

    return text


def redact_for_logging(text: str, level: Optional[str] = None) -> str:
    """
    Master redaction function that applies appropriate redactions based on level.

    This is the main entry point for PII redaction. It applies different
    redaction strategies based on the environment:

    PRODUCTION (default):
        - Redact IP addresses (preserve first 2 octets for network debugging)
        - Redact MAC addresses (preserve OUI)
        - Redact file paths (preserve structure)
        - Redact all credentials

    DEVELOPMENT:
        - Keep IP addresses (for local debugging)
        - Redact MAC addresses
        - Redact file paths
        - Redact all credentials

    DEBUG:
        - No redaction (WARNING: NOT GDPR-COMPLIANT)
        - Use only in isolated development environments
        - Never store or transmit DEBUG logs

    Args:
        text: Text to redact
        level: Redaction level (PRODUCTION, DEVELOPMENT, DEBUG)
               If None, uses get_redaction_level() which checks environment

    Returns:
        Redacted text appropriate for the security level

    Compliance:
        GDPR Art. 25: Data Protection by Design and Default
        GDPR Art. 5(1)(c): Data Minimization
        NIST SP 800-122: Implement safeguards for PII
        CWE-532: Prevent sensitive information in log files

    Security Notes:
        - DEFAULT is PRODUCTION (most secure) - opt-out, not opt-in
        - DEBUG mode logs warning to prevent production use
        - Environment variable override: PCAP_ANALYZER_REDACTION_LEVEL

    Examples:
        >>> # Production mode (default)
        >>> redact_for_logging("Flow 10.28.104.211:16586 -> 10.179.161.14:10100")
        'Flow 10.28.XXX.XXX:16586 -> 10.179.XXX.XXX:10100'

        >>> # Development mode
        >>> redact_for_logging(
        ...     "Testing from 192.168.1.100 with api_key=secret",
        ...     level='DEVELOPMENT'
        ... )
        'Testing from 192.168.1.100 with api_key=[REDACTED]'

        >>> # Debug mode (warning logged)
        >>> redact_for_logging("Raw data", level='DEBUG')
        'Raw data'
    """
    if level is None:
        level = get_redaction_level()

    level = level.upper()

    # DEBUG mode: No redaction (log warning)
    if level == REDACTION_DEBUG:
        # Warning already logged in get_redaction_level()
        return text

    # DEVELOPMENT mode: Keep IPs, redact credentials
    if level == REDACTION_DEVELOPMENT:
        text = redact_mac_addresses(text)
        text = redact_file_paths(text)
        text = redact_credentials(text)
        return text

    # PRODUCTION mode (default): Redact everything
    text = redact_ip_addresses(text, preserve_prefix=True)
    text = redact_mac_addresses(text)
    text = redact_file_paths(text)
    text = redact_credentials(text)

    return text


def is_production_environment() -> bool:
    """
    Detect if running in production environment.

    Returns:
        True if production indicators are detected, False otherwise

    Detection heuristics:
        - ENVIRONMENT=production
        - FLASK_ENV=production
        - DJANGO_SETTINGS_MODULE contains 'production'
        - HOME/USERPROFILE not in common dev paths
    """
    # Check explicit environment variables
    env = os.getenv('ENVIRONMENT', '').lower()
    if env in ['production', 'prod', 'live']:
        return True

    flask_env = os.getenv('FLASK_ENV', '').lower()
    if flask_env == 'production':
        return True

    django_settings = os.getenv('DJANGO_SETTINGS_MODULE', '').lower()
    if 'production' in django_settings or 'prod' in django_settings:
        return True

    # Heuristic: Check if in typical development paths
    home = os.getenv('HOME') or os.getenv('USERPROFILE') or ''
    dev_indicators = ['/home/', '/Users/', 'C:\\Users\\', 'localhost', '127.0.0.1']

    if any(indicator in home for indicator in dev_indicators):
        # Likely development environment
        return False

    # Default to production (safer)
    return True


def log_redaction_status() -> None:
    """
    Log the current redaction configuration for audit purposes.

    This should be called at application startup to document the
    redaction settings in the logs.

    Compliance:
        GDPR Art. 5(2): Accountability - document privacy measures
        NIST SP 800-122: Document PII handling procedures
    """
    level = get_redaction_level()
    is_prod = is_production_environment()

    logger.info(
        f"PII Redaction Configuration: "
        f"Level={level}, "
        f"Environment={'PRODUCTION' if is_prod else 'DEVELOPMENT'}"
    )

    if level == REDACTION_DEBUG and is_prod:
        logger.critical(
            "SECURITY ALERT: DEBUG redaction level detected in PRODUCTION environment. "
            "This violates GDPR data minimization requirements. "
            "Set PCAP_ANALYZER_REDACTION_LEVEL=PRODUCTION immediately."
        )
    elif level == REDACTION_DEBUG:
        logger.warning(
            "PII redaction is DISABLED (DEBUG mode). "
            "Do not store, transmit, or share logs containing PII."
        )


# Export public API
__all__ = [
    'redact_ip_addresses',
    'redact_ipv4_addresses',
    'redact_ipv6_addresses',
    'redact_mac_addresses',
    'redact_file_paths',
    'redact_credentials',
    'redact_for_logging',
    'get_redaction_level',
    'is_production_environment',
    'log_redaction_status',
    'REDACTION_PRODUCTION',
    'REDACTION_DEVELOPMENT',
    'REDACTION_DEBUG',
]
