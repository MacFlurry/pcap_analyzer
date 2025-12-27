"""
File validation utilities for PCAP files.

This module implements OWASP ASVS 5.2 security standards for file upload validation,
specifically targeting PCAP file validation to prevent malicious file uploads.

Standards implemented:
- OWASP ASVS 5.2.2: File Type and Content Validation (Magic Bytes)
- OWASP File Upload Cheat Sheet: Magic number validation before processing
- OWASP ASVS 5.2.1: File Size Validation
- CWE-434: Unrestricted Upload of File with Dangerous Type (Rank 12 in 2025)
- CWE-770: Allocation of Resources Without Limits or Throttling
- NIST SP 800-53 SC-5: Denial of Service Protection

Security rationale:
1. Magic byte validation prevents malicious files disguised as PCAP files
2. File size validation prevents resource exhaustion attacks
3. Validation occurs BEFORE file processing to prevent exploitation
4. Error messages do not leak sensitive information (file paths, system details)

References:
- https://owasp.org/www-project-application-security-verification-standard/
- https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- https://cwe.mitre.org/data/definitions/434.html
- https://cwe.mitre.org/data/definitions/770.html
"""

import logging
from pathlib import Path
from typing import Literal, Optional, List

# Configure module logger
logger = logging.getLogger(__name__)

# PCAP magic numbers (first 4 bytes of file)
# Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
PCAP_MAGIC_NUMBERS = {
    # Standard PCAP format (microsecond precision)
    b"\xa1\xb2\xc3\xd4": "pcap",  # Big-endian
    b"\xd4\xc3\xb2\xa1": "pcap",  # Little-endian
    # PCAP with nanosecond precision
    b"\xa1\xb2\x3c\x4d": "pcap-ns",  # Big-endian
    b"\x4d\x3c\xb2\xa1": "pcap-ns",  # Little-endian
    # PCAP-NG format (next generation)
    b"\x0a\x0d\x0d\x0a": "pcapng",  # Section Header Block magic
}

# Default file size limits (OWASP ASVS 5.2.1)
DEFAULT_MAX_SIZE_GB = 20  # Maximum PCAP file size in GB
MIN_FILE_SIZE = 24  # Minimum valid PCAP file size (header size)


def validate_pcap_magic_number(file_path: str) -> str:
    """
    Validate PCAP file by checking magic bytes (file signature).

    This function implements OWASP ASVS 5.2.2 by validating the file type
    using magic numbers rather than relying on file extensions. This prevents
    malicious files from being processed by disguising themselves with .pcap extension.

    Supported PCAP formats:
    - Standard PCAP (both big-endian and little-endian)
    - PCAP with nanosecond precision
    - PCAP-NG (next generation format)

    Args:
        file_path: Absolute path to the PCAP file to validate

    Returns:
        str: PCAP type ('pcap', 'pcap-ns', or 'pcapng') if valid

    Raises:
        ValueError: If file is not a valid PCAP file with descriptive error message
        FileNotFoundError: If file does not exist
        PermissionError: If file cannot be read due to permissions

    Security notes:
    - File path is NOT included in error messages to prevent information disclosure
    - Validation occurs before any file processing
    - Only first 4 bytes are read to minimize resource usage
    - All exceptions are caught and re-raised with sanitized messages

    Examples:
        >>> # Valid PCAP file
        >>> pcap_type = validate_pcap_magic_number('/path/to/capture.pcap')
        >>> print(pcap_type)  # 'pcap'

        >>> # Invalid file (e.g., text file with .pcap extension)
        >>> validate_pcap_magic_number('/path/to/fake.pcap')
        ValueError: Invalid PCAP file: magic number 0x54455854 not recognized

        >>> # Executable disguised as PCAP
        >>> validate_pcap_magic_number('/path/to/malware.pcap')
        ValueError: Invalid PCAP file: magic number 0x4d5a9000 not recognized

    References:
    - OWASP ASVS 5.2.2: https://owasp.org/www-project-application-security-verification-standard/
    - CWE-434: https://cwe.mitre.org/data/definitions/434.html
    - PCAP Format: https://wiki.wireshark.org/Development/LibpcapFileFormat
    """
    logger.info(f"Validating PCAP magic number for file")

    try:
        path = Path(file_path)

        # Security: Verify file exists and is a regular file
        if not path.exists():
            raise FileNotFoundError("PCAP file does not exist")

        if not path.is_file():
            raise ValueError("Invalid PCAP file: path is not a regular file")

        # Read only first 4 bytes (magic number)
        with open(path, "rb") as f:
            magic_bytes = f.read(4)

        # Validate we read enough bytes
        if len(magic_bytes) < 4:
            raise ValueError(f"Invalid PCAP file: file too small (minimum {MIN_FILE_SIZE} bytes required)")

        # Check if magic number matches any known PCAP format
        if magic_bytes in PCAP_MAGIC_NUMBERS:
            pcap_type = PCAP_MAGIC_NUMBERS[magic_bytes]
            logger.info(f"Valid PCAP file detected: type={pcap_type}")
            return pcap_type

        # Security: Do not leak file path in error message
        # Convert magic bytes to hex for error message
        magic_hex = "0x" + magic_bytes.hex()
        error_msg = (
            f"Invalid PCAP file: magic number {magic_hex} not recognized. "
            f"Expected one of: standard PCAP (0xa1b2c3d4), PCAP-NS (0xa1b23c4d), "
            f"or PCAP-NG (0x0a0d0d0a). Please ensure the file is a valid PCAP capture."
        )
        logger.warning(f"Invalid magic number detected: {magic_hex}")
        raise ValueError(error_msg)

    except FileNotFoundError as e:
        # Re-raise with sanitized message (no file path)
        logger.error("File not found during validation")
        raise FileNotFoundError("PCAP file does not exist or is not accessible") from e

    except PermissionError as e:
        # Re-raise with sanitized message (no file path)
        logger.error("Permission denied during validation")
        raise PermissionError("Permission denied: cannot read PCAP file") from e

    except OSError as e:
        # Catch-all for other OS errors (e.g., I/O errors)
        logger.error(f"OS error during validation: {type(e).__name__}")
        raise ValueError(f"Cannot read PCAP file: {type(e).__name__}") from e


def validate_pcap_file_size(file_path: str, max_size_gb: int = DEFAULT_MAX_SIZE_GB) -> int:
    """
    Validate PCAP file size to prevent resource exhaustion attacks.

    This function implements OWASP ASVS 5.2.1 and NIST SC-5 by validating
    file size BEFORE processing to prevent denial-of-service attacks via
    extremely large files.

    Validation checks:
    1. File is not empty (size > 0)
    2. File is not too small (size >= MIN_FILE_SIZE bytes for valid PCAP header)
    3. File does not exceed maximum size limit (default: 20GB)

    Args:
        file_path: Absolute path to the PCAP file to validate
        max_size_gb: Maximum allowed file size in gigabytes (default: 20)

    Returns:
        int: File size in bytes if validation passes

    Raises:
        ValueError: If file size is invalid (too small, too large, or zero)
        FileNotFoundError: If file does not exist
        PermissionError: If file cannot be accessed

    Security notes:
    - Validation occurs before file is opened for processing
    - Maximum size limit prevents memory exhaustion attacks
    - Minimum size check prevents processing of truncated/corrupt files
    - File path is NOT included in error messages

    Examples:
        >>> # Valid file size
        >>> size = validate_pcap_file_size('/path/to/capture.pcap')
        >>> print(f"File size: {size} bytes")

        >>> # Empty file
        >>> validate_pcap_file_size('/path/to/empty.pcap')
        ValueError: Invalid PCAP file: file is empty (0 bytes)

        >>> # File too large
        >>> validate_pcap_file_size('/path/to/huge.pcap', max_size_gb=1)
        ValueError: PCAP file too large: 5.2 GB exceeds maximum of 1 GB

        >>> # Custom size limit for large captures
        >>> size = validate_pcap_file_size('/path/to/large.pcap', max_size_gb=50)

    References:
    - OWASP ASVS 5.2.1: https://owasp.org/www-project-application-security-verification-standard/
    - CWE-770: https://cwe.mitre.org/data/definitions/770.html
    - NIST SP 800-53 SC-5: https://nvd.nist.gov/800-53/Rev4/control/SC-5
    """
    logger.info(f"Validating PCAP file size (max: {max_size_gb} GB)")

    try:
        path = Path(file_path)

        # Security: Verify file exists and is a regular file
        if not path.exists():
            raise FileNotFoundError("PCAP file does not exist")

        if not path.is_file():
            raise ValueError("Invalid PCAP file: path is not a regular file")

        # Get file size without opening the file (efficient)
        file_size = path.stat().st_size

        # Validate file is not empty (CWE-770: resource exhaustion via zero-byte files)
        if file_size == 0:
            logger.warning("Empty file detected during validation")
            raise ValueError("Invalid PCAP file: file is empty (0 bytes)")

        # Validate minimum file size (PCAP header is 24 bytes minimum)
        if file_size < MIN_FILE_SIZE:
            logger.warning(f"File too small: {file_size} bytes < {MIN_FILE_SIZE} bytes")
            raise ValueError(
                f"Invalid PCAP file: file too small ({file_size} bytes). "
                f"Minimum valid PCAP file is {MIN_FILE_SIZE} bytes (header size)."
            )

        # Validate maximum file size (prevent resource exhaustion)
        max_size_bytes = max_size_gb * 1024 * 1024 * 1024  # Convert GB to bytes
        if file_size > max_size_bytes:
            file_size_gb = file_size / (1024 * 1024 * 1024)
            logger.warning(f"File too large: {file_size_gb:.1f} GB > {max_size_gb} GB")
            raise ValueError(
                f"PCAP file too large: {file_size_gb:.1f} GB exceeds maximum of {max_size_gb} GB. "
                f"Consider processing the file in chunks or increasing the size limit."
            )

        # Validation passed
        file_size_mb = file_size / (1024 * 1024)
        logger.info(f"File size validation passed: {file_size_mb:.2f} MB")
        return file_size

    except FileNotFoundError as e:
        logger.error("File not found during size validation")
        raise FileNotFoundError("PCAP file does not exist or is not accessible") from e

    except PermissionError as e:
        logger.error("Permission denied during size validation")
        raise PermissionError("Permission denied: cannot access PCAP file") from e

    except OSError as e:
        logger.error(f"OS error during size validation: {type(e).__name__}")
        raise ValueError(f"Cannot access PCAP file: {type(e).__name__}") from e


def validate_pcap_file(file_path: str, max_size_gb: int = DEFAULT_MAX_SIZE_GB) -> tuple[str, int]:
    """
    Comprehensive PCAP file validation (magic number + file size).

    This function combines both magic number validation and file size validation
    to provide a complete security check before PCAP file processing. It implements
    multiple OWASP ASVS 5.2 controls in a single call.

    Validation order (fail-fast):
    1. File size validation (fast, prevents processing of huge files)
    2. Magic number validation (requires reading first 4 bytes)

    Args:
        file_path: Absolute path to the PCAP file to validate
        max_size_gb: Maximum allowed file size in gigabytes (default: 20)

    Returns:
        tuple[str, int]: (pcap_type, file_size_bytes)
            - pcap_type: 'pcap', 'pcap-ns', or 'pcapng'
            - file_size_bytes: File size in bytes

    Raises:
        ValueError: If validation fails (invalid magic number or file size)
        FileNotFoundError: If file does not exist
        PermissionError: If file cannot be accessed

    Security notes:
    - Implements defense-in-depth with multiple validation layers
    - Fail-fast approach minimizes resource usage for invalid files
    - All errors are sanitized to prevent information disclosure

    Example:
        >>> # Validate PCAP file before processing
        >>> try:
        >>>     pcap_type, file_size = validate_pcap_file('/path/to/capture.pcap')
        >>>     print(f"Valid {pcap_type} file ({file_size} bytes)")
        >>>     # Safe to proceed with processing
        >>> except ValueError as e:
        >>>     print(f"Validation failed: {e}")
        >>>     # Abort processing

    References:
    - OWASP ASVS 5.2: https://owasp.org/www-project-application-security-verification-standard/
    - Defense in Depth: https://owasp.org/www-community/Defense_in_Depth
    """
    logger.info("Starting comprehensive PCAP file validation")

    # Step 1: Validate file size (fast, prevents processing huge files)
    file_size = validate_pcap_file_size(file_path, max_size_gb)

    # Step 2: Validate magic number (requires reading file)
    pcap_type = validate_pcap_magic_number(file_path)

    logger.info(f"Comprehensive validation passed: type={pcap_type}, size={file_size} bytes")
    return pcap_type, file_size


def validate_file_path(file_path: str, allowed_dirs: Optional[List[str]] = None) -> str:
    """
    Validate file path to prevent path traversal attacks (CWE-22).

    This function implements defense-in-depth with three validation layers:
    1. Pre-processing detection: Reject dangerous patterns (.. ~ null-bytes)
    2. Path resolution: Resolve symlinks and relative paths to absolute paths
    3. Directory containment: Verify path is within allowed directories (if specified)

    This approach prevents:
    - Path traversal attacks (CWE-22 - Rank 6 in 2025)
    - Directory traversal via symbolic links
    - Access to sensitive system files
    - Bypassing directory restrictions

    Args:
        file_path: File path to validate (can be relative or absolute)
        allowed_dirs: Optional list of allowed directory paths. If provided,
                     the resolved file path must be within one of these directories.
                     If None, only basic path traversal checks are performed.

    Returns:
        str: Validated absolute path with symlinks resolved

    Raises:
        ValueError: If path contains traversal patterns or is outside allowed directories
                   Error messages are sanitized to prevent information disclosure

    Security notes:
    - Defense-in-depth: Multiple layers of validation for robust protection
    - Symlink resolution: Path.resolve() follows symlinks to actual location
    - No information leakage: Error messages do not reveal system paths
    - Empty paths rejected: Prevents processing of invalid input

    Examples:
        >>> # Basic validation (no directory restriction)
        >>> path = validate_file_path('/tmp/capture.pcap')
        >>> print(path)  # '/tmp/capture.pcap' (absolute, resolved)

        >>> # Reject path traversal
        >>> validate_file_path('../../../etc/passwd')
        ValueError: Path traversal detected: illegal path patterns

        >>> # Reject tilde expansion
        >>> validate_file_path('~/secrets.pcap')
        ValueError: Path traversal detected: illegal path patterns

        >>> # Directory containment check
        >>> allowed = ['/var/uploads']
        >>> validate_file_path('/var/uploads/file.pcap', allowed_dirs=allowed)
        '/var/uploads/file.pcap'

        >>> # Reject path outside allowed directory
        >>> validate_file_path('/etc/passwd', allowed_dirs=['/var/uploads'])
        ValueError: Access denied: path is outside allowed directories

        >>> # Symlink following with containment check
        >>> # If /var/uploads/link -> /tmp/outside.pcap
        >>> validate_file_path('/var/uploads/link', allowed_dirs=['/var/uploads'])
        ValueError: Access denied: path is outside allowed directories

    References:
    - CWE-22: https://cwe.mitre.org/data/definitions/22.html
    - OWASP Path Traversal: https://owasp.org/www-community/attacks/Path_Traversal
    - OWASP ASVS 5.2.3: Path Traversal Prevention
    """
    logger.debug(f"Validating file path (allowed_dirs: {len(allowed_dirs) if allowed_dirs else 'none'})")

    # Layer 1: Pre-processing detection
    # Reject dangerous patterns before any path operations
    if not file_path or file_path.strip() == "":
        logger.warning("Empty path rejected during validation")
        raise ValueError("Path traversal detected: empty path not allowed")

    # Detect path traversal patterns
    dangerous_patterns = ["..", "~"]
    for pattern in dangerous_patterns:
        if pattern in file_path:
            logger.warning(f"Dangerous pattern '{pattern}' detected in path")
            raise ValueError("Path traversal detected: illegal path patterns")

    # Detect null bytes (path injection)
    if "\0" in file_path:
        logger.warning("Null byte detected in path")
        raise ValueError("Path traversal detected: illegal path patterns")

    # Layer 2: Path resolution
    # Resolve symlinks and relative paths to absolute paths
    try:
        resolved_path = Path(file_path).resolve()
        logger.debug(f"Path resolved to: {resolved_path}")
    except (OSError, RuntimeError) as e:
        # Catch resolution errors (e.g., circular symlinks, permission issues)
        logger.error(f"Path resolution failed: {type(e).__name__}")
        raise ValueError("Path validation failed: cannot resolve path") from e

    # Layer 3: Directory containment check
    # If allowed_dirs specified, verify path is within one of them
    if allowed_dirs is not None and len(allowed_dirs) > 0:
        # Resolve all allowed directories to absolute paths
        resolved_allowed_dirs = []
        for allowed_dir in allowed_dirs:
            try:
                resolved_allowed_dir = Path(allowed_dir).resolve()
                resolved_allowed_dirs.append(resolved_allowed_dir)
            except (OSError, RuntimeError) as e:
                logger.error(f"Cannot resolve allowed directory '{allowed_dir}': {type(e).__name__}")
                # Skip invalid allowed directories
                continue

        # Check if resolved path is within any allowed directory
        is_within_allowed = False
        for allowed_dir in resolved_allowed_dirs:
            try:
                # Check if resolved_path is relative to allowed_dir
                # This will raise ValueError if not a subpath
                resolved_path.relative_to(allowed_dir)
                is_within_allowed = True
                logger.debug(f"Path is within allowed directory: {allowed_dir}")
                break
            except ValueError:
                # Not within this allowed directory, try next
                continue

        if not is_within_allowed:
            logger.warning("Path is outside all allowed directories")
            raise ValueError("Access denied: path is outside allowed directories")

    # All validations passed
    logger.info("Path validation passed")
    return str(resolved_path)
