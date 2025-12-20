"""
Path Traversal Protection (CWE-22)

Validates task_id and filename to prevent path traversal attacks.

References:
- GitHub Issue #14
- docs/security/WEB_UI_SECURITY_AUDIT.md (lines 180-349)
- OWASP ASVS 5.2.2
- CWE-22: https://cwe.mitre.org/data/definitions/22.html
"""

import re
from pathlib import Path
from fastapi import HTTPException, status


def validate_task_id(task_id: str) -> str:
    """
    Validate qu'un task_id est un UUID v4 valide.
    Empêche path traversal via ../

    Args:
        task_id: Task ID from user input (URL parameter)

    Returns:
        Validated task_id (same as input if valid)

    Raises:
        HTTPException 400: If task_id is not a valid UUID v4

    Examples:
        >>> validate_task_id("550e8400-e29b-41d4-a716-446655440000")  # Valid
        "550e8400-e29b-41d4-a716-446655440000"

        >>> validate_task_id("../../../etc/passwd")  # Invalid
        HTTPException(400, "Invalid task_id format (must be UUID v4)")
    """
    # UUID v4 format: 8-4-4-4-12 hexadecimal characters
    # Example: 550e8400-e29b-41d4-a716-446655440000
    #          ^^^^^^^^ ^^^^ ^^^^ ^^^^ ^^^^^^^^^^^^
    #          8 chars  4    4    4    12 chars
    uuid_v4_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'

    if not re.match(uuid_v4_pattern, task_id, re.IGNORECASE):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid task_id format (must be UUID v4)"
        )

    return task_id


def validate_filename(filename: str) -> str:
    """
    Sanitize filename pour éviter path traversal.

    Extracts basename only (removes any directory path).
    Validates extension against whitelist.
    Limits length to prevent buffer overflows.

    Args:
        filename: Filename from user input (upload form)

    Returns:
        Sanitized filename (basename only, validated extension)

    Raises:
        HTTPException 400: If filename is invalid

    Examples:
        >>> validate_filename("capture.pcap")  # Valid
        "capture.pcap"

        >>> validate_filename("../../etc/cron.d/evil.pcap")  # Path traversal
        "evil.pcap"  # Basename extracted

        >>> validate_filename("malware.exe")  # Invalid extension
        HTTPException(400, "Invalid file extension")

        >>> validate_filename(".hidden.pcap")  # Starts with dot
        HTTPException(400, "Invalid filename")
    """
    # 1. Extract basename only (remove any path components)
    filename = Path(filename).name

    # 2. Reject empty filename
    if not filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename (empty)"
        )

    # 3. Reject filename starting with dot (hidden files)
    if filename.startswith('.'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename (cannot start with dot)"
        )

    # 4. Reject filename with .. sequences
    if '..' in filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename (cannot contain '..')"
        )

    # 5. Whitelist extension
    allowed_extensions = ['.pcap', '.pcapng']
    if not any(filename.lower().endswith(ext) for ext in allowed_extensions):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension (allowed: {', '.join(allowed_extensions)})"
        )

    # 6. Limit filename length (prevent buffer overflows)
    max_length = 255  # Typical filesystem limit
    if len(filename) > max_length:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Filename too long (max {max_length} characters)"
        )

    # 7. Reject filename with null bytes (can bypass filesystem checks)
    if '\x00' in filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid filename (contains null byte)"
        )

    return filename


def validate_path_in_directory(file_path: Path, base_directory: Path) -> Path:
    """
    Validate que le resolved path est bien dans base_directory.

    Protection supplémentaire contre path traversal même après validation filename.

    Args:
        file_path: Path to validate
        base_directory: Base directory (e.g., REPORTS_DIR, UPLOAD_DIR)

    Returns:
        Resolved file_path (if valid)

    Raises:
        HTTPException 400: If path escapes base_directory

    Examples:
        >>> validate_path_in_directory(
        ...     Path("/data/reports/abc123.html"),
        ...     Path("/data/reports")
        ... )
        Path("/data/reports/abc123.html")

        >>> validate_path_in_directory(
        ...     Path("/data/reports/../../../etc/passwd"),
        ...     Path("/data/reports")
        ... )
        HTTPException(400, "Invalid path (escapes base directory)")
    """
    try:
        # Resolve both paths (follow symlinks, resolve ..)
        resolved_file = file_path.resolve()
        resolved_base = base_directory.resolve()

        # Check if resolved file is relative to base
        if not resolved_file.is_relative_to(resolved_base):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid path (escapes base directory)"
            )

        return resolved_file

    except (ValueError, OSError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid path: {str(e)}"
        )
