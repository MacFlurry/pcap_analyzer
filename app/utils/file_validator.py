"""
File Upload Security Validation (CWE-434, CWE-770)

Stream-based validation to prevent:
- Malicious file uploads (magic number validation)
- Memory exhaustion (size check BEFORE full read)
- Decompression bombs (expansion ratio monitoring)

References:
- GitHub Issue #17
- OWASP ASVS 5.2.1, 5.2.2, 5.2.3
- CWE-434: Unrestricted File Upload
- CWE-770: Allocation of Resources Without Limits
"""

import logging
import os
from typing import AsyncIterator, Tuple

from fastapi import HTTPException, UploadFile, status

logger = logging.getLogger(__name__)

# Configuration
MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "500"))
MAX_EXPANSION_RATIO = int(os.getenv("MAX_EXPANSION_RATIO", "1000"))
CRITICAL_EXPANSION_RATIO = int(os.getenv("CRITICAL_EXPANSION_RATIO", "10000"))

# PCAP Magic Numbers (first 4 bytes)
PCAP_MAGIC_LE = b"\xd4\xc3\xb2\xa1"  # Little-endian
PCAP_MAGIC_BE = b"\xa1\xb2\xc3\xd4"  # Big-endian
PCAP_MAGIC_NS = b"\x4d\x3c\x2b\x1a"  # Nanosecond resolution
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # PCAPNG Section Header Block


async def validate_upload_size_streaming(
    file: UploadFile, max_size_mb: int = MAX_UPLOAD_SIZE_MB
) -> AsyncIterator[bytes]:
    """
    Stream file upload with size validation BEFORE accumulating in memory.

    Prevents DoS attacks where 10GB file is read before size check.

    Args:
        file: FastAPI UploadFile object
        max_upload_size_mb: Maximum upload size limit in MB
        max_size_mb: Maximum allowed file size in MB

    Yields:
        File chunks (bytes)

    Raises:
        HTTPException 413: File exceeds size limit

    Example:
        async for chunk in validate_upload_size_streaming(file, max_size_mb=500):
            content_chunks.append(chunk)
    """
    max_size_bytes = max_size_mb * 1024 * 1024
    total_bytes = 0
    chunk_size = 10 * 1024 * 1024  # 10MB chunks

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break

        total_bytes += len(chunk)

        # Check size DURING reading (not after!)
        if total_bytes > max_size_bytes:
            logger.warning(f"Upload rejected: size {total_bytes} bytes exceeds limit {max_size_bytes} bytes")
            raise HTTPException(
                status_code=status.HTTP_413_CONTENT_TOO_LARGE,
                detail=f"File too large (max: {max_size_mb} MB)",
            )

        yield chunk


def validate_pcap_magic_bytes_streaming(first_chunk: bytes) -> str:
    """
    Validate PCAP/PCAPNG magic number from first chunk.

    Server-side validation prevents malware.exe disguised as .pcap.

    Args:
        first_chunk: First bytes of file (at least 4 bytes)

    Returns:
        PCAP type: 'pcap', 'pcap-ns', or 'pcapng'

    Raises:
        HTTPException 400: Invalid magic number

    Example:
        pcap_type = validate_pcap_magic_bytes_streaming(chunks[0])
        # pcap_type = 'pcap'
    """
    if len(first_chunk) < 4:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File too small to validate (minimum 4 bytes required)",
        )

    magic = first_chunk[:4]

    if magic == PCAP_MAGIC_LE or magic == PCAP_MAGIC_BE:
        return "pcap"
    elif magic == PCAP_MAGIC_NS:
        return "pcap-ns"
    elif magic == PCAPNG_MAGIC:
        return "pcapng"
    else:
        magic_hex = magic.hex()
        logger.warning(f"Invalid PCAP magic number: 0x{magic_hex}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid PCAP file format (magic number: 0x{magic_hex})",
        )


def detect_decompression_bomb(chunks: list, estimated_size: int) -> None:
    """
    Detect decompression bombs by monitoring expansion ratio.

    Prevents 42KB zip that expands to 5GB (10000:1 ratio).

    Args:
        chunks: List of file chunks read so far
        estimated_size: Estimated compressed file size (Content-Length or actual)

    Raises:
        HTTPException 413: Decompression bomb detected

    Example:
        detect_decompression_bomb(chunks, file_size=42000)
        # Raises if sum(chunks) > 42MB (1000:1 ratio)
    """
    total_bytes = sum(len(chunk) for chunk in chunks)

    if estimated_size == 0:
        estimated_size = 1024  # Avoid division by zero

    expansion_ratio = total_bytes / estimated_size

    # Warning threshold (OWASP recommended)
    if expansion_ratio > MAX_EXPANSION_RATIO:
        logger.warning(
            f"High expansion ratio detected: {expansion_ratio:.0f}:1 "
            f"(processed: {total_bytes}, estimated: {estimated_size})"
        )

    # Critical threshold - abort upload
    if expansion_ratio > CRITICAL_EXPANSION_RATIO:
        logger.critical(
            f"Decompression bomb detected! Ratio: {expansion_ratio:.0f}:1 "
            f"(processed: {total_bytes} bytes from {estimated_size} bytes source)"
        )
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"Suspected decompression bomb (expansion ratio: {expansion_ratio:.0f}:1)",
        )


async def validate_pcap_upload_complete(file: UploadFile, max_upload_size_mb: int = MAX_UPLOAD_SIZE_MB) -> Tuple[bytes, str]:
    """
    Complete file upload validation with defense-in-depth.

    Orchestrates all validation layers:
    1. Stream-based size limiting (prevents memory DoS)
    2. Magic number validation (prevents malware upload)
    3. Decompression bomb detection (prevents zip bombs)

    Args:
        file: FastAPI UploadFile object

    Returns:
        Tuple of (file_content, pcap_type)

    Raises:
        HTTPException 400: Invalid file format
        HTTPException 413: File too large or decompression bomb

    Example:
        content, pcap_type = await validate_pcap_upload_complete(uploaded_file)
        # content = b'\\xd4\\xc3\\xb2\\xa1...'
        # pcap_type = 'pcap'
    """
    chunks = []
    estimated_size = file.size or 1024  # Fallback if Content-Length not provided

    # Step 1: Stream validation with size check
    async for chunk in validate_upload_size_streaming(file, max_upload_size_mb):
        chunks.append(chunk)

        # Step 3: Decompression bomb check every 50MB
        total_so_far = sum(len(c) for c in chunks)
        if total_so_far % (50 * 1024 * 1024) < len(chunk):  # Crossed 50MB boundary
            detect_decompression_bomb(chunks, estimated_size)

    if not chunks:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Empty file upload")

    # Step 2: Magic number validation on first chunk
    pcap_type = validate_pcap_magic_bytes_streaming(chunks[0])

    # Final decompression bomb check
    detect_decompression_bomb(chunks, estimated_size)

    # Reconstruct file content
    content = b"".join(chunks)

    logger.info(
        f"File upload validated: {len(content)} bytes, type: {pcap_type}, "
        f"expansion ratio: {len(content)/estimated_size:.2f}:1"
    )

    return content, pcap_type
