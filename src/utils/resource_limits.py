"""
OS-Level Resource Limits for DoS Protection

This module implements resource limits according to Python resource module best practices
to prevent resource exhaustion attacks (DoS).

SECURITY STANDARDS:
- CWE-770: Allocation of Resources Without Limits or Throttling (Rank 25 in 2025)
- NIST SP 800-53 SC-5: Denial of Service Protection

PROTECTION MECHANISMS:
- Memory limits (RLIMIT_AS): Prevent zip bombs from consuming all RAM
- CPU time limits (RLIMIT_CPU): Prevent infinite loops from hanging process
- File size limits (RLIMIT_FSIZE): Prevent disk exhaustion
- File descriptor limits (RLIMIT_NOFILE): Prevent fd exhaustion attacks

PLATFORM SUPPORT:
- Linux: Full support
- macOS: Full support
- Windows: Not supported (resource module not available)

Author: PCAP Analyzer Security Team
Date: 2025-12-20
"""

import logging
import platform
import signal
import sys
from dataclasses import dataclass
from typing import Optional

# Platform detection
RESOURCE_MODULE_AVAILABLE = False
try:
    import resource

    RESOURCE_MODULE_AVAILABLE = True
except ImportError:
    # Windows doesn't have resource module
    pass

logger = logging.getLogger(__name__)


@dataclass
class ResourceLimitConfig:
    """
    Configuration object for resource limits.

    This provides a structured way to define resource limits that will be enforced
    by the OS to prevent resource exhaustion attacks (CWE-770, NIST SC-5).

    Attributes:
        memory_limit_gb: Maximum virtual memory in gigabytes (default: 4GB)
        cpu_time_limit_seconds: Maximum CPU time in seconds (default: 3600s = 1 hour)
        max_file_size_gb: Maximum file size in gigabytes (default: 10GB)
        max_open_files: Maximum number of open file descriptors (default: 1024)

    Example:
        >>> # Use defaults
        >>> config = ResourceLimitConfig()
        >>> set_resource_limits(config)

        >>> # Custom limits
        >>> config = ResourceLimitConfig(memory_limit_gb=8.0, cpu_time_limit_seconds=7200)
        >>> set_resource_limits(config)
    """

    memory_limit_gb: float = 4.0
    cpu_time_limit_seconds: int = 3600
    max_file_size_gb: float = 10.0
    max_open_files: int = 1024


def _bytes_to_human(bytes_value: int) -> str:
    """
    Convert bytes to human-readable format.

    Args:
        bytes_value: Size in bytes

    Returns:
        Human-readable string (e.g., "4.0 GB", "512.0 MB")
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024.0:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024.0
    return f"{bytes_value:.1f} PB"


def _handle_cpu_limit_exceeded(signum, frame):
    """
    Signal handler for SIGXCPU (CPU time limit exceeded).

    This is triggered when the process exceeds its CPU time limit.
    We log the violation and exit gracefully.

    SECURITY NOTE: This prevents infinite loops from consuming CPU indefinitely.
    """
    logger.critical(
        "CPU time limit exceeded! Process has consumed too much CPU time. "
        "This may indicate an infinite loop or inefficient algorithm. "
        "Terminating gracefully to prevent resource exhaustion (CWE-770, NIST SC-5)."
    )
    print("\n[SECURITY] CPU time limit exceeded. Terminating process.", file=sys.stderr)
    sys.exit(1)


def _handle_memory_limit_exceeded():
    """
    Handle MemoryError exceptions when memory limit is exceeded.

    This should be called in a try/except block around memory-intensive operations.

    SECURITY NOTE: This prevents memory exhaustion attacks (e.g., zip bombs).
    """
    logger.critical(
        "Memory limit exceeded! Process attempted to allocate more memory than allowed. "
        "This may indicate a memory leak, zip bomb, or excessively large file. "
        "Operation aborted to prevent system crash (CWE-770, NIST SC-5)."
    )
    print("\n[SECURITY] Memory limit exceeded. Operation aborted.", file=sys.stderr)
    sys.exit(1)


def set_resource_limits(
    config: Optional[ResourceLimitConfig] = None,
    memory_gb: Optional[float] = None,
    cpu_seconds: Optional[int] = None,
    max_file_size_gb: Optional[float] = None,
    max_open_files: Optional[int] = None,
) -> None:
    """
    Set OS-level resource limits to prevent resource exhaustion attacks.

    This function implements defense-in-depth security by setting HARD limits
    on system resources. When limits are exceeded, the OS will kill the process.

    SECURITY RATIONALE:
    - Memory limit (RLIMIT_AS): Prevents zip bombs and memory exhaustion
      Default: 4GB (sufficient for analyzing large PCAPs, prevents system crash)

    - CPU time limit (RLIMIT_CPU): Prevents infinite loops and algorithmic DoS
      Default: 3600 seconds (1 hour - reasonable for large file analysis)

    - File size limit (RLIMIT_FSIZE): Prevents disk exhaustion from log files
      Default: 10GB (prevents runaway log generation)

    - File descriptor limit (RLIMIT_NOFILE): Prevents fd exhaustion attacks
      Default: 1024 (standard Linux default, prevents resource exhaustion)

    STANDARDS COMPLIANCE:
    - CWE-770: Allocation of Resources Without Limits or Throttling
    - NIST SP 800-53 SC-5: Denial of Service Protection

    PLATFORM NOTES:
    - Linux/macOS: Full support via resource module
    - Windows: Not supported (resource module unavailable, logs warning)

    Args:
        config: ResourceLimitConfig object with all settings (preferred method)
        memory_gb: Maximum virtual memory in gigabytes (default: 4GB)
        cpu_seconds: Maximum CPU time in seconds (default: 3600s = 1 hour)
        max_file_size_gb: Maximum file size in gigabytes (default: 10GB)
        max_open_files: Maximum number of open file descriptors (default: 1024)

    Raises:
        OSError: If setting limits fails (e.g., insufficient permissions)
        ValueError: If invalid limit values provided

    Example:
        >>> # Use defaults with config object (recommended)
        >>> config = ResourceLimitConfig()
        >>> set_resource_limits(config)

        >>> # Custom limits with config object
        >>> config = ResourceLimitConfig(memory_limit_gb=8.0, cpu_time_limit_seconds=7200)
        >>> set_resource_limits(config)

        >>> # Legacy: Use defaults with direct parameters (4GB RAM, 1 hour CPU, 10GB files, 1024 fds)
        >>> set_resource_limits()

        >>> # Legacy: Custom limits for resource-constrained environment
        >>> set_resource_limits(memory_gb=2.0, cpu_seconds=1800, max_file_size_gb=5.0)

        >>> # Legacy: Allow more memory for analyzing very large PCAPs
        >>> set_resource_limits(memory_gb=8.0)
    """
    # If config object provided, extract parameters from it
    if config is not None:
        memory_gb = config.memory_limit_gb
        cpu_seconds = config.cpu_time_limit_seconds
        max_file_size_gb = config.max_file_size_gb
        max_open_files = config.max_open_files
    else:
        # Use defaults if not specified (backward compatibility)
        if memory_gb is None:
            memory_gb = 4.0
        if cpu_seconds is None:
            cpu_seconds = 3600
        if max_file_size_gb is None:
            max_file_size_gb = 10.0
        if max_open_files is None:
            max_open_files = 1024
    # Check platform support
    if not RESOURCE_MODULE_AVAILABLE:
        logger.warning(
            "Resource limits not available on this platform (%s). "
            "The resource module is only available on Unix-like systems (Linux, macOS). "
            "Resource exhaustion protection is DISABLED. "
            "Consider running on Linux/macOS for production deployments.",
            platform.system(),
        )
        print(
            f"[WARNING] Resource limits not supported on {platform.system()}. "
            "Resource exhaustion protection disabled.",
            file=sys.stderr,
        )
        return

    # Save original limits if not already saved (for restore_default_limits())
    global _ORIGINAL_LIMITS
    if not _ORIGINAL_LIMITS:
        try:
            _ORIGINAL_LIMITS = {
                "RLIMIT_AS": resource.getrlimit(resource.RLIMIT_AS),
                "RLIMIT_CPU": resource.getrlimit(resource.RLIMIT_CPU),
                "RLIMIT_FSIZE": resource.getrlimit(resource.RLIMIT_FSIZE),
                "RLIMIT_NOFILE": resource.getrlimit(resource.RLIMIT_NOFILE),
            }
            logger.debug("Saved original resource limits for potential restoration")
        except Exception as e:
            logger.warning("Failed to save original limits: %s", e)

    # Validate inputs
    if memory_gb <= 0:
        raise ValueError(f"memory_gb must be positive, got {memory_gb}")
    if cpu_seconds <= 0:
        raise ValueError(f"cpu_seconds must be positive, got {cpu_seconds}")
    if max_file_size_gb <= 0:
        raise ValueError(f"max_file_size_gb must be positive, got {max_file_size_gb}")
    if max_open_files <= 0:
        raise ValueError(f"max_open_files must be positive, got {max_open_files}")

    # Convert human-readable values to bytes
    memory_bytes = int(memory_gb * 1024 * 1024 * 1024)
    file_size_bytes = int(max_file_size_gb * 1024 * 1024 * 1024)

    logger.info("Setting OS-level resource limits for DoS protection (CWE-770, NIST SC-5)")

    try:
        # Set virtual memory limit (RLIMIT_AS)
        # This is the TOTAL virtual memory (including mmap, stack, heap)
        # When exceeded, malloc() will fail and Python will raise MemoryError
        # NOTE: RLIMIT_AS is not fully supported on macOS and may fail with ValueError
        try:
            current_mem_soft, current_mem_hard = resource.getrlimit(resource.RLIMIT_AS)
            # Only set if the new limit is lower than current hard limit (or if unlimited)
            if current_mem_hard == resource.RLIM_INFINITY or memory_bytes <= current_mem_hard:
                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
                logger.info(
                    "Memory limit (RLIMIT_AS): %s (prevents zip bombs and memory exhaustion)",
                    _bytes_to_human(memory_bytes),
                )
            else:
                logger.warning(
                    "Cannot set memory limit to %s (system hard limit is %s). Using system limit.",
                    _bytes_to_human(memory_bytes),
                    _bytes_to_human(current_mem_hard),
                )
        except (ValueError, OSError) as e:
            # macOS doesn't fully support RLIMIT_AS - this is expected
            logger.warning(
                "RLIMIT_AS not supported on this platform (%s). Memory limit cannot be enforced. "
                "This is a known limitation on macOS. Consider using Linux for production deployments.",
                platform.system(),
            )

        # Set CPU time limit (RLIMIT_CPU)
        # This is CUMULATIVE CPU time (not wall-clock time)
        # When exceeded, SIGXCPU is sent, then SIGKILL after grace period
        current_cpu_soft, current_cpu_hard = resource.getrlimit(resource.RLIMIT_CPU)
        if current_cpu_hard == resource.RLIM_INFINITY or cpu_seconds <= current_cpu_hard:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
            logger.info("CPU time limit (RLIMIT_CPU): %d seconds (prevents infinite loops)", cpu_seconds)
        else:
            logger.warning(
                "Cannot set CPU limit to %d seconds (system hard limit is %d). Using system limit.",
                cpu_seconds,
                current_cpu_hard,
            )

        # Set maximum file size limit (RLIMIT_FSIZE)
        # Prevents any single file write from exceeding this size
        # When exceeded, SIGXFSZ is sent and write() fails with errno EFBIG
        current_fsize_soft, current_fsize_hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        if current_fsize_hard == resource.RLIM_INFINITY or file_size_bytes <= current_fsize_hard:
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_bytes, file_size_bytes))
            logger.info(
                "File size limit (RLIMIT_FSIZE): %s (prevents disk exhaustion)", _bytes_to_human(file_size_bytes)
            )
        else:
            logger.warning(
                "Cannot set file size limit to %s (system hard limit is %s). Using system limit.",
                _bytes_to_human(file_size_bytes),
                _bytes_to_human(current_fsize_hard),
            )

        # Set maximum open file descriptors (RLIMIT_NOFILE)
        # Prevents fd exhaustion attacks (e.g., opening thousands of files)
        # When exceeded, open() will fail with errno EMFILE
        current_nofile_soft, current_nofile_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if current_nofile_hard == resource.RLIM_INFINITY:
            target_nofile_soft = max_open_files
            target_nofile_hard = current_nofile_hard
            resource.setrlimit(resource.RLIMIT_NOFILE, (target_nofile_soft, target_nofile_hard))
            logger.info(
                "File descriptor limit (RLIMIT_NOFILE): soft=%d hard=unlimited (prevents fd exhaustion)",
                target_nofile_soft,
            )
        elif max_open_files <= current_nofile_hard:
            # Keep hard limit unchanged to avoid irreversible test-process degradation
            # when lowering limits in a non-root context.
            target_nofile_soft = max_open_files
            target_nofile_hard = current_nofile_hard
            resource.setrlimit(resource.RLIMIT_NOFILE, (target_nofile_soft, target_nofile_hard))
            logger.info(
                "File descriptor limit (RLIMIT_NOFILE): soft=%d hard=%d (prevents fd exhaustion)",
                target_nofile_soft,
                target_nofile_hard,
            )
        else:
            logger.warning(
                "Cannot set file descriptor limit to %d (system hard limit is %d). Using system limit.",
                max_open_files,
                current_nofile_hard,
            )

        # Install signal handler for CPU limit exceeded
        # SIGXCPU is sent when soft CPU limit is reached
        signal.signal(signal.SIGXCPU, _handle_cpu_limit_exceeded)
        logger.info("Installed SIGXCPU handler for graceful CPU limit violation handling")

        logger.info(
            "Resource limits successfully applied. "
            "Process will be terminated if limits are exceeded. "
            "This protects against DoS attacks (CWE-770, NIST SP 800-53 SC-5)."
        )

    except OSError as e:
        # This can happen if:
        # 1. Insufficient permissions (e.g., trying to raise hard limit as non-root)
        # 2. System limit is lower than requested limit
        # 3. Platform-specific restrictions
        logger.error(
            "Failed to set resource limits: %s. "
            "This may occur if you lack permissions or if system limits are too restrictive. "
            "Consider running with appropriate privileges or adjusting limits. "
            "Resource exhaustion protection may be INCOMPLETE.",
            e,
        )
        raise OSError(
            f"Failed to set resource limits: {e}. "
            "Ensure you have appropriate permissions and system limits are not too restrictive."
        ) from e
    except Exception as e:
        logger.error("Unexpected error setting resource limits: %s", e)
        raise


def get_current_resource_usage() -> dict:
    """
    Get current resource usage statistics.

    This is useful for monitoring and debugging resource consumption.

    Returns:
        Dictionary with current resource usage:
        - memory_mb: Current memory usage in MB
        - cpu_time: Cumulative CPU time in seconds
        - open_files: Number of currently open file descriptors

    Example:
        >>> usage = get_current_resource_usage()
        >>> print(f"Memory: {usage['memory_mb']:.2f} MB")
        >>> print(f"CPU time: {usage['cpu_time']:.2f}s")
    """
    if not RESOURCE_MODULE_AVAILABLE:
        return {
            "platform": platform.system(),
            "resource_module_available": False,
            "message": "Resource monitoring not available on this platform",
        }

    try:
        # Get resource usage
        usage = resource.getrusage(resource.RUSAGE_SELF)

        # Get current limits
        memory_limit = resource.getrlimit(resource.RLIMIT_AS)
        cpu_limit = resource.getrlimit(resource.RLIMIT_CPU)

        return {
            "platform": platform.system(),
            "resource_module_available": True,
            "memory_mb": usage.ru_maxrss / 1024 / 1024,  # Convert KB to MB (Linux)
            "cpu_time_seconds": usage.ru_utime + usage.ru_stime,  # User + System time
            "memory_limit_gb": (
                memory_limit[0] / 1024 / 1024 / 1024 if memory_limit[0] != resource.RLIM_INFINITY else None
            ),
            "cpu_limit_seconds": cpu_limit[0] if cpu_limit[0] != resource.RLIM_INFINITY else None,
        }
    except Exception as e:
        logger.warning("Failed to get resource usage: %s", e)
        return {"platform": platform.system(), "resource_module_available": True, "error": str(e)}


def handle_memory_error():
    """
    Call this function in except MemoryError blocks to handle memory limit violations.

    This provides consistent error handling and logging for memory exhaustion.

    Example:
        >>> try:
        ...     # Memory-intensive operation
        ...     large_data = allocate_huge_array()
        ... except MemoryError:
        ...     from src.utils.resource_limits import handle_memory_error
        ...     handle_memory_error()
    """
    _handle_memory_limit_exceeded()


def get_current_limits() -> dict:
    """
    Get current resource limits set by the OS.

    This is an alias for get_current_resource_usage() for backward compatibility.
    Returns the current resource limits as a dictionary.

    Returns:
        Dictionary with current resource limits:
        - RLIMIT_AS: Memory limit (soft, hard) in bytes
        - RLIMIT_CPU: CPU time limit (soft, hard) in seconds
        - RLIMIT_FSIZE: File size limit (soft, hard) in bytes
        - RLIMIT_NOFILE: File descriptor limit (soft, hard)

    Example:
        >>> limits = get_current_limits()
        >>> print(f"Memory limit: {limits['RLIMIT_AS']}")
    """
    if not RESOURCE_MODULE_AVAILABLE:
        return {
            "platform": platform.system(),
            "resource_module_available": False,
            "message": "Resource limits not available on this platform",
        }

    try:
        return {
            "platform": platform.system(),
            "resource_module_available": True,
            "RLIMIT_AS": resource.getrlimit(resource.RLIMIT_AS),
            "RLIMIT_CPU": resource.getrlimit(resource.RLIMIT_CPU),
            "RLIMIT_FSIZE": resource.getrlimit(resource.RLIMIT_FSIZE),
            "RLIMIT_NOFILE": resource.getrlimit(resource.RLIMIT_NOFILE),
        }
    except Exception as e:
        logger.warning("Failed to get current limits: %s", e)
        return {"platform": platform.system(), "resource_module_available": True, "error": str(e)}


# Store original limits for restoration
_ORIGINAL_LIMITS = {}


def restore_default_limits() -> None:
    """
    Restore resource limits to their original system defaults.

    This function restores limits to the values that were in place before
    set_resource_limits() was called. If limits were never modified, this
    will attempt to set them to very high values (close to system maximum).

    SECURITY NOTE: Only call this when you're certain the process is exiting
    or when you need to temporarily remove resource restrictions for a specific
    operation. Removing limits reduces DoS protection.

    Example:
        >>> # Set custom limits
        >>> config = ResourceLimitConfig(memory_limit_gb=2.0)
        >>> set_resource_limits(config)
        >>> # ... do work ...
        >>> # Restore original limits
        >>> restore_default_limits()
    """
    if not RESOURCE_MODULE_AVAILABLE:
        logger.warning(
            "Resource limits not available on this platform (%s). " "Cannot restore limits.", platform.system()
        )
        return

    try:
        # If we have stored original limits, restore them
        if _ORIGINAL_LIMITS:
            logger.info("Restoring original resource limits")

            # Restore each limit, handling errors individually
            for limit_name in ["RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_NOFILE"]:
                if limit_name in _ORIGINAL_LIMITS:
                    try:
                        limit_const = getattr(resource, limit_name)
                        resource.setrlimit(limit_const, _ORIGINAL_LIMITS[limit_name])
                    except (ValueError, OSError) as e:
                        # Some limits can't be restored (e.g., macOS RLIMIT_AS)
                        logger.warning(
                            "Could not restore %s to original value: %s. This is expected on some platforms.",
                            limit_name,
                            e,
                        )
        else:
            # No original limits stored - try to set to high values
            logger.info("No original limits stored. Attempting to set to system defaults")

            # Get current hard limits and set soft limits to match them
            for limit_name in ["RLIMIT_AS", "RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_NOFILE"]:
                try:
                    limit_const = getattr(resource, limit_name)
                    soft, hard = resource.getrlimit(limit_const)
                    # Set soft limit to hard limit (most permissive without raising hard limit)
                    if hard != resource.RLIM_INFINITY:
                        resource.setrlimit(limit_const, (hard, hard))
                    else:
                        # Hard limit is already infinite, just set soft to infinite
                        resource.setrlimit(limit_const, (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
                except (ValueError, OSError) as e:
                    # Some limits can't be set (e.g., macOS RLIMIT_AS)
                    logger.warning(
                        "Could not set %s to default: %s. This is expected on some platforms.", limit_name, e
                    )

        logger.info("Resource limits restoration completed")

    except Exception as e:
        logger.error("Unexpected error restoring resource limits: %s", e)
        # Don't raise - this is a best-effort operation
        logger.warning("Continuing despite restore failure")
