#!/usr/bin/env python3
"""
Decompression Bomb Protection Monitor

Implements OWASP ASVS 5.2.3 and CWE-409 protection against data amplification attacks.

SECURITY STANDARDS:
- OWASP ASVS 5.2.3: Compressed File Validation
- CWE-409: Improper Handling of Highly Compressed Data (Decompression Bombs)
- OpenSSF Python Security Guide: Data amplification attack prevention

BACKGROUND:
A decompression bomb (zip bomb) is a malicious archive designed to crash or render
useless the system reading it. Example:
- Compressed size: 100 KB
- Uncompressed size: 100 GB
- Expansion ratio: 1,000,000:1

PCAP Context:
While PCAP files are typically NOT compressed, malicious actors could:
1. Embed compressed data in packet payloads
2. Craft artificially large packet captures
3. Use packet deduplication attacks
4. Create captures with extreme data expansion ratios

This monitor detects abnormal expansion ratios BEFORE memory exhaustion occurs.

Author: PCAP Analyzer Security Team
Reference: OWASP ASVS v4.0.3
"""

import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# OWASP-recommended thresholds for data expansion
MAX_EXPANSION_RATIO = 1000  # Warn at 1000:1 expansion
CRITICAL_EXPANSION_RATIO = 10000  # Abort at 10000:1 expansion
CHECK_INTERVAL_PACKETS = 10000  # Check every 10k packets for efficiency


class DecompressionBombError(ValueError):
    """
    Raised when a decompression bomb is detected.

    This is a security exception indicating potential malicious activity
    or corrupted data that could exhaust system resources.
    """

    pass


@dataclass
class ExpansionStats:
    """Statistics about data expansion during processing."""

    file_size: int
    bytes_processed: int
    packets_processed: int
    expansion_ratio: float
    is_warning: bool
    is_critical: bool

    def __str__(self) -> str:
        """Human-readable representation of expansion stats."""
        return (
            f"Expansion Stats: {self.expansion_ratio:.1f}:1 ratio "
            f"({self.bytes_processed:,} bytes from {self.file_size:,} byte file, "
            f"{self.packets_processed:,} packets)"
        )


class DecompressionMonitor:
    """
    Monitor data expansion ratios to detect decompression bomb attacks.

    Implements OWASP ASVS 5.2.3 requirements for compressed file validation
    and CWE-409 protection against data amplification attacks.

    Usage:
        monitor = DecompressionMonitor()
        file_size = os.path.getsize(pcap_file)

        for packet in reader:
            packets_processed += 1
            bytes_processed += len(packet)

            if packets_processed % 10000 == 0:
                monitor.check_expansion_ratio(
                    file_size,
                    bytes_processed,
                    packets_processed
                )

    Security Features:
    - Early detection before memory exhaustion
    - Configurable thresholds (OWASP-recommended defaults)
    - Progressive warning levels
    - Minimal performance overhead (checks every N packets)
    """

    def __init__(
        self,
        max_ratio: int = MAX_EXPANSION_RATIO,
        critical_ratio: int = CRITICAL_EXPANSION_RATIO,
        check_interval: int = CHECK_INTERVAL_PACKETS,
        enabled: bool = True,
    ):
        """
        Initialize decompression bomb monitor.

        Args:
            max_ratio: Warn when expansion exceeds this ratio (default: 1000)
            critical_ratio: Abort when expansion exceeds this ratio (default: 10000)
            check_interval: Number of packets between checks (default: 10000)
            enabled: Enable/disable monitoring (default: True)

        Note:
            OWASP recommends ratios between 100:1 and 1000:1 for warning thresholds.
            We use 1000:1 for warnings and 10000:1 for critical aborts to balance
            security with support for legitimate large packet captures.
        """
        self.max_ratio = max_ratio
        self.critical_ratio = critical_ratio
        self.check_interval = check_interval
        self.enabled = enabled

        # Tracking
        self.last_check_packet = 0
        self.warning_logged = False
        self.checks_performed = 0

        logger.debug(
            f"DecompressionMonitor initialized: max_ratio={max_ratio}, "
            f"critical_ratio={critical_ratio}, enabled={enabled}"
        )

    def calculate_ratio(self, bytes_in: int, bytes_out: int) -> float:
        """
        Calculate expansion ratio.

        Args:
            bytes_in: Input size (compressed/file size)
            bytes_out: Output size (uncompressed/bytes processed)

        Returns:
            Expansion ratio (bytes_out / bytes_in)

        Example:
            >>> monitor = DecompressionMonitor()
            >>> monitor.calculate_ratio(100, 100000)
            1000.0
        """
        if bytes_in <= 0:
            return 0.0
        return bytes_out / bytes_in

    def check_expansion_ratio(
        self, file_size: int, bytes_processed: int, packets_count: int
    ) -> Optional[ExpansionStats]:
        """
        Check if expansion ratio exceeds safe thresholds.

        SECURITY: This is the main security check that prevents decompression bombs.
        It MUST be called periodically during packet processing to detect anomalies
        BEFORE memory exhaustion occurs.

        Args:
            file_size: Original file size in bytes (compressed size)
            bytes_processed: Total bytes processed so far (uncompressed size)
            packets_count: Number of packets processed

        Returns:
            ExpansionStats if check was performed, None if skipped

        Raises:
            DecompressionBombError: If critical expansion ratio exceeded

        Example:
            >>> monitor = DecompressionMonitor()
            >>> # Safe ratio: 1 MB file, 100 MB processed = 100:1
            >>> stats = monitor.check_expansion_ratio(1_000_000, 100_000_000, 10000)
            >>>
            >>> # Critical ratio: 1 KB file, 100 GB processed = 100,000:1
            >>> monitor.check_expansion_ratio(1000, 100_000_000_000, 10000)
            Traceback (most recent call last):
                ...
            DecompressionBombError: Decompression bomb detected...
        """
        if not self.enabled:
            return None

        # Only check at intervals for performance
        if packets_count - self.last_check_packet < self.check_interval:
            return None

        self.last_check_packet = packets_count
        self.checks_performed += 1

        # Calculate current expansion ratio
        ratio = self.calculate_ratio(file_size, bytes_processed)

        # Create stats object
        stats = ExpansionStats(
            file_size=file_size,
            bytes_processed=bytes_processed,
            packets_processed=packets_count,
            expansion_ratio=ratio,
            is_warning=ratio >= self.max_ratio,
            is_critical=ratio >= self.critical_ratio,
        )

        # CRITICAL: Abort if critical threshold exceeded
        if stats.is_critical:
            error_msg = (
                f"SECURITY: Decompression bomb detected! "
                f"Expansion ratio {ratio:.1f}:1 exceeds critical threshold "
                f"of {self.critical_ratio}:1. "
                f"File size: {file_size:,} bytes, "
                f"Bytes processed: {bytes_processed:,} bytes, "
                f"Packets: {packets_count:,}. "
                f"Processing aborted to prevent resource exhaustion. "
                f"Reference: OWASP ASVS 5.2.3, CWE-409"
            )
            logger.critical(error_msg)
            raise DecompressionBombError(error_msg)

        # WARNING: Log if warning threshold exceeded
        if stats.is_warning and not self.warning_logged:
            logger.warning(
                f"High expansion ratio detected: {ratio:.1f}:1 "
                f"(threshold: {self.max_ratio}:1). "
                f"File: {file_size:,} bytes, Processed: {bytes_processed:,} bytes, "
                f"Packets: {packets_count:,}. "
                f"Monitoring for potential decompression bomb (CWE-409)."
            )
            self.warning_logged = True

        # INFO: Periodic status updates
        if self.checks_performed % 10 == 0:
            logger.debug(
                f"Expansion check #{self.checks_performed}: " f"ratio={ratio:.1f}:1, packets={packets_count:,}"
            )

        return stats

    def reset(self) -> None:
        """
        Reset monitor state.

        Useful when processing multiple files sequentially.
        """
        self.last_check_packet = 0
        self.warning_logged = False
        self.checks_performed = 0
        logger.debug("DecompressionMonitor reset")

    def get_stats(self) -> dict:
        """
        Get monitor statistics.

        Returns:
            Dictionary with monitor stats
        """
        return {
            "enabled": self.enabled,
            "max_ratio": self.max_ratio,
            "critical_ratio": self.critical_ratio,
            "check_interval": self.check_interval,
            "checks_performed": self.checks_performed,
            "warning_logged": self.warning_logged,
        }

    def disable(self) -> None:
        """
        Disable monitoring.

        WARNING: Only use this for trusted input or legitimate large captures.
        Disabling this protection removes a critical security control.
        """
        logger.warning(
            "DecompressionMonitor disabled. System is vulnerable to "
            "decompression bomb attacks (CWE-409). Only disable for trusted input."
        )
        self.enabled = False

    def enable(self) -> None:
        """Enable monitoring."""
        self.enabled = True
        logger.info("DecompressionMonitor enabled")


# Convenience function for quick checks
def check_expansion_safe(file_size: int, bytes_processed: int, max_ratio: int = MAX_EXPANSION_RATIO) -> bool:
    """
    Quick check if expansion ratio is safe.

    Args:
        file_size: Original file size
        bytes_processed: Bytes processed so far
        max_ratio: Maximum safe ratio

    Returns:
        True if safe, False if exceeded

    Example:
        >>> check_expansion_safe(1000, 500000)  # 500:1 - safe
        True
        >>> check_expansion_safe(1000, 5000000)  # 5000:1 - unsafe
        False
    """
    monitor = DecompressionMonitor(max_ratio=max_ratio)
    ratio = monitor.calculate_ratio(file_size, bytes_processed)
    return ratio < max_ratio


if __name__ == "__main__":
    # Self-test
    print("Testing DecompressionMonitor...")

    monitor = DecompressionMonitor()

    # Test 1: Safe ratio (100:1)
    print("\nTest 1: Safe ratio (100:1)")
    try:
        stats = monitor.check_expansion_ratio(1_000_000, 100_000_000, 10000)
        if stats:
            print(f"  PASS: {stats}")
    except DecompressionBombError:
        print("  FAIL: False positive")

    # Test 2: Warning ratio (1500:1)
    print("\nTest 2: Warning ratio (1500:1)")
    try:
        stats = monitor.check_expansion_ratio(1_000_000, 1_500_000_000, 20000)
        if stats and stats.is_warning:
            print(f"  PASS: Warning triggered at {stats.expansion_ratio:.1f}:1")
    except DecompressionBombError:
        print("  FAIL: Should warn, not abort")

    # Test 3: Critical ratio (15000:1)
    print("\nTest 3: Critical ratio (15000:1)")
    monitor.reset()
    try:
        monitor.check_expansion_ratio(1_000_000, 15_000_000_000, 30000)
        print("  FAIL: Should have raised DecompressionBombError")
    except DecompressionBombError as e:
        print(f"  PASS: Bomb detected - {e}")

    print("\nAll tests completed!")
