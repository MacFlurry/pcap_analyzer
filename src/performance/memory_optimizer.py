#!/usr/bin/env python3
"""
Memory Optimization Utilities

Provides memory management and optimization tools:
- Automatic garbage collection
- Memory usage monitoring
- Memory limit enforcement
- Object size tracking

Author: PCAP Analyzer Team
Sprint: 10 (Performance Optimization)
"""

import gc
import os
import sys
from dataclasses import dataclass
from typing import Any, List, Optional

import psutil


@dataclass
class MemoryStats:
    """Memory usage statistics."""

    total_mb: float
    available_mb: float
    used_mb: float
    percent: float
    process_mb: float


class MemoryOptimizer:
    """
    Memory optimization and monitoring utilities.

    Features:
    - Real-time memory monitoring
    - Automatic GC triggering
    - Memory limit warnings
    - Object size analysis
    """

    def __init__(self, memory_limit_mb: Optional[float] = None, low_memory_mode: bool = False):
        """
        Initialize memory optimizer.

        Args:
            memory_limit_mb: Optional memory limit in MB (default: 80% of available)
            low_memory_mode: Enable aggressive memory management (default: False)
        """
        self.process = psutil.Process(os.getpid())
        self.memory_limit_mb = memory_limit_mb or (psutil.virtual_memory().available / (1024 * 1024) * 0.8)
        self.peak_memory_mb = 0.0
        self.gc_count = 0
        self.low_memory_mode = low_memory_mode

        # Cooldown tracking (Fix for Issue #4)
        self.last_gc_time = 0.0
        self.gc_cooldown_seconds = 5.0  # Wait 5s between GC attempts
        self.consecutive_empty_gcs = 0
        self.max_consecutive_empty_gcs = 3  # Stop after 3 empty GCs

    def get_memory_stats(self) -> MemoryStats:
        """
        Get current memory statistics.

        Returns:
            MemoryStats object with current memory info
        """
        vm = psutil.virtual_memory()
        process_mem = self.process.memory_info().rss / (1024 * 1024)

        # Track peak memory
        if process_mem > self.peak_memory_mb:
            self.peak_memory_mb = process_mem

        return MemoryStats(
            total_mb=vm.total / (1024 * 1024),
            available_mb=vm.available / (1024 * 1024),
            used_mb=vm.used / (1024 * 1024),
            percent=vm.percent,
            process_mb=process_mem,
        )

    def check_memory_pressure(self) -> bool:
        """
        Check if process is under memory pressure.

        Returns:
            True if memory usage is high

        Note:
            Fix for Issue #4 - Now uses process memory instead of system memory.
            This prevents false positives when other processes use system RAM.
        """
        stats = self.get_memory_stats()

        # In low memory mode, use stricter thresholds
        if self.low_memory_mode:
            # Trigger at 70% of limit
            return stats.process_mb > (self.memory_limit_mb * 0.7)

        # Normal mode: Only check process memory, ignore system memory
        # Use 90% of process limit (increased from implicit 100%)
        return stats.process_mb > (self.memory_limit_mb * 0.9)

    def trigger_gc(self, force: bool = False) -> int:
        """
        Trigger garbage collection if needed with cooldown protection.

        Args:
            force: Force GC even if not under pressure

        Returns:
            Number of objects collected

        Note:
            Fix for Issue #4 - Added cooldown mechanism and consecutive empty GC tracking.
            Prevents excessive GC calls when collection yields no results.
        """
        import time

        current_time = time.time()

        # Skip if in cooldown period (unless forced)
        if not force and (current_time - self.last_gc_time) < self.gc_cooldown_seconds:
            return 0

        # Skip if too many consecutive empty GCs
        if self.consecutive_empty_gcs >= self.max_consecutive_empty_gcs:
            return 0

        # Check if GC is needed
        if force or self.check_memory_pressure():
            collected = gc.collect()
            self.gc_count += 1
            self.last_gc_time = current_time

            # Track consecutive empty GCs
            if collected == 0:
                self.consecutive_empty_gcs += 1
            else:
                # Reset counter on successful collection
                self.consecutive_empty_gcs = 0

            return collected
        return 0

    def get_object_size(self, obj: Any) -> int:
        """
        Get size of object in bytes.

        Args:
            obj: Object to measure

        Returns:
            Size in bytes
        """
        return sys.getsizeof(obj)

    def optimize_list(self, data_list: list[Any], keep_ratio: float = 0.5) -> list[Any]:
        """
        Optimize list by sampling if too large.

        Args:
            data_list: List to optimize
            keep_ratio: Ratio of elements to keep (0.0-1.0)

        Returns:
            Optimized list (may be sampled)
        """
        if len(data_list) < 10000:
            return data_list

        # Sample every N elements
        step = int(1 / keep_ratio)
        return data_list[::step]

    def clear_caches(self):
        """Clear internal Python caches."""
        # Clear function cache
        gc.collect()

        # Clear regex cache
        import re

        re.purge()

    def reset_gc_tracking(self):
        """
        Reset GC tracking counters.

        Useful when entering a new processing phase where GC behavior might change.
        """
        self.consecutive_empty_gcs = 0
        self.last_gc_time = 0.0

    def release_chunk_memory(self, chunk_data: Any):
        """
        Explicitly release memory for chunk data.

        Args:
            chunk_data: Chunk data to release (list, dict, etc.)

        Note:
            Fix for Issue #4 - Explicitly clear references to help GC.
        """
        if isinstance(chunk_data, list):
            chunk_data.clear()
        elif isinstance(chunk_data, dict):
            chunk_data.clear()
        del chunk_data

    def get_peak_memory(self) -> float:
        """
        Get peak memory usage since start.

        Returns:
            Peak memory in MB
        """
        return self.peak_memory_mb

    def get_memory_report(self) -> dict:
        """
        Get comprehensive memory report.

        Returns:
            Dictionary with memory metrics
        """
        stats = self.get_memory_stats()

        return {
            "current_mb": stats.process_mb,
            "peak_mb": self.peak_memory_mb,
            "system_total_mb": stats.total_mb,
            "system_available_mb": stats.available_mb,
            "system_percent": stats.percent,
            "limit_mb": self.memory_limit_mb,
            "under_pressure": self.check_memory_pressure(),
            "gc_triggered_count": self.gc_count,
            "consecutive_empty_gcs": self.consecutive_empty_gcs,
            "low_memory_mode": self.low_memory_mode,
            "recommendation": self._get_recommendation(stats),
        }

    def _get_recommendation(self, stats: MemoryStats) -> str:
        """Get memory optimization recommendation."""
        if stats.process_mb > self.memory_limit_mb:
            return "High memory usage - consider using streaming mode"
        elif stats.percent > 85:
            return "System memory pressure - close other applications"
        elif stats.process_mb > 1000:
            return "Large memory usage - file may benefit from chunked processing"
        else:
            return "Memory usage normal"


class MemoryMonitor:
    """
    Context manager for monitoring memory usage during operations.

    Usage:
        with MemoryMonitor("Loading packets") as monitor:
            packets = load_packets()
        print(f"Operation used {monitor.memory_used_mb:.2f}MB")
    """

    def __init__(self, operation_name: str, optimizer: Optional[MemoryOptimizer] = None):
        """
        Initialize memory monitor.

        Args:
            operation_name: Name of operation to monitor
            optimizer: Optional MemoryOptimizer instance
        """
        self.operation_name = operation_name
        self.optimizer = optimizer or MemoryOptimizer()
        self.start_memory_mb = 0.0
        self.end_memory_mb = 0.0
        self.memory_used_mb = 0.0

    def __enter__(self):
        """Start monitoring."""
        self.start_memory_mb = self.optimizer.get_memory_stats().process_mb
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Stop monitoring and calculate usage."""
        self.end_memory_mb = self.optimizer.get_memory_stats().process_mb
        self.memory_used_mb = self.end_memory_mb - self.start_memory_mb

        # Trigger GC if needed
        if self.optimizer.check_memory_pressure():
            self.optimizer.trigger_gc(force=True)

    def get_summary(self) -> dict:
        """Get monitoring summary."""
        return {
            "operation": self.operation_name,
            "start_mb": self.start_memory_mb,
            "end_mb": self.end_memory_mb,
            "used_mb": self.memory_used_mb,
            "peak_mb": self.optimizer.get_peak_memory(),
        }


def get_system_memory_info() -> dict:
    """
    Get system memory information.

    Returns:
        Dictionary with system memory details
    """
    vm = psutil.virtual_memory()

    return {
        "total_gb": vm.total / (1024**3),
        "available_gb": vm.available / (1024**3),
        "used_gb": vm.used / (1024**3),
        "percent": vm.percent,
        "sufficient_for_large_files": vm.available > 2 * (1024**3),  # >2GB available
    }
