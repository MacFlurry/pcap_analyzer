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
import sys
import psutil
import os
from typing import Any, Optional, List
from dataclasses import dataclass


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

    def __init__(self, memory_limit_mb: Optional[float] = None):
        """
        Initialize memory optimizer.

        Args:
            memory_limit_mb: Optional memory limit in MB (default: 80% of available)
        """
        self.process = psutil.Process(os.getpid())
        self.memory_limit_mb = memory_limit_mb or (psutil.virtual_memory().available / (1024 * 1024) * 0.8)
        self.peak_memory_mb = 0.0
        self.gc_count = 0

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
            process_mb=process_mem
        )

    def check_memory_pressure(self) -> bool:
        """
        Check if system is under memory pressure.

        Returns:
            True if memory usage is high
        """
        stats = self.get_memory_stats()
        return stats.process_mb > self.memory_limit_mb or stats.percent > 85

    def trigger_gc(self, force: bool = False) -> int:
        """
        Trigger garbage collection if needed.

        Args:
            force: Force GC even if not under pressure

        Returns:
            Number of objects collected
        """
        if force or self.check_memory_pressure():
            collected = gc.collect()
            self.gc_count += 1
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

    def optimize_list(self, data_list: List[Any], keep_ratio: float = 0.5) -> List[Any]:
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
            'current_mb': stats.process_mb,
            'peak_mb': self.peak_memory_mb,
            'system_total_mb': stats.total_mb,
            'system_available_mb': stats.available_mb,
            'system_percent': stats.percent,
            'limit_mb': self.memory_limit_mb,
            'under_pressure': self.check_memory_pressure(),
            'gc_triggered_count': self.gc_count,
            'recommendation': self._get_recommendation(stats)
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
            'operation': self.operation_name,
            'start_mb': self.start_memory_mb,
            'end_mb': self.end_memory_mb,
            'used_mb': self.memory_used_mb,
            'peak_mb': self.optimizer.get_peak_memory()
        }


def get_system_memory_info() -> dict:
    """
    Get system memory information.

    Returns:
        Dictionary with system memory details
    """
    vm = psutil.virtual_memory()

    return {
        'total_gb': vm.total / (1024 ** 3),
        'available_gb': vm.available / (1024 ** 3),
        'used_gb': vm.used / (1024 ** 3),
        'percent': vm.percent,
        'sufficient_for_large_files': vm.available > 2 * (1024 ** 3)  # >2GB available
    }
