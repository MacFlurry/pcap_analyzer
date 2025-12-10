#!/usr/bin/env python3
"""
Parallel Analyzer Executor

Executes multiple analyzers in parallel using multiprocessing.
Optimizes CPU usage for multi-core systems.

Author: PCAP Analyzer Team
Sprint: 10 (Performance Optimization)
"""

import multiprocessing as mp
from typing import List, Dict, Any, Tuple
from concurrent.futures import ProcessPoolExecutor, as_completed
import time


class ParallelAnalyzerExecutor:
    """
    Executes analyzers in parallel to leverage multiple CPU cores.

    Features:
    - Automatic CPU detection
    - Work stealing for load balancing
    - Timeout handling
    - Error isolation (one failure doesn't break all)
    """

    def __init__(self, max_workers: int = None):
        """
        Initialize parallel executor.

        Args:
            max_workers: Maximum number of worker processes (default: CPU count - 1)
        """
        self.cpu_count = mp.cpu_count()
        self.max_workers = max_workers or max(1, self.cpu_count - 1)

    def run_analyzers_parallel(
        self,
        analyzers: List[Tuple[str, Any]],
        packets: List[Any]
    ) -> Dict[str, Any]:
        """
        Run multiple analyzers in parallel.

        Args:
            analyzers: List of (name, analyzer_instance) tuples
            packets: List of packets to analyze

        Returns:
            Dictionary of {analyzer_name: results}
        """
        results = {}

        # Group analyzers by dependency
        # Analyzers that can run in parallel
        parallel_analyzers = [
            ('protocol_distribution', None),
            ('jitter', None),
            ('service_classification', None),
            ('port_scan_detection', None),
            ('brute_force_detection', None),
            ('ddos_detection', None),
            ('dns_tunneling_detection', None),
            ('data_exfiltration_detection', None),
            ('c2_beaconing_detection', None),
            ('lateral_movement_detection', None),
        ]

        # Filter to only include provided analyzers
        tasks = [(name, analyzer) for name, analyzer in analyzers
                 if name in [n for n, _ in parallel_analyzers]]

        if not tasks:
            # No parallelizable analyzers, run sequentially
            for name, analyzer in analyzers:
                results[name] = self._run_single_analyzer(analyzer, packets)
            return results

        # Run in parallel
        with ProcessPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all analyzer tasks
            future_to_name = {
                executor.submit(self._run_analyzer_process, analyzer, packets): name
                for name, analyzer in tasks
            }

            # Collect results as they complete
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    result = future.result(timeout=300)  # 5 min timeout per analyzer
                    results[name] = result
                except Exception as e:
                    # Fallback: run sequentially on error
                    print(f"Warning: Parallel execution failed for {name}, running sequentially")
                    analyzer = next(a for n, a in tasks if n == name)
                    results[name] = self._run_single_analyzer(analyzer, packets)

        return results

    @staticmethod
    def _run_analyzer_process(analyzer: Any, packets: List[Any]) -> Any:
        """
        Run analyzer in subprocess (for multiprocessing).

        Args:
            analyzer: Analyzer instance
            packets: List of packets

        Returns:
            Analyzer results
        """
        return analyzer.analyze(packets)

    @staticmethod
    def _run_single_analyzer(analyzer: Any, packets: List[Any]) -> Any:
        """
        Run single analyzer (sequential fallback).

        Args:
            analyzer: Analyzer instance
            packets: List of packets

        Returns:
            Analyzer results
        """
        return analyzer.analyze(packets)

    def get_optimal_worker_count(self, num_analyzers: int) -> int:
        """
        Calculate optimal number of workers for given analyzer count.

        Args:
            num_analyzers: Number of analyzers to run

        Returns:
            Optimal worker count
        """
        # Don't create more workers than analyzers
        return min(self.max_workers, num_analyzers)

    def get_stats(self) -> Dict[str, Any]:
        """
        Get executor statistics.

        Returns:
            Dictionary with executor stats
        """
        return {
            'cpu_count': self.cpu_count,
            'max_workers': self.max_workers,
            'parallel_capable': self.max_workers > 1,
            'recommended_for_files': '> 100MB or > 50k packets'
        }


def benchmark_parallel_vs_sequential(
    analyzers: List[Tuple[str, Any]],
    packets: List[Any]
) -> Dict[str, float]:
    """
    Benchmark parallel vs sequential execution.

    Args:
        analyzers: List of (name, analyzer) tuples
        packets: Packet list

    Returns:
        Dictionary with timing comparison
    """
    # Sequential timing
    start = time.time()
    for name, analyzer in analyzers:
        analyzer.analyze(packets)
    sequential_time = time.time() - start

    # Parallel timing
    executor = ParallelAnalyzerExecutor()
    start = time.time()
    executor.run_analyzers_parallel(analyzers, packets)
    parallel_time = time.time() - start

    speedup = sequential_time / parallel_time if parallel_time > 0 else 0

    return {
        'sequential_time': sequential_time,
        'parallel_time': parallel_time,
        'speedup': speedup,
        'improvement_percent': (1 - parallel_time / sequential_time) * 100 if sequential_time > 0 else 0
    }
