#!/usr/bin/env python3
"""
Performance Benchmarking Tool

Benchmarks PCAP analyzer performance with different optimization modes:
- Memory vs Streaming mode
- Sequential vs Parallel execution
- Memory usage profiling
- Throughput calculation

Author: PCAP Analyzer Team
Sprint: 10 (Performance Optimization)
"""

import statistics
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .memory_optimizer import MemoryMonitor, MemoryOptimizer
from .parallel_executor import ParallelAnalyzerExecutor
from .streaming_processor import StreamingProcessor


class PerformanceBenchmark:
    """
    Benchmarks PCAP analyzer performance with different configurations.

    Features:
    - Execution time measurement
    - Memory usage profiling
    - Throughput calculation (packets/second)
    - Comparison reports
    """

    def __init__(self, pcap_file: str):
        """
        Initialize benchmark for a PCAP file.

        Args:
            pcap_file: Path to PCAP file to benchmark
        """
        self.pcap_file = pcap_file
        self.file_size_mb = Path(pcap_file).stat().st_size / (1024 * 1024)
        self.streaming_processor = StreamingProcessor(pcap_file)
        self.results = {}

    def benchmark_packet_loading(self, mode: str = "auto") -> dict[str, Any]:
        """
        Benchmark packet loading with different modes.

        Args:
            mode: 'memory', 'streaming', or 'auto'

        Returns:
            Dictionary with benchmark results
        """
        memory_optimizer = MemoryOptimizer()

        # Determine mode
        if mode == "auto":
            perf_stats = self.streaming_processor.get_stats()
            mode = perf_stats["processing_mode"]

        # Benchmark loading
        with MemoryMonitor(f"Packet Loading ({mode})", memory_optimizer) as monitor:
            start_time = time.time()

            if mode == "memory":
                # Load all packets into memory
                from scapy.all import PcapReader

                packets = []
                with PcapReader(self.pcap_file) as reader:
                    for packet in reader:
                        packets.append(packet)
                packet_count = len(packets)

            else:
                # Use streaming
                packet_count = 0
                for chunk in self.streaming_processor.stream_chunks():
                    packet_count += len(chunk)

            elapsed_time = time.time() - start_time

        # Calculate metrics
        mem_summary = monitor.get_summary()
        throughput = packet_count / elapsed_time if elapsed_time > 0 else 0

        return {
            "mode": mode,
            "packet_count": packet_count,
            "elapsed_time": elapsed_time,
            "throughput_pps": throughput,
            "memory_used_mb": mem_summary["used_mb"],
            "peak_memory_mb": mem_summary["peak_mb"],
            "file_size_mb": self.file_size_mb,
        }

    def benchmark_comparison(self) -> dict[str, Any]:
        """
        Compare memory vs streaming mode performance.

        Returns:
            Dictionary with comparison results
        """
        results = {}

        # Benchmark memory mode (if file is small enough)
        if self.file_size_mb < 100:
            print(f"Benchmarking memory mode...")
            results["memory"] = self.benchmark_packet_loading("memory")

        # Benchmark streaming mode
        print(f"Benchmarking streaming mode...")
        results["streaming"] = self.benchmark_packet_loading("streaming")

        # Calculate improvements
        if "memory" in results and "streaming" in results:
            memory_result = results["memory"]
            streaming_result = results["streaming"]

            time_ratio = memory_result["elapsed_time"] / streaming_result["elapsed_time"]
            memory_savings = memory_result["memory_used_mb"] - streaming_result["memory_used_mb"]
            memory_savings_pct = (memory_savings / memory_result["memory_used_mb"]) * 100

            results["comparison"] = {
                "time_ratio": time_ratio,
                "memory_savings_mb": memory_savings,
                "memory_savings_pct": memory_savings_pct,
                "streaming_faster": streaming_result["elapsed_time"] < memory_result["elapsed_time"],
                "streaming_uses_less_memory": streaming_result["memory_used_mb"] < memory_result["memory_used_mb"],
            }

        return results

    def benchmark_file_sizes(self, iterations: int = 3) -> dict[str, Any]:
        """
        Benchmark with multiple iterations to get stable results.

        Args:
            iterations: Number of benchmark runs

        Returns:
            Dictionary with averaged results
        """
        times = []
        throughputs = []
        memory_used = []

        for i in range(iterations):
            print(f"Iteration {i+1}/{iterations}...")
            result = self.benchmark_packet_loading("auto")
            times.append(result["elapsed_time"])
            throughputs.append(result["throughput_pps"])
            memory_used.append(result["memory_used_mb"])

        return {
            "iterations": iterations,
            "avg_time": statistics.mean(times),
            "min_time": min(times),
            "max_time": max(times),
            "std_dev_time": statistics.stdev(times) if len(times) > 1 else 0,
            "avg_throughput": statistics.mean(throughputs),
            "avg_memory_mb": statistics.mean(memory_used),
            "consistency_score": (
                100 - (statistics.stdev(times) / statistics.mean(times) * 100) if len(times) > 1 else 100
            ),
        }

    def generate_report(self) -> str:
        """
        Generate human-readable benchmark report.

        Returns:
            Formatted report string
        """
        report = []
        report.append("=" * 80)
        report.append("PERFORMANCE BENCHMARK REPORT")
        report.append("=" * 80)
        report.append(f"File: {self.pcap_file}")
        report.append(f"File Size: {self.file_size_mb:.2f} MB")
        report.append("")

        # File info
        perf_stats = self.streaming_processor.get_stats()
        report.append(f"Processing Mode: {perf_stats['processing_mode']}")
        report.append(f"Description: {perf_stats['recommended_mode']}")
        if perf_stats["chunk_size"]:
            report.append(f"Chunk Size: {perf_stats['chunk_size']} packets")
        report.append("")

        # Run comparison benchmark
        print("Running comparison benchmark...")
        comparison = self.benchmark_comparison()

        if "memory" in comparison:
            mem_result = comparison["memory"]
            report.append("-" * 80)
            report.append("MEMORY MODE RESULTS")
            report.append("-" * 80)
            report.append(f"Packets Processed: {mem_result['packet_count']:,}")
            report.append(f"Elapsed Time: {mem_result['elapsed_time']:.2f}s")
            report.append(f"Throughput: {mem_result['throughput_pps']:.2f} packets/sec")
            report.append(f"Memory Used: {mem_result['memory_used_mb']:.2f} MB")
            report.append(f"Peak Memory: {mem_result['peak_memory_mb']:.2f} MB")
            report.append("")

        if "streaming" in comparison:
            stream_result = comparison["streaming"]
            report.append("-" * 80)
            report.append("STREAMING MODE RESULTS")
            report.append("-" * 80)
            report.append(f"Packets Processed: {stream_result['packet_count']:,}")
            report.append(f"Elapsed Time: {stream_result['elapsed_time']:.2f}s")
            report.append(f"Throughput: {stream_result['throughput_pps']:.2f} packets/sec")
            report.append(f"Memory Used: {stream_result['memory_used_mb']:.2f} MB")
            report.append(f"Peak Memory: {stream_result['peak_memory_mb']:.2f} MB")
            report.append("")

        if "comparison" in comparison:
            comp = comparison["comparison"]
            report.append("-" * 80)
            report.append("PERFORMANCE COMPARISON")
            report.append("-" * 80)
            report.append(f"Time Ratio (Memory/Streaming): {comp['time_ratio']:.2f}x")
            report.append(f"Memory Savings: {comp['memory_savings_mb']:.2f} MB ({comp['memory_savings_pct']:.1f}%)")
            report.append(f"Streaming is faster: {comp['streaming_faster']}")
            report.append(f"Streaming uses less memory: {comp['streaming_uses_less_memory']}")
            report.append("")

        # Multi-iteration benchmark
        print("\nRunning multi-iteration benchmark (3 runs)...")
        iterations = self.benchmark_file_sizes(3)

        report.append("-" * 80)
        report.append("CONSISTENCY TEST (3 iterations)")
        report.append("-" * 80)
        report.append(f"Average Time: {iterations['avg_time']:.2f}s")
        report.append(f"Min Time: {iterations['min_time']:.2f}s")
        report.append(f"Max Time: {iterations['max_time']:.2f}s")
        report.append(f"Std Deviation: {iterations['std_dev_time']:.2f}s")
        report.append(f"Average Throughput: {iterations['avg_throughput']:.2f} packets/sec")
        report.append(f"Average Memory: {iterations['avg_memory_mb']:.2f} MB")
        report.append(f"Consistency Score: {iterations['consistency_score']:.1f}%")
        report.append("")

        report.append("=" * 80)

        return "\n".join(report)


def run_benchmark(pcap_file: str) -> str:
    """
    Run complete benchmark suite for a PCAP file.

    Args:
        pcap_file: Path to PCAP file

    Returns:
        Benchmark report string
    """
    benchmark = PerformanceBenchmark(pcap_file)
    return benchmark.generate_report()


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m src.performance.benchmark <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    report = run_benchmark(pcap_file)
    print(report)
