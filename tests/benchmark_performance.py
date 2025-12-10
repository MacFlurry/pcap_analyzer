"""
Performance Benchmark Suite

Measures execution time, memory usage, and analyzer performance
for the PCAP analysis pipeline.

Usage:
    python tests/benchmark_performance.py <pcap_file>
    python tests/benchmark_performance.py <pcap_file> --profile
    python tests/benchmark_performance.py <pcap_file> --memory

Requirements:
    pip install memory_profiler

Example Output:
    ========================================
    Performance Benchmark Results
    ========================================
    PCAP File: large_capture.pcap
    File Size: 125.3 MB
    Total Packets: 50,000

    Execution Time: 12.34s
    Peak Memory: 245.6 MB
    Packets/sec: 4,050

    Analyzer Breakdown:
      - TCP Handshake: 2.1s (17%)
      - RTT Analysis: 3.5s (28%)
      - Timestamp Analysis: 1.8s (15%)
      - Health Score: 0.5s (4%)
      ...
"""

import argparse
import gc
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))


def format_bytes(bytes_val: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} TB"


def format_duration(seconds: float) -> str:
    """Format seconds as human-readable duration."""
    if seconds < 1:
        return f"{seconds * 1000:.1f}ms"
    elif seconds < 60:
        return f"{seconds:.2f}s"
    else:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.1f}s"


class PerformanceBenchmark:
    """Performance benchmarking for PCAP analysis."""

    def __init__(self, pcap_path: Path):
        self.pcap_path = pcap_path
        self.results: dict[str, any] = {}

    def measure_file_stats(self) -> dict[str, any]:
        """Measure PCAP file statistics."""
        file_size = self.pcap_path.stat().st_size

        # Quick packet count using scapy
        try:
            from scapy.all import PcapReader

            packet_count = 0
            with PcapReader(str(self.pcap_path)) as pcap:
                for _ in pcap:
                    packet_count += 1

            return {
                "file_size": file_size,
                "file_size_str": format_bytes(file_size),
                "packet_count": packet_count,
            }
        except Exception as e:
            return {
                "file_size": file_size,
                "file_size_str": format_bytes(file_size),
                "packet_count": None,
                "error": str(e),
            }

    def measure_execution_time(self) -> tuple[float, dict]:
        """Measure total execution time of analysis pipeline."""
        from src.cli import analyze_pcap_hybrid

        gc.collect()
        start_time = time.perf_counter()

        try:
            results = analyze_pcap_hybrid(str(self.pcap_path))
            end_time = time.perf_counter()

            return (end_time - start_time, results)
        except Exception as e:
            end_time = time.perf_counter()
            return (end_time - start_time, {"error": str(e)})

    def measure_memory_usage(self) -> dict[str, any]:
        """Measure peak memory usage during analysis."""
        try:
            import tracemalloc

            from src.cli import analyze_pcap_hybrid

            gc.collect()
            tracemalloc.start()

            start_mem = tracemalloc.get_traced_memory()[0]
            results = analyze_pcap_hybrid(str(self.pcap_path))
            current_mem, peak_mem = tracemalloc.get_traced_memory()

            tracemalloc.stop()

            return {
                "start_memory": start_mem,
                "peak_memory": peak_mem,
                "memory_increase": peak_mem - start_mem,
                "start_memory_str": format_bytes(start_mem),
                "peak_memory_str": format_bytes(peak_mem),
                "memory_increase_str": format_bytes(peak_mem - start_mem),
            }
        except Exception as e:
            return {"error": str(e)}

    def profile_analyzers(self) -> dict[str, float]:
        """Profile individual analyzer execution times."""
        import cProfile
        import io
        import pstats

        from src.cli import analyze_pcap_hybrid

        profiler = cProfile.Profile()
        profiler.enable()

        analyze_pcap_hybrid(str(self.pcap_path))

        profiler.disable()

        # Extract analyzer timing
        stream = io.StringIO()
        stats = pstats.Stats(profiler, stream=stream)
        stats.sort_stats("cumulative")

        # Parse stats for analyzer methods
        analyzer_times = {}
        for func, (cc, nc, tt, ct, callers) in stats.stats.items():
            if "analyzer" in func[2].lower() and "analyze" in func[2].lower():
                analyzer_name = func[2]
                analyzer_times[analyzer_name] = ct

        return analyzer_times

    def run_benchmark(self, with_memory: bool = False, with_profile: bool = False) -> dict:
        """Run full benchmark suite."""
        print("=" * 60)
        print("PCAP Analyzer - Performance Benchmark")
        print("=" * 60)
        print(f"PCAP File: {self.pcap_path.name}")
        print()

        # File statistics
        print("Analyzing file statistics...")
        file_stats = self.measure_file_stats()
        print(f"  File Size: {file_stats['file_size_str']}")
        if file_stats.get("packet_count"):
            print(f"  Total Packets: {file_stats['packet_count']:,}")
        print()

        # Execution time
        print("Measuring execution time...")
        exec_time, results = self.measure_execution_time()
        print(f"  Execution Time: {format_duration(exec_time)}")

        if file_stats.get("packet_count"):
            packets_per_sec = file_stats["packet_count"] / exec_time
            print(f"  Throughput: {packets_per_sec:,.0f} packets/sec")
        print()

        # Memory usage
        if with_memory:
            print("Measuring memory usage...")
            mem_stats = self.measure_memory_usage()
            if "error" not in mem_stats:
                print(f"  Peak Memory: {mem_stats['peak_memory_str']}")
                print(f"  Memory Increase: {mem_stats['memory_increase_str']}")
            else:
                print(f"  Error: {mem_stats['error']}")
            print()

        # Profiling
        if with_profile:
            print("Profiling analyzer performance...")
            analyzer_times = self.profile_analyzers()
            total_analyzer_time = sum(analyzer_times.values())

            print("  Analyzer Breakdown:")
            for analyzer, duration in sorted(analyzer_times.items(), key=lambda x: x[1], reverse=True):
                pct = (duration / total_analyzer_time * 100) if total_analyzer_time > 0 else 0
                print(f"    - {analyzer}: {format_duration(duration)} ({pct:.1f}%)")
            print()

        # Health Score Results (if available)
        if results and "health_score" in results:
            health = results["health_score"]
            print("Health Score Results:")
            print(f"  Overall Score: {health.get('overall_score', 0):.1f}/100")
            print(f"  Packet Loss: {health.get('packet_loss_score', 0):.1f}/100")
            print(f"  Retransmissions: {health.get('retransmission_score', 0):.1f}/100")
            print(f"  RTT: {health.get('rtt_score', 0):.1f}/100")
            print()

        print("=" * 60)
        print("Benchmark Complete")
        print("=" * 60)

        return {
            "file_stats": file_stats,
            "execution_time": exec_time,
            "memory_stats": mem_stats if with_memory else None,
            "analyzer_times": analyzer_times if with_profile else None,
            "results": results,
        }


def main():
    parser = argparse.ArgumentParser(description="Benchmark PCAP Analyzer performance")
    parser.add_argument("pcap_file", type=Path, help="Path to PCAP file")
    parser.add_argument("--memory", action="store_true", help="Include memory profiling")
    parser.add_argument("--profile", action="store_true", help="Profile individual analyzers")
    parser.add_argument("--all", action="store_true", help="Run all profiling (memory + profile)")

    args = parser.parse_args()

    if not args.pcap_file.exists():
        print(f"Error: PCAP file not found: {args.pcap_file}")
        sys.exit(1)

    benchmark = PerformanceBenchmark(args.pcap_file)

    with_memory = args.memory or args.all
    with_profile = args.profile or args.all

    benchmark.run_benchmark(with_memory=with_memory, with_profile=with_profile)


if __name__ == "__main__":
    main()
