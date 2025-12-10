"""
Performance Comparison Tool

Compares performance between different versions or branches
of the PCAP analyzer to measure impact of changes.

Usage:
    # Compare current branch with main
    python tests/compare_performance.py <pcap_file> --baseline main

    # Compare two branches
    python tests/compare_performance.py <pcap_file> --baseline v1.0 --current feature-branch

    # Quick comparison (execution time only)
    python tests/compare_performance.py <pcap_file> --quick

Example Output:
    ========================================
    Performance Comparison
    ========================================
    Baseline: main (commit abc123)
    Current:  feature/health-score (commit def456)
    PCAP:     large_capture.pcap (125.3 MB)

    Metric              Baseline    Current     Change
    -----------------   ----------  ----------  -------
    Execution Time      15.2s       12.3s       -19% ✓
    Peak Memory         280 MB      245 MB      -12% ✓
    Packets/sec         3,289       4,065       +24% ✓

    Analyzer Breakdown:
      TCP Handshake:    2.5s → 2.1s  (-16%)
      RTT Analysis:     4.2s → 3.5s  (-17%)
      Health Score:     NEW  → 0.5s
"""

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, Optional

sys.path.insert(0, str(Path(__file__).parent.parent))


def get_git_commit(branch: Optional[str] = None) -> str:
    """Get current git commit hash."""
    if branch:
        cmd = ["git", "rev-parse", branch]
    else:
        cmd = ["git", "rev-parse", "HEAD"]

    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout.strip()[:7]


def get_current_branch() -> str:
    """Get current git branch name."""
    result = subprocess.run(["git", "branch", "--show-current"], capture_output=True, text=True)
    return result.stdout.strip()


def checkout_branch(branch: str) -> bool:
    """Checkout a git branch."""
    result = subprocess.run(["git", "checkout", branch], capture_output=True, text=True)
    return result.returncode == 0


def run_benchmark(pcap_path: Path, quick: bool = False) -> Dict:
    """Run benchmark and return results."""
    from benchmark_performance import PerformanceBenchmark

    benchmark = PerformanceBenchmark(pcap_path)

    # Capture output
    import io
    from contextlib import redirect_stdout

    output = io.StringIO()
    with redirect_stdout(output):
        results = benchmark.run_benchmark(with_memory=not quick, with_profile=not quick)

    return results


def format_change(baseline: float, current: float, reverse: bool = False) -> str:
    """Format percentage change with color indicator."""
    if baseline == 0:
        return "N/A"

    change_pct = ((current - baseline) / baseline) * 100

    # For metrics where lower is better (time, memory), reverse the indicator
    if reverse:
        change_pct = -change_pct

    if change_pct < -5:
        indicator = "↓"  # Significant improvement
    elif change_pct > 5:
        indicator = "↑"  # Significant regression
    else:
        indicator = "→"  # Minimal change

    return f"{change_pct:+.1f}% {indicator}"


def compare_results(baseline: Dict, current: Dict, pcap_path: Path):
    """Compare and display benchmark results."""
    print("=" * 70)
    print("Performance Comparison Results")
    print("=" * 70)
    print(f"PCAP File: {pcap_path.name}")
    print(f"File Size: {baseline['file_stats']['file_size_str']}")
    if baseline["file_stats"].get("packet_count"):
        print(f"Packets:   {baseline['file_stats']['packet_count']:,}")
    print()

    # Execution time comparison
    baseline_time = baseline["execution_time"]
    current_time = current["execution_time"]
    time_change = format_change(baseline_time, current_time, reverse=True)

    print("Execution Time:")
    print(f"  Baseline: {baseline_time:.2f}s")
    print(f"  Current:  {current_time:.2f}s")
    print(f"  Change:   {time_change}")
    print()

    # Throughput comparison
    if baseline["file_stats"].get("packet_count"):
        baseline_throughput = baseline["file_stats"]["packet_count"] / baseline_time
        current_throughput = current["file_stats"]["packet_count"] / current_time
        throughput_change = format_change(baseline_throughput, current_throughput)

        print("Throughput (packets/sec):")
        print(f"  Baseline: {baseline_throughput:,.0f}")
        print(f"  Current:  {current_throughput:,.0f}")
        print(f"  Change:   {throughput_change}")
        print()

    # Memory comparison (if available)
    if baseline.get("memory_stats") and current.get("memory_stats"):
        baseline_mem = baseline["memory_stats"]["peak_memory"]
        current_mem = current["memory_stats"]["peak_memory"]
        mem_change = format_change(baseline_mem, current_mem, reverse=True)

        print("Peak Memory:")
        print(f"  Baseline: {baseline['memory_stats']['peak_memory_str']}")
        print(f"  Current:  {current['memory_stats']['peak_memory_str']}")
        print(f"  Change:   {mem_change}")
        print()

    # Analyzer breakdown (if available)
    if baseline.get("analyzer_times") and current.get("analyzer_times"):
        print("Analyzer Performance:")
        all_analyzers = set(baseline["analyzer_times"].keys()) | set(current["analyzer_times"].keys())

        for analyzer in sorted(all_analyzers):
            baseline_val = baseline["analyzer_times"].get(analyzer, 0)
            current_val = current["analyzer_times"].get(analyzer, 0)

            if baseline_val == 0 and current_val > 0:
                print(f"  {analyzer}: NEW → {current_val:.2f}s")
            elif baseline_val > 0 and current_val == 0:
                print(f"  {analyzer}: {baseline_val:.2f}s → REMOVED")
            else:
                change = format_change(baseline_val, current_val, reverse=True)
                print(f"  {analyzer}: {baseline_val:.2f}s → {current_val:.2f}s ({change})")
        print()

    # Summary
    print("=" * 70)
    if current_time < baseline_time * 0.95:
        print("✓ Performance IMPROVED")
    elif current_time > baseline_time * 1.05:
        print("✗ Performance REGRESSED")
    else:
        print("→ Performance UNCHANGED (within 5% margin)")
    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Compare PCAP Analyzer performance")
    parser.add_argument("pcap_file", type=Path, help="Path to PCAP file")
    parser.add_argument("--baseline", default="main", help="Baseline branch (default: main)")
    parser.add_argument("--current", help="Current branch (default: current branch)")
    parser.add_argument("--quick", action="store_true", help="Quick comparison (time only)")

    args = parser.parse_args()

    if not args.pcap_file.exists():
        print(f"Error: PCAP file not found: {args.pcap_file}")
        sys.exit(1)

    # Get current state
    original_branch = get_current_branch()
    current_branch = args.current or original_branch

    print(f"Comparing branches:")
    print(f"  Baseline: {args.baseline}")
    print(f"  Current:  {current_branch}")
    print()

    try:
        # Run baseline benchmark
        print(f"Running baseline benchmark ({args.baseline})...")
        if not checkout_branch(args.baseline):
            print(f"Error: Could not checkout baseline branch '{args.baseline}'")
            sys.exit(1)

        baseline_results = run_benchmark(args.pcap_file, quick=args.quick)

        # Run current benchmark
        print(f"Running current benchmark ({current_branch})...")
        if not checkout_branch(current_branch):
            print(f"Error: Could not checkout current branch '{current_branch}'")
            sys.exit(1)

        current_results = run_benchmark(args.pcap_file, quick=args.quick)

        # Compare results
        compare_results(baseline_results, current_results, args.pcap_file)

    finally:
        # Restore original branch
        checkout_branch(original_branch)


if __name__ == "__main__":
    main()
